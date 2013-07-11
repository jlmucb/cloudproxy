#include "cloud_server.h"
#include "util.h"

#include <arpa/inet.h>

#include <sstream>

using std::stringstream;

namespace cloudproxy {
CloudServer::CloudServer(const string &tls_cert,
    const string &tls_key, 
    const string &public_policy_keyczar,
    const string &public_policy_pem,
    const string &acl_location,
    const string &users_location,
    const string &server_key_location,
    const string &host,
    ushort port) 
  : crypter_(keyczar::Crypter::Read(server_key_location)),
    public_policy_key_(keyczar::Verifier::Read(public_policy_keyczar.c_str())),
    rand_(keyczar::CryptoFactory::Rand()),
    context_(SSL_CTX_new(TLSv1_2_server_method())),
    bio_(nullptr),
    abio_(nullptr),
    auth_(new CloudAuth(acl_location, public_policy_key_.get())),
    users_(new CloudUserManager()),
    objects_(),
    challenges_() {
  // set up the SSL context and BIOs for getting client connections
  CHECK(SetUpSSLCTX(context_.get(), public_policy_pem, tls_cert,
                       tls_key)) << "Could not set up TLS";

  CHECK(rand_->Init()) << "Could not initialize the random-number generator";

  bio_.reset(BIO_new_ssl(context_.get(), 0));
  
  SSL *ssl = nullptr;
  BIO_get_ssl(bio_.get(), &ssl);
  CHECK(ssl) << "Could not get an SSL pointer from the BIO";
  CHECK(SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY)) << "Could not set AUTO_RETRY";

  stringstream ss;
  ss << port;
  string host_and_port = host + string(":") + ss.str();
  abio_.reset(BIO_new_accept(const_cast<char*>(host_and_port.c_str())));

  CHECK(BIO_set_accept_bios(abio_.get(), bio_.get())) << "Could not get an"
    " accept BIO for the TLS connection";

  CHECK_GT(BIO_do_accept(abio_.get()), 0) << "Could not set up an accept for"
    " the host and port combination " << host_and_port;
}

bool CloudServer::Listen() {
  while(true) {
    LOG(INFO) << "About to listen for a client";
    CHECK_GT(BIO_do_accept(abio_.get()), 0) << "Could not wait for a client"
      " connection";

    keyczar::openssl::ScopedBIO out(BIO_pop(abio_.get()));
    if (BIO_do_handshake(out.get()) <= 0) {
      LOG(ERROR) << "Could not perform a TLS handshake with the client";
    } else {
      LOG(INFO) << "Successful client handshake";
      
      // pass the BIO to a handler that gets a length and an Action and forwards
      // to the correct handler for this action
      if (!HandleConnection(out)) {
        LOG(ERROR) << "Could not handle the client connection";
      }
    }
  }

  return true;
}

bool CloudServer::HandleConnection(
    keyczar::openssl::ScopedBIO &sbio) {
  keyczar::openssl::ScopedBIO bio(sbio.release()); 

  // read a 4-byte integer from the channel to get the length of the
  // ClientMessage.
  // TODO(tmroeder): the right way to do this would be to
  // implement something like ParseFromIstream with an istream wrapping the
  // OpenSSL BIO abstraction. This would then render the first integer otiose,
  // since protobufs already have length information in their metadata.
  ClientMessage cm;
  string serialized_cm;
  if (!ReceiveData(bio.get(), &serialized_cm)) {
    LOG(ERROR) << "Could not get the serialized ClientMessage";
    return false;
  }

  cm.ParseFromString(serialized_cm);

  string failure_reason;
  bool reply = true;
  bool rv = HandleMessage(cm, bio.get(), &failure_reason, &reply);

  if (reply) {
    Result r;
    r.set_success(rv);
    if (!failure_reason.empty()) {
      r.set_reason(failure_reason);
    }

    string serialized_r;
    if (!r.SerializeToString(&serialized_r)) {
      LOG(ERROR) << "Could not serialize reply";
    } else {
      if (!SendData(bio.get(), serialized_r)) {
        LOG(ERROR) << "Could not reply";
      }
    }
  }

  return rv;
}

bool CloudServer::HandleMessage(const ClientMessage &message,
    BIO *bio, string *reason, bool *reply) {
  CHECK(bio) << "null bio";
  CHECK(reason) << "null reason";
  CHECK(reply) << "null reply";

  if (message.has_action()) {
    Action a = message.action();
    if (!users_->IsAuthenticated(a.subject())) {
      LOG(ERROR) << "User " << a.subject() << " not authenticated";
      reason->assign("User not authenticated");
      return false;
    }

    // check with the auth code to see if this action is allowed
    if (!auth_->Permitted(a.subject(), a.verb(), a.object())) {
      LOG(ERROR) << "User " << a.subject() << " not authorized to perform"
        << a.verb() << " on " << a.object();
      reason->assign("Not authorized");
      return false;
    }

    switch (a.verb()) {
      case ALL:
        LOG(ERROR) << "Received a request for the ALL action from a client";
        reason->assign("Invalid request for the ALL action");
        return false;
      case CREATE: 
        return HandleCreate(a, bio, reason, reply);
      case DESTROY:
        return HandleDestroy(a, bio, reason, reply);
      case WRITE:
        return HandleWrite(a, bio, reason, reply);
      case READ:
        return HandleRead(a, bio, reason, reply);
      default:
        LOG(ERROR) << "Request for invalid operation " << a.verb();
        reason->assign("Invalid operation requested");
        return false;
    }
  } else if (message.has_auth()) {
    return HandleAuth(message.auth(), bio, reason, reply);
  } else if (message.has_response()) {
    return HandleResponse(message.response(), bio, reason, reply);
  } else {
    LOG(ERROR) << "Message from client did not have any recognized content";
    reason->assign("Unrecognized ClientMessage type");
  }

  return false;
}

bool CloudServer::HandleAuth(const Auth &auth, BIO *bio,
    string *reason, bool *reply) {
  string subject = auth.subject();

  // Send a challenge to the client to authenticate this user.  The reply from
  // the client consists of a Response, which has an optional SignedSpeaksFor
  // that binds the subject name to a key, and a signature on the challenge.
  // The SignedSpeaksFor only needs to be provided once: the client needn't send
  // it if the server is known to have this binding information. But if the
  // server can't bind the subject name to a key at the time it receives the
  // response, then it will reject even correctly signed responses.

  Challenge c;
  c.set_subject(subject);

  string nonce;
  if (!rand_->RandBytes(NonceSize, &nonce)) {
    LOG(ERROR) << "Could not generate a nonce for a challenge";
    reason->assign("Randomness failure");
    return false;
  }

  c.set_nonce(nonce.data(), nonce.length());

  // store this challenge until we get a response from the client
  // TODO(tmroeder): make the challenge data structure a cache or time out
  // requests so we don't run into space problems.
  // TODO(tmroeder): also, note that this map only supports one outstanding
  // challenge for a given username: subsequent challenges will wipe out older
  // challenges. This map could be replaced with a multimap to handle this case.
  // TODO(tmroeder): need synchronization here when we allow multiple threads
  challenges_[subject] = nonce;

  string serialized_chall;
  if (!c.SerializeToString(&serialized_chall)) {
    LOG(ERROR) << "Could not serialize the Challenge";
    reason->assign("Serialization failure");
    return false;
  }

  if (!SendData(bio, serialized_chall)) {
    LOG(ERROR) << "Could not send the Challenge to the client";
    reason->assign("Could not send serialized Challenge");
    return false;
  }

  // don't send any reply to the client other than the Challenge
  *reply = false;
  
  return true;
}

bool CloudServer::HandleResponse(const Response &response,
    BIO *bio, string *reason, bool *reply) {
  // check to see if this is an outstanding challenge
  Challenge c;
  if (!c.ParseFromString(response.serialized_chall())) {
    LOG(ERROR) << "Could not parse the serialized challenge";
    reason->assign("Could not parse the serialized challenge");
    return false;
  }

  auto chall_it = challenges_.find(c.subject());
  if (challenges_.end() == chall_it) {
    LOG(ERROR) << "Could not find the challenge provided in this response";
    reason->assign("Could not find the challenge for this response");
    return false;
  }

  // compare the length and contents of the nonce
  // TODO(tmroeder): can you use string compare safely here?
  if (chall_it->second.length() != c.nonce().length()) {
    LOG(ERROR) << "Invalid nonce";
    reason->assign("Invalid nonce");
    return false;
  }

  if (memcmp(chall_it->second.data(), c.nonce().data(),
        c.nonce().length()) != 0) {
    LOG(ERROR) << "Nonces do not match";
    reason->assign("Nonces do not match");
    return false;
  }

  // get or add the public key for this user
  shared_ptr<keyczar::Keyczar> user_key;
  if (!users_->HasKey(c.subject())) {
    if (!response.has_binding()) {
      LOG(ERROR) << "No key known for user " << c.subject();
      reason->assign("No key binding for response");
      return false;
    }

    if (!users_->AddKey(response.binding(), public_policy_key_.get())) {
      LOG(ERROR) << "Could not add the binding from the response";
      reason->assign("Invalid binding");
      return false;
    }
  }
  
  CHECK(users_->GetKey(c.subject(), &user_key)) << "Could not get a key";

  // check the signature on the serialized_challenge
  if (!VerifySignature(response.serialized_chall(), response.signature(),
        user_key.get())) {
    LOG(ERROR) << "Challenge signature failed";
    reason->assign("Invalid response signature");
    return false;
  }

  // remove this challenge from the list, since it was verified and the user was
  // authenticated on this channel
  challenges_.erase(chall_it);
  users_->SetAuthenticated(c.subject());

  return true;
}

bool CloudServer::HandleCreate(const Action &action, BIO *bio, string *reason,
    bool *reply) {
  // note that CREATE fails if the object already exists
  if (objects_.end() != objects_.find(action.object())) {
    LOG(ERROR) << "Object " << action.object() << " already exists";
    reason->assign("Object already exists");
    return false;
  }

  // create the object and grant the subject all permissions on it
  objects_.insert(action.object());
  auth_->Insert(action.subject(), ALL, action.object());
  return true;
}

bool CloudServer::HandleDestroy(const Action &action, BIO *bio,
    string *reason, bool *reply) {
  auto object_it = objects_.find(action.object());
  if (objects_.end() == object_it) {
    LOG(ERROR) << "Can't destroy object " << action.object() << " since it"
      << " doesn't exist";
    reason->assign("Object doesn't exist");
    return false;
  }

  objects_.erase(object_it);

  // remove all permissions except CREATE
  auth_->DestroyObject(action.subject(), action.object());
  return true;
}

bool CloudServer::HandleWrite(const Action &action, BIO *bio,
    string *reason, bool *reply) {
  // this is mostly a nop; just check to make sure the object exists
  if (objects_.end() == objects_.find(action.object())) {
    LOG(ERROR) << "Can't write to object " << action.object() << " that"
      << " doesn't exist";
    reason->assign("Object doesn't exist");
    return false;
  }

  return true;
}

bool CloudServer::HandleRead(const Action &action, BIO *bio,
    string *reason, bool *reply) {
  // this is mostly a nop; just check to make sure the object exists
  if (objects_.end() == objects_.find(action.object())) {
    LOG(ERROR) << "Can't read from object " << action.object() << " that"
      << " doesn't exist";
    reason->assign("Object doesn't exist");
    return false;
  }

  return true;
}

} // namespace cloudproxy
