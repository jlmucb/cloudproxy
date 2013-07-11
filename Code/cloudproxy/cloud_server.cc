#include "cloud_server.h"
#include "util.h"

#include <arpa/inet.h>

#include <sstream>

using std::lock_guard;
using std::stringstream;

namespace cloudproxy {
CloudServer::CloudServer(const string &tls_cert,
    const string &tls_key, 
    const string &tls_password,
    const string &public_policy_keyczar,
    const string &public_policy_pem,
    const string &acl_location,
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
                       tls_key, tls_password)) << "Could not set up TLS";

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
    LOG(INFO) << "About to listen for a client message";
    CHECK_GT(BIO_do_accept(abio_.get()), 0) << "Could not wait for a client"
      " connection";

    BIO *out = BIO_pop(abio_.get());
    thread t(&CloudServer::HandleConnection, this, out);
    t.detach();
  }

  return true;
}

void CloudServer::HandleConnection(BIO *sbio) {
  keyczar::openssl::ScopedBIO bio(sbio); 
  if (BIO_do_handshake(bio.get()) <= 0) {
    LOG(ERROR) << "Could not perform a TLS handshake with the client";
  } else {
    LOG(INFO) << "Successful client handshake";
  }

  // loop on the message handler for this connection with the client
  bool rv = true;
  while (true) {
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
      return;
    }

    cm.ParseFromString(serialized_cm);

    string reason;
    bool reply = true;
    bool close = false;
    rv = HandleMessage(cm, bio.get(), &reason, &reply, &close);

    if (close) {
      break;
    }

    if (reply) {
      Result r;
      r.set_success(rv);
      if (!reason.empty()) {
        r.set_reason(reason);
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
  }

  if (rv) { 
    LOG(INFO) << "The channel closed successfully";
  } else {
    LOG(ERROR) << "The channel closed with an error";
  }

  return;

}

bool CloudServer::HandleMessage(const ClientMessage &message,
    BIO *bio, string *reason, bool *reply, bool *close) {
  CHECK(bio) << "null bio";
  CHECK(reason) << "null reason";
  CHECK(reply) << "null reply";

  int rv = false;
  if (message.has_action()) {
    LOG(INFO) << "It's an Action message";
    Action a = message.action();
    if (!users_->IsAuthenticated(a.subject())) {
      LOG(ERROR) << "User " << a.subject() << " not authenticated";
      reason->assign("User not authenticated");
      return false;
    }

    // check with the auth code to see if this action is allowed
    {
      lock_guard<mutex> l(m_);
      if (!auth_->Permitted(a.subject(), a.verb(), a.object())) {
	LOG(ERROR) << "User " << a.subject() << " not authorized to perform"
	  << a.verb() << " on " << a.object();
	reason->assign("Not authorized");
	return false;
      }
    }

    switch (a.verb()) {
      case ALL:
        LOG(ERROR) << "Received a request for the ALL action from a client";
        reason->assign("Invalid request for the ALL action");
        return false;
      case CREATE: 
	    LOG(INFO) << "Handling a CREATE request";
        rv = HandleCreate(a, bio, reason, reply);
	    LOG(INFO) << "return value: " << rv;
	    return rv;
      case DESTROY:
	    LOG(INFO) << "Handling a DESTROY request";
        rv = HandleDestroy(a, bio, reason, reply);
        LOG(INFO) << "return value: " << rv;
        return rv;
      case WRITE:
	    LOG(INFO) << "Handling a WRITE request";
        rv = HandleWrite(a, bio, reason, reply);
        LOG(INFO) << "return value: " << rv;
        return rv;
      case READ:
	    LOG(INFO) << "Handling a READ request";
        rv = HandleRead(a, bio, reason, reply);
        LOG(INFO) << "return value: " << rv;
        return rv;
      default:
        LOG(ERROR) << "Request for invalid operation " << a.verb();
        reason->assign("Invalid operation requested");
        return false;
    }
  } else if (message.has_auth()) {
    LOG(INFO) << "Received an Auth message";
    return HandleAuth(message.auth(), bio, reason, reply);
  } else if (message.has_response()) {
    LOG(INFO) << "Received a Response message";
    return HandleResponse(message.response(), bio, reason, reply);
  } else if (message.has_close()) {
    rv = !message.close().error();
    *close = true;
    return rv;
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
  {
    lock_guard<mutex> l(m_);
    challenges_[subject].insert(nonce);
  }

  string serialized_chall;
  if (!c.SerializeToString(&serialized_chall)) {
    LOG(ERROR) << "Could not serialize the Challenge";
    reason->assign("Serialization failure");
    return false;
  }

  LOG(INFO) << "Sending a challenge to the client";
  if (!SendData(bio, serialized_chall)) {
    LOG(ERROR) << "Could not send the Challenge to the client";
    reason->assign("Could not send serialized Challenge");
    return false;
  }

  LOG(INFO) << "Successfully processed an Auth message";

  *reply = false;

  // now listen again on this BIO for the Response
  // TODO(tmroeder): this needs to timeout if we wait for too long
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

  {
    lock_guard<mutex> l(m_);
    auto chall_it = challenges_.find(c.subject());
    if (challenges_.end() == chall_it) {
      LOG(ERROR) << "Could not find the challenge provided in this response";
      reason->assign("Could not find the challenge for this response");
      return false;
    }

    // search this set for the nonce we were supplied
    auto nonce_it = chall_it->second.find(c.nonce());
    if (chall_it->second.end() == nonce_it) {
      LOG(ERROR) << "The user had outstanding nonces, but not the right ones";
      reason->assign("Could not find this nonce");
      return false;
    }

    // compare the length and contents of the nonce
    // TODO(tmroeder): can you use string compare safely here?
    if (nonce_it->length() != c.nonce().length()) {
      LOG(ERROR) << "Invalid nonce";
      reason->assign("Invalid nonce");
      return false;
    }

    if (memcmp(nonce_it->data(), c.nonce().data(),
	  c.nonce().length()) != 0) {
      LOG(ERROR) << "Nonces do not match";
      reason->assign("Nonces do not match");
      return false;
    }
  
    chall_it->second.erase(nonce_it);
  }

  // get or add the public key for this user
  shared_ptr<keyczar::Keyczar> user_key;
  {
    lock_guard<mutex> l(m_);
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
  }

  LOG(INFO) << "Challenge passed. Adding user " << c.subject() << " as"
    " authenticated";

  // remove this challenge from the list, since it was verified and the user was
  // authenticated on this channel
  {
    lock_guard<mutex> l(m_);
    users_->SetAuthenticated(c.subject());
  }

  return true;
}

bool CloudServer::HandleCreate(const Action &action, BIO *bio, string *reason,
    bool *reply) {

  lock_guard<mutex> l(m_);

  // note that CREATE fails if the object already exists
  if (objects_.end() != objects_.find(action.object())) {
    LOG(ERROR) << "Object " << action.object() << " already exists";
    reason->assign("Object already exists");
    return false;
  }

  // create the object
  objects_.insert(action.object());

  return true;
}

bool CloudServer::HandleDestroy(const Action &action, BIO *bio,
    string *reason, bool *reply) {

  lock_guard<mutex> l(m_);

  auto object_it = objects_.find(action.object());
  if (objects_.end() == object_it) {
    LOG(ERROR) << "Can't destroy object " << action.object() << " since it"
      << " doesn't exist";
    reason->assign("Object doesn't exist");
    return false;
  }

  objects_.erase(object_it);
  return true;
}

bool CloudServer::HandleWrite(const Action &action, BIO *bio,
    string *reason, bool *reply) {

  lock_guard<mutex> l(m_);

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

  lock_guard<mutex> l(m_);

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
