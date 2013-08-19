//  File: cloud_server.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the CloudServer class used to
// implement CloudProxy applications
//
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



#include "cloudproxy/cloud_server.h"
#include "cloudproxy/util.h"

#include <keyczar/keyczar.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>

#include <arpa/inet.h>

#include <sstream>

using std::lock_guard;
using std::stringstream;

using keyczar::base::ScopedSafeString;
using keyczar::base::Base64WEncode;
using keyczar::base::PathExists;

using tao::Quote;
using tao::Tao;
using tao::SignedQuote;
using tao::WhitelistAuthorizationManager;

namespace cloudproxy {

CloudServer::CloudServer(const string &tls_cert, const string &tls_key,
                         const string &secret,
                         const string &public_policy_keyczar,
                         const string &public_policy_pem,
                         const string &acl_location,
                         const string &whitelist_location, const string &host,
                         ushort port)
    : public_policy_key_(
          keyczar::Verifier::Read(public_policy_keyczar.c_str())),
      rand_(keyczar::CryptoFactory::Rand()),
      context_(SSL_CTX_new(TLSv1_2_server_method())),
      bio_(nullptr),
      abio_(nullptr),
      auth_(),
      users_(new CloudUserManager()),
      objects_(),
      auth_manager_(new WhitelistAuthorizationManager()) {

  // set up the policy key to verify bytes, not strings
  public_policy_key_->set_encoding(keyczar::Keyczar::NO_ENCODING);
  auth_.reset(new CloudAuth(acl_location, public_policy_key_.get()));

  CHECK(auth_manager_->Init(whitelist_location, *public_policy_key_))
      << "Could not initialize the whitelist";

  ScopedSafeString encoded_secret(new string());
  CHECK(Base64WEncode(secret, encoded_secret.get()))
    << "Could not encode the secret as a Base64W string";

  // check to see if the public/private keys exist. If not, create them
  FilePath fp(tls_cert);
  if (!PathExists(fp)) {
    CHECK(CreateECDSAKey(tls_key, tls_cert, *encoded_secret, "US", "Google",
  			"server"))
      << "Could not create new keys for OpenSSL for the client";
  }

  // set up the SSL context and BIOs for getting client connections
  CHECK(SetUpSSLCTX(context_.get(), public_policy_pem, tls_cert, tls_key,
                    *encoded_secret)) << "Could not set up TLS";

  CHECK(rand_->Init()) << "Could not initialize the random-number generator";

  bio_.reset(BIO_new_ssl(context_.get(), 0));

  SSL *ssl = nullptr;
  BIO_get_ssl(bio_.get(), &ssl);
  CHECK(ssl) << "Could not get an SSL pointer from the BIO";
  CHECK(SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY)) << "Could not set AUTO_RETRY";

  stringstream ss;
  ss << port;
  string host_and_port = host + string(":") + ss.str();
  abio_.reset(BIO_new_accept(const_cast<char *>(host_and_port.c_str())));

  CHECK(BIO_set_accept_bios(abio_.get(), bio_.get()))
      << "Could not get an"
         " accept BIO for the TLS connection";

  CHECK_GT(BIO_do_accept(abio_.get()), 0) << "Could not set up an accept for"
                                             " the host and port combination "
                                          << host_and_port;
}

bool CloudServer::Listen(const Tao &quote_tao) {
  while (true) {
    LOG(INFO) << "About to listen for a client message";
    CHECK_GT(BIO_do_accept(abio_.get()), 0) << "Could not wait for a client"
                                               " connection";

    BIO *out = BIO_pop(abio_.get());
    thread t(&CloudServer::HandleConnection, this, out, &quote_tao);
    t.detach();
  }

  return true;
}

void CloudServer::HandleConnection(BIO *sbio, const Tao *t) {
  keyczar::openssl::ScopedBIO bio(sbio);
  if (BIO_do_handshake(bio.get()) <= 0) {
    LOG(ERROR) << "Could not perform a TLS handshake with the client";
    LOG(ERROR) << "The OpenSSL error was: " << ERR_error_string(ERR_get_error(), NULL);
    return;
  } 

  SSL *cur_ssl = nullptr;
  BIO_get_ssl(bio.get(), &cur_ssl);
  X509 *self_cert = SSL_get_certificate(cur_ssl);
  ScopedX509Ctx peer_cert(SSL_get_peer_certificate(cur_ssl));
  if (peer_cert.get() == nullptr) {
    LOG(ERROR) << "No X.509 certificate received from the client";
    return;
  }

  string serialized_peer_cert;
  if (!SerializeX509(peer_cert.get(), &serialized_peer_cert)) {
    LOG(ERROR) << "Could not serialize the X.509 certificate";
    return;
  }

  string serialized_self_cert;
  if (!SerializeX509(self_cert, &serialized_self_cert)) {
    LOG(ERROR) << "Could not serialize our own X.509 certificate";
    return;
  }

  CloudServerThreadData cstd(serialized_peer_cert, serialized_self_cert);

  // loop on the message handler for this connection with the client
  bool rv = true;
  while (true) {
    // read a 4-byte integer from the channel to get the length of the
    // ClientMessage
    // TODO(tmroeder): the right way to do this would be to
    // implement something like ParseFromIstream with an istream wrapping the
    // OpenSSL BIO abstraction. This would then render the first integer otiose,
    // since protobufs already have length information in their metadata.
    LOG(INFO) << "Waiting for client message";
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
    rv = HandleMessage(cm, bio.get(), &reason, &reply, &close, cstd, *t);

    if (close) {
      break;
    }

    if (reply) {
      if (!SendReply(bio.get(), rv, reason.c_str())) {
        LOG(ERROR) << "Could not send a reply to the client";
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

bool CloudServer::SendReply(BIO *bio, bool success, const string &reason) {
  ServerMessage sm;
  Result *r = sm.mutable_result();
  r->set_success(success);
  if (!reason.empty()) {
    r->set_reason(reason);
  }

  string serialized_sm;
  if (!sm.SerializeToString(&serialized_sm)) {
    LOG(ERROR) << "Could not serialize reply";
    return false;
  } else {
    if (!SendData(bio, serialized_sm)) {
      LOG(ERROR) << "Could not reply";
      return false;
    }
  }

  return true;
}
bool CloudServer::HandleMessage(const ClientMessage &message, BIO *bio,
                                string *reason, bool *reply, bool *close,
                                CloudServerThreadData &cstd, const Tao &t) {
  CHECK(bio) << "null bio";
  CHECK(reason) << "null reason";
  CHECK(reply) << "null reply";

  if (!cstd.GetCertValidated() && !message.has_quote()) {
    LOG(ERROR)
        << "Client did not provide a SignedQuote before sending other messages";
    return false;
  }

  int rv = false;
  if (message.has_action()) {
    Action a = message.action();
    if (!cstd.IsAuthenticated(a.subject())) {
      LOG(ERROR) << "User " << a.subject() << " not authenticated";
      reason->assign("User not authenticated");
      return false;
    }

    // check with the auth code to see if this action is allowed
    {
      lock_guard<mutex> l(auth_m_);
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
        rv = HandleCreate(a, bio, reason, reply, cstd);
        LOG(INFO) << "return value: " << rv;
        return rv;
      case DESTROY:
        LOG(INFO) << "Handling a DESTROY request";
        rv = HandleDestroy(a, bio, reason, reply, cstd);
        LOG(INFO) << "return value: " << rv;
        return rv;
      case WRITE:
        LOG(INFO) << "Handling a WRITE request";
        rv = HandleWrite(a, bio, reason, reply, cstd);
        LOG(INFO) << "return value: " << rv;
        return rv;
      case READ:
        LOG(INFO) << "Handling a READ request";
        rv = HandleRead(a, bio, reason, reply, cstd);
        LOG(INFO) << "return value: " << rv;
        return rv;
      default:
        LOG(ERROR) << "Request for invalid operation " << a.verb();
        reason->assign("Invalid operation requested");
        return false;
    }
  } else if (message.has_auth()) {
    LOG(INFO) << "Received an Auth message";
    return HandleAuth(message.auth(), bio, reason, reply, cstd);
  } else if (message.has_response()) {
    LOG(INFO) << "Received a Response message";
    return HandleResponse(message.response(), bio, reason, reply, cstd);
  } else if (message.has_close()) {
    rv = !message.close().error();
    *close = true;
    *reply = false;
    return rv;
  } else if (message.has_quote()) {
    rv = HandleQuote(message.quote(), bio, reason, reply, cstd, t);
    if (!rv) {
      LOG(ERROR) << "Quote verification failed. Closing connection";
      *close = true;
    }
    return rv;
  } else {
    LOG(ERROR) << "Message from client did not have any recognized content";
    reason->assign("Unrecognized ClientMessage type");
  }

  return false;
}

bool CloudServer::HandleAuth(const Auth &auth, BIO *bio, string *reason,
                             bool *reply, CloudServerThreadData &cstd) {
  string subject = auth.subject();

  // check to see if this user is already authenticated on some channel
  bool has_key = false;
  {
    lock_guard<mutex> l(auth_m_);
    has_key = users_->HasKey(subject);
  }

  // Send a challenge to the client to authenticate this user.  The reply from
  // the client consists of a Response, which has an optional SignedSpeaksFor
  // that binds the subject name to a key, and a signature on the challenge.
  // The SignedSpeaksFor only needs to be provided once: the client needn't send
  // it if the server is known to have this binding information. But if the
  // server can't bind the subject name to a key at the time it receives the
  // response, then it will reject even correctly signed responses.

  ServerMessage sm;
  Challenge *c = sm.mutable_challenge();
  c->set_subject(subject);

  string nonce;
  if (!rand_->RandBytes(NonceSize, &nonce)) {
    LOG(ERROR) << "Could not generate a nonce for a challenge";
    reason->assign("Randomness failure");
    return false;
  }

  c->set_nonce(nonce.data(), nonce.length());
  c->set_send_binding(!has_key);

  // store this challenge until we get a response from the client
  // TODO(tmroeder): make the challenge data structure a cache or time out
  // requests so we don't run into space problems.
  cstd.AddChallenge(subject, nonce);

  string serialized_sm;
  if (!sm.SerializeToString(&serialized_sm)) {
    LOG(ERROR) << "Could not serialize the ServerMessage";
    reason->assign("Serialization failure");
    return false;
  }

  LOG(INFO) << "Sending a challenge to the client";
  if (!SendData(bio, serialized_sm)) {
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

bool CloudServer::HandleResponse(const Response &response, BIO *bio,
                                 string *reason, bool *reply,
                                 CloudServerThreadData &cstd) {
  // check to see if this is an outstanding challenge
  Challenge c;
  if (!c.ParseFromString(response.serialized_chall())) {
    LOG(ERROR) << "Could not parse the serialized challenge";
    reason->assign("Could not parse the serialized challenge");
    return false;
  }

  string nonce;
  bool found_chall = cstd.GetChallenge(c.subject(), &nonce);
  if (!found_chall) {
    LOG(ERROR) << "Could not find the challenge provided in this response";
    reason->assign("Could not find the challenge for this response");
    return false;
  }

  // compare the length and contents of the nonce
  // TODO(tmroeder): can you use string compare safely here?
  if (nonce.length() != c.nonce().length()) {
    LOG(ERROR) << "Invalid nonce";
    reason->assign("Invalid nonce");
    return false;
  }

  if (memcmp(nonce.data(), c.nonce().data(), c.nonce().length()) != 0) {
    LOG(ERROR) << "Nonces do not match";
    reason->assign("Nonces do not match");
    return false;
  }

  CHECK(cstd.RemoveChallenge(c.subject())) << "Could not delete the challenge";

  // get or add the public key for this user
  scoped_ptr<keyczar::Keyczar> user_key;
  {
    lock_guard<mutex> l(key_m_);
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

    shared_ptr<keyczar::Keyczar> temp_key;
    CHECK(users_->GetKey(c.subject(), &temp_key)) << "Could not get a key";

    // TODO(tmroeder): Generalize to other types of keys
    scoped_ptr<keyczar::Keyset> user_keyset(new keyczar::Keyset());
    CHECK(CopyRSAPublicKeyset(temp_key.get(), user_keyset.get()))
        << "Could not copy the key";

    user_key.reset(new keyczar::Verifier(user_keyset.release()));
    user_key->set_encoding(keyczar::Keyczar::NO_ENCODING);
  }

  // check the signature on the serialized_challenge
  if (!VerifySignature(response.serialized_chall(), response.signature(),
                       user_key.get())) {
    LOG(ERROR) << "Challenge signature failed";
    reason->assign("Invalid response signature");
    return false;
  }

  LOG(INFO) << "Challenge passed. Adding user " << c.subject()
            << " as authenticated";

  cstd.SetAuthenticated(c.subject());

  return true;
}

bool CloudServer::HandleCreate(const Action &action, BIO *bio, string *reason,
                               bool *reply, CloudServerThreadData &cstd) {

  lock_guard<mutex> l(data_m_);

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

bool CloudServer::HandleDestroy(const Action &action, BIO *bio, string *reason,
                                bool *reply, CloudServerThreadData &cstd) {

  lock_guard<mutex> l(data_m_);

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

bool CloudServer::HandleWrite(const Action &action, BIO *bio, string *reason,
                              bool *reply, CloudServerThreadData &cstd) {

  lock_guard<mutex> l(data_m_);

  // this is mostly a nop; just check to make sure the object exists
  if (objects_.end() == objects_.find(action.object())) {
    LOG(ERROR) << "Can't write to object " << action.object() << " that"
               << " doesn't exist";
    reason->assign("Object doesn't exist");
    return false;
  }

  return true;
}

bool CloudServer::HandleRead(const Action &action, BIO *bio, string *reason,
                             bool *reply, CloudServerThreadData &cstd) {

  lock_guard<mutex> l(data_m_);

  // this is mostly a nop; just check to make sure the object exists
  if (objects_.end() == objects_.find(action.object())) {
    LOG(ERROR) << "Can't read from object " << action.object() << " that"
               << " doesn't exist";
    reason->assign("Object doesn't exist");
    return false;
  }

  return true;
}

bool CloudServer::HandleQuote(const SignedQuote &quote, BIO *bio,
                              string *reason, bool *reply,
                              CloudServerThreadData &cstd, const Tao &t) {
  string serialized_quote;
  if (!quote.SerializeToString(&serialized_quote)) {
    LOG(ERROR) << "Could not serialize the quote to pass it to the Tao";
    return false;
  }

  // check that this is a valid quote
  {
    lock_guard<mutex> l(tao_m_);
    if (!t.VerifyQuote(cstd.GetPeerCert(), serialized_quote)) {
      LOG(ERROR) << "The SignedQuote did not pass Tao verification";
      return false;
    }
  }

  Quote client_quote;
  if (!client_quote.ParseFromString(quote.serialized_quote())) {
    LOG(ERROR) << "Could not parse the client Quote";
    return false;
  }

  // check that this hash is authorized
  {
    lock_guard<mutex> l(auth_m_);
    if (!auth_manager_->IsAuthorized(client_quote.hash())) {
      LOG(ERROR) << "The client with hash " << client_quote.hash()
		 << " is not authorized";
      return false;
    }
  }

  cstd.SetCertValidated();

  // quote it to send it to the client
  string signature;
  {
    lock_guard<mutex> l(tao_m_);
    if (!t.Quote(cstd.GetSelfCert(), &signature)) {
      LOG(ERROR) << "Could not get a signed quote for our own X.509 certificate";
      return false;
    }
  }

  ServerMessage sm;
  SignedQuote *sq = sm.mutable_quote();
  if (!sq->ParseFromString(signature)) {
    LOG(ERROR) << "Could not parse the SignedQuote provided by the Tao";
    return false;
  }

  string serialized_sm;
  if (!sm.SerializeToString(&serialized_sm)) {
    LOG(ERROR) << "Could not serialize the ServerMessage";
    return false;
  }

  if (!SendData(bio, serialized_sm)) {
    LOG(ERROR) << "Could not send the serialized ServerMessage to the client";
    return false;
  }

  // don't send another reply
  *reply = false;
  return true;
}
}  // namespace cloudproxy
