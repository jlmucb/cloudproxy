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

#include <arpa/inet.h>

#include <thread>

#include <glog/logging.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_client.h"
#include "cloudproxy/cloud_server_thread_data.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/util.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/tao_auth.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using std::lock_guard;
using std::thread;

using tao::Keys;
using tao::OpenTCPSocket;
using tao::ScopedFd;
using tao::SerializeX509;
using tao::TaoChildChannel;
using tao::TaoDomain;
using tao::VerifySignature;

namespace cloudproxy {

// TODO(kwalsh) move work to Init().
CloudServer::CloudServer(const string &server_config_path,
                         const string &acl_location, const string &host,
                         const string &port, TaoChildChannel *channel,
                         TaoDomain *admin)
    : admin_(admin),
      rand_(keyczar::CryptoFactory::Rand()),
      host_(host),
      port_(port),
      auth_(),
      users_(new CloudUserManager()),
      objects_(),
      host_channel_(channel),
      keys_(new Keys(server_config_path, "cloudserver", Keys::Signing)) {

  auth_.reset(new CloudAuth(acl_location, admin_->GetPolicyVerifier()));

  CHECK(keys_->InitHosted(*host_channel_))
      << "Could not initialize CloudServer keys";

  // TODO(kwalsh) x509 details should come from elsewhere
  if (keys_->HasFreshKeys()) {
    CHECK(keys_->CreateSelfSignedX509("US", "Washington", "Google",
                                      "cloudserver"));
  }

  // set up the SSL context and SSLs for getting client connections
  CHECK(SetUpSSLServerCtx(*keys_, &context_)) << "Could not set up server TLS";

  CHECK(rand_->Init()) << "Could not initialize the random-number generator";
}

bool CloudServer::Listen(bool single_channel) {
  // Set up a TCP connection for the given host and port.
  ScopedFd sock(new int(-1));
  if (!OpenTCPSocket(host_, port_, sock.get())) {
    LOG(ERROR) << "Could not open a TCP socket on port " << host_ << ":"
               << port_;
    return false;
  }

  while (true) {
    int accept_sock = accept(*sock, nullptr, nullptr);
    if (accept_sock == -1) {
      PLOG(ERROR) << "Could not accept a connection on the socket";
      return false;
    }

    if (single_channel) {
      HandleConnection(accept_sock);
      return true;
    } else {
      thread t(&CloudServer::HandleConnection, this, accept_sock);
      t.detach();
    }
  }

  return true;
}

void CloudServer::HandleConnection(int accept_sock) {
  // Create a new SSL context to handle this connection and do a handshake on
  // it. The ScopedSSL will close the fd in its cleanup routine.
  ScopedSSL ssl(SSL_new(context_.get()));
  SSL_set_fd(ssl.get(), accept_sock);

  if (SSL_accept(ssl.get()) == -1) {
    LOG(ERROR) << "Could not accept an SSL connection on the socket";
    return;
  }

  // Don't delete this X.509 certificate, since it is owned by the SSL_CTX and
  // will be deleted there. Putting this cert in a ScopedX509Ctx leads to a
  // double-free error.
  X509 *self_cert = SSL_get_certificate(ssl.get());
  tao::ScopedX509Ctx peer_cert(SSL_get_peer_certificate(ssl.get()));
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
    ClientMessage cm;
    string serialized_cm;
    if (!ReceiveData(ssl.get(), &serialized_cm)) {
      LOG(ERROR) << "Could not get the serialized ClientMessage";
      return;
    }

    cm.ParseFromString(serialized_cm);

    string reason;
    bool reply = true;
    bool close = false;
    rv = HandleMessage(cm, ssl.get(), &reason, &reply, &close, cstd);

    if (close) {
      break;
    }

    if (reply) {
      if (!SendReply(ssl.get(), rv, reason.c_str())) {
        LOG(ERROR) << "Could not send a reply to the client";
      }
    }
  }

  if (!rv) {
    LOG(ERROR) << "The channel closed with an error";
  }

  return;
}

bool CloudServer::SendReply(SSL *ssl, bool success, const string &reason) {
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
    if (!SendData(ssl, serialized_sm)) {
      LOG(ERROR) << "Could not reply";
      return false;
    }
  }

  return true;
}
bool CloudServer::HandleMessage(const ClientMessage &message, SSL *ssl,
                                string *reason, bool *reply, bool *close,
                                CloudServerThreadData &cstd) {  // NOLINT
  CHECK(ssl) << "null ssl";
  CHECK(reason) << "null reason";
  CHECK(reply) << "null reply";

  if (!cstd.GetCertValidated() && !message.has_attestation()) {
    LOG(ERROR)
        << "Client did not provide a Attestation before sending other messages";
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
        LOG(ERROR) << "User " << a.subject() << " not authorized to perform "
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
        rv = HandleCreate(a, ssl, reason, reply, cstd);
        return rv;
      case DESTROY:
        rv = HandleDestroy(a, ssl, reason, reply, cstd);
        return rv;
      case WRITE:
        rv = HandleWrite(a, ssl, reason, reply, cstd);
        return rv;
      case READ:
        rv = HandleRead(a, ssl, reason, reply, cstd);
        return rv;
      default:
        LOG(ERROR) << "Request for invalid operation " << a.verb();
        reason->assign("Invalid operation requested");
        return false;
    }
  } else if (message.has_auth()) {
    return HandleAuth(message.auth(), ssl, reason, reply, cstd);
  } else if (message.has_response()) {
    return HandleResponse(message.response(), ssl, reason, reply, cstd);
  } else if (message.has_close()) {
    rv = !message.close().error();
    *close = true;
    *reply = false;
    return rv;
  } else if (message.has_attestation()) {
    rv = HandleAttestation(message.attestation(), ssl, reason, reply, cstd);
    if (!rv) {
      LOG(ERROR) << "Attestation verification failed. Closing connection";
      *close = true;
    }
    return rv;
  } else {
    LOG(ERROR) << "Message from client did not have any recognized content";
    reason->assign("Unrecognized ClientMessage type");
  }

  return false;
}

bool CloudServer::HandleAuth(const Auth &auth, SSL *ssl, string *reason,
                             bool *reply,
                             CloudServerThreadData &cstd) {  // NOLINT
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

  if (!SendData(ssl, serialized_sm)) {
    LOG(ERROR) << "Could not send the Challenge to the client";
    reason->assign("Could not send serialized Challenge");
    return false;
  }

  *reply = false;

  // now listen again on this SSL for the Response
  // TODO(tmroeder): this needs to timeout if we wait for too long
  return true;
}

bool CloudServer::HandleResponse(const Response &response, SSL *ssl,
                                 string *reason, bool *reply,
                                 CloudServerThreadData &cstd) {  // NOLINT
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
  if (nonce.compare(c.nonce()) != 0) {
    LOG(ERROR) << "Nonces do not match";
    reason->assign("Nonces do not match");
    return false;
  }

  CHECK(cstd.RemoveChallenge(c.subject())) << "Could not delete the challenge";

  {
    lock_guard<mutex> l(key_m_);
    if (!users_->HasKey(c.subject())) {
      if (!response.has_binding()) {
        LOG(ERROR) << "No key known for user " << c.subject();
        reason->assign("No key binding for response");
        return false;
      }

      if (!users_->AddKey(response.binding(), admin_->GetPolicyVerifier())) {
        LOG(ERROR) << "Could not add the binding from the response";
        reason->assign("Invalid binding");
        return false;
      }

      SpeaksFor sf;
      sf.ParseFromString(response.binding().serialized_speaks_for());
      VLOG(2) << "Added key for " << sf.subject();
    }

    keyczar::Verifier *user_key = nullptr;
    if (!users_->GetKey(c.subject(), &user_key)) {
      LOG(ERROR) << "No key found for " << c.subject();
      reason->assign("Missing binding");
      return false;
    }

    // check the signature on the serialized_challenge
    if (!VerifySignature(*user_key, response.serialized_chall(),
                         CloudClient::ChallengeSigningContext,
                         response.signature())) {
      LOG(ERROR) << "Challenge signature failed";
      reason->assign("Invalid response signature");
      return false;
    }
  }

  VLOG(2) << "Challenge passed. Adding user " << c.subject()
          << " as authenticated";

  cstd.SetAuthenticated(c.subject());

  return true;
}

bool CloudServer::HandleCreate(const Action &action, SSL *ssl, string *reason,
                               bool *reply,
                               CloudServerThreadData &cstd) {  // NOLINT
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

bool CloudServer::HandleDestroy(const Action &action, SSL *ssl, string *reason,
                                bool *reply,
                                CloudServerThreadData &cstd) {  // NOLINT
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

bool CloudServer::HandleWrite(const Action &action, SSL *ssl, string *reason,
                              bool *reply,
                              CloudServerThreadData &cstd) {  // NOLINT
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

bool CloudServer::HandleRead(const Action &action, SSL *ssl, string *reason,
                             bool *reply,
                             CloudServerThreadData &cstd) {  // NOLINT
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

bool CloudServer::HandleAttestation(const string &attestation, SSL *ssl,
                                    string *reason, bool *reply,
                                    CloudServerThreadData &cstd) {  // NOLINT
  // check that this is a valid attestation, including checking that
  // the client hash is authorized.
  {
    lock_guard<mutex> l(tao_m_);
    string data;
    if (!admin_->VerifyAttestation(attestation, &data)) {
      LOG(ERROR) << "The Attestation did not pass Tao verification";
      return false;
    }

    if (data.compare(cstd.GetPeerCert()) != 0) {
      LOG(ERROR)
          << "The Attestation passed validation, but the data didn't match";
      return false;
    }
  }

  cstd.SetCertValidated();

  // quote it to send it to the client
  ServerMessage sm;
  string *signature = sm.mutable_attestation();
  {
    lock_guard<mutex> l(tao_m_);
    if (!host_channel_->Attest(cstd.GetSelfCert(), signature)) {
      LOG(ERROR)
          << "Could not get a signed attestation for our own X.509 certificate";
      return false;
    }
  }

  string serialized_sm;
  if (!sm.SerializeToString(&serialized_sm)) {
    LOG(ERROR) << "Could not serialize the ServerMessage";
    return false;
  }

  if (!SendData(ssl, serialized_sm)) {
    LOG(ERROR) << "Could not send the serialized ServerMessage to the client";
    return false;
  }

  // don't send another reply
  *reply = false;
  return true;
}
}  // namespace cloudproxy
