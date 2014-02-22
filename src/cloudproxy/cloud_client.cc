//  File: cloud_client.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the CloudClient class used to
// communicate with CloudServer instances
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
#include "cloudproxy/cloud_client.h"

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/tao_auth.h"
#include "tao/util.h"

using keyczar::base::ReadFileToString;

using tao::ConnectToTCPServer;
using tao::Keys;
using tao::ScopedX509Ctx;
using tao::SerializeX509;
using tao::SignData;

namespace cloudproxy {

// TODO(kwalsh) move work to Init().
CloudClient::CloudClient(const string &client_config_path,
                         tao::TaoChildChannel *channel, tao::TaoDomain *admin)
    : admin_(admin),
      users_(new CloudUserManager()),
      host_channel_(channel),
      keys_(new Keys(client_config_path, "cloudclient", Keys::Signing)) {

  CHECK(keys_->InitHosted(*host_channel_))
      << "Could not initialize CloudClient keys";

  // TODO(kwalsh) x509 details should come from elsewhere
  if (keys_->HasFreshKeys()) {
    CHECK(keys_->CreateSelfSignedX509("US", "Washington", "Google",
                                      "cloudclient"));
  }

  // set up the TLS connection with the cert and keys and trust DB
  CHECK(SetUpSSLClientCtx(*keys_, &context_));
}

bool CloudClient::Connect(const string &server, const string &port,
                          ScopedSSL *ssl) {
  if (ssl == nullptr) {
    LOG(ERROR) << "Could not fill a null ssl pointer";
    return false;
  }

  int sock = -1;
  if (!ConnectToTCPServer(server, port, &sock)) {
    LOG(ERROR) << "Could not connect to the server at " << server << ":"
               << port;
    return false;
  }

  // The ScopedSSL will close the file descriptor when it's deleted.
  ssl->reset(SSL_new(context_.get()));
  SSL_set_fd(ssl->get(), sock);
  int r = SSL_connect(ssl->get());
  if (r <= 0) {
    LOG(ERROR) << "Could not connect to the server";
    return false;
  }

  // Get an attestation for our X.509 cert and send it to the server, then check
  // the server's reply. Don't delete the cert, since this cert is owned by the
  // SSL_CTX and will be deleted by that context.
  X509 *self_cert = SSL_get_certificate(ssl->get());
  CHECK_NOTNULL(self_cert);

  ScopedX509Ctx peer_cert(SSL_get_peer_certificate(ssl->get()));
  CHECK_NOTNULL(peer_cert.get());

  string serialized_client_cert;
  CHECK(SerializeX509(self_cert, &serialized_client_cert))
      << "Could not serialize the client certificate";

  ClientMessage cm;
  string *signature = cm.mutable_attestation();
  CHECK(host_channel_->Attest(serialized_client_cert, signature))
      << "Could not get a SignedAttestation for our client certificate";

  string serialized_cm;
  CHECK(cm.SerializeToString(&serialized_cm))
      << "Could not serialize the ClientMessage(Attestation)";

  CHECK(SendData(ssl->get(), serialized_cm)) << "Could not send attestation";

  // now listen for the connection
  string serialized_sm;
  CHECK(ReceiveData(ssl->get(), &serialized_sm))
      << "Could not get a reply from the server";

  ServerMessage sm;
  CHECK(sm.ParseFromString(serialized_sm))
      << "Could not deserialize the message from the server";

  CHECK(sm.has_attestation()) << "The server did not reply with an attestation";

  string serialized_peer_cert;
  CHECK(SerializeX509(peer_cert.get(), &serialized_peer_cert))
      << "Could not serialize the server's X.509 certificate";

  // this step also checks to see if the program hash is authorized
  string data;
  CHECK(admin_->VerifyAttestation(sm.attestation(), &data))
      << "The Attestation from the server did not pass verification";

  CHECK_EQ(data.compare(serialized_peer_cert), 0)
      << "The Attestation passed verification, but the data didn't match";

  // Once we get here, both sides have verified their quotes and know
  // that they are talked to authorized applications under the Tao.
  return true;
}

bool CloudClient::AddUser(const string &user, const keyczar::Signer &signer) {
  if (users_->HasKey(user)) {
    LOG(ERROR) << "User " << user << " already has a key";
    return false;
  }
  return users_->AddSigningKey(user, signer);
}

bool CloudClient::Authenticate(SSL *ssl, const string &subject,
                               const string &binding_file) {
  // check to see if we have already authenticated this subject
  if (users_->IsAuthenticated(subject)) {
    LOG(ERROR) << "User " << subject << " is already authenticated";
    return true;
  }

  // check to see if we have the key for this user. If not, then we can't
  // authenticate
  CHECK(users_->HasKey(subject)) << "No key loaded for user " << subject;

  keyczar::Signer *signer = nullptr;
  CHECK(users_->GetKey(subject, &signer)) << "Could not get the key for user "
                                          << subject;

  // send to the server an AUTH request
  ClientMessage cm;
  Auth *a = cm.mutable_auth();
  a->set_subject(subject);

  string serialized_cm;
  CHECK(cm.SerializeToString(&serialized_cm)) << "Could not serialize the"
                                                 " ClientMessage(Auth)";

  CHECK(SendData(ssl, serialized_cm)) << "Could not request auth";

  // now listen for the connection
  string serialized_sm;
  CHECK(ReceiveData(ssl, &serialized_sm)) << "Could not get a"
                                             " reply from the server";

  ServerMessage sm;
  CHECK(sm.ParseFromString(serialized_sm)) << "Could not deserialize the"
                                              " message from the server";

  // there are two possible replies to an Auth request: a Result(true) or a
  // Challenge
  if (sm.has_result()) {
    CHECK(sm.result().success()) << "Authentication failed";
    return true;
  }

  if (!sm.has_challenge()) {
    LOG(FATAL) << "Unknown response from CloudServer to Auth message";
    return false;
  }

  const Challenge &c = sm.challenge();
  string serialized_chall;
  CHECK(c.SerializeToString(&serialized_chall)) << "Could not serialize the"
                                                   " challenge";

  CHECK_STREQ(c.subject().c_str(), subject.c_str())
      << "Challenge for the wrong subject";

  string sig;
  CHECK(SignData(*signer, serialized_chall, ChallengeSigningContext, &sig))
      << "Could not sign the challenge";

  ClientMessage cm2;
  Response *r = cm2.mutable_response();
  r->set_serialized_chall(serialized_chall);
  r->set_signature(sig);

  SignedSpeaksFor *ssf = r->mutable_binding();

  // now create a SignedSpeaksFor annotation from the corresponding signed file
  // for this user
  string binding;
  CHECK(ReadFileToString(binding_file, &binding)) << "Could not open "
                                                  << binding_file;
  ssf->ParseFromString(binding);

  CHECK(cm2.SerializeToString(&serialized_cm))
      << "Could not serialize"
         " the Response to the Challenge";

  CHECK(SendData(ssl, serialized_cm)) << "Could not send"
                                         " Response";

  return HandleReply(ssl);
}

bool CloudClient::SendAction(SSL *ssl, const string &owner,
                             const string &object_name, Op op,
                             bool handle_reply) {
  ClientMessage cm;
  Action *a = cm.mutable_action();
  a->set_subject(owner);
  a->set_verb(op);
  a->set_object(object_name);

  string s;
  CHECK(cm.SerializeToString(&s)) << "Could not serialize Action";
  CHECK(SendData(ssl, s)) << "Could not send the Action to CloudServer";
  if (handle_reply) {
    return HandleReply(ssl);
  } else {
    return true;
  }
}

bool CloudClient::Create(SSL *ssl, const string &owner,
                         const string &object_name) {
  return SendAction(ssl, owner, object_name, CREATE, true);
}

bool CloudClient::Destroy(SSL *ssl, const string &requestor,
                          const string &object_name) {
  return SendAction(ssl, requestor, object_name, DESTROY, true);
}

bool CloudClient::Read(SSL *ssl, const string &requestor,
                       const string &object_name, const string &output_name) {
  // cloud client ignores the output name, since it's not reading any data from
  // the server
  return SendAction(ssl, requestor, object_name, READ, true);
}

bool CloudClient::Write(SSL *ssl, const string &requestor,
                        const string &input_name, const string &object_name) {
  // cloud client ignores the input name, since it's not writing any data to
  // the server
  return SendAction(ssl, requestor, object_name, WRITE, true);
}

bool CloudClient::HandleReply(SSL *ssl) {
  string s;
  if (!ReceiveData(ssl, &s)) {
    LOG(ERROR) << "Could not receive a reply from the server";
    return false;
  }

  ServerMessage sm;
  if (!sm.ParseFromString(s)) {
    LOG(ERROR) << "Could not parse the response from the server";
    return false;
  }

  if (!sm.has_result()) {
    LOG(ERROR) << "The reply from the server does not contain a Result";
    return false;
  }

  const Result &r = sm.result();
  if (!r.success()) {
    if (r.has_reason()) {
      LOG(ERROR) << "Error: " << r.reason();
    } else {
      LOG(ERROR) << "The operation failed for an unknown reason";
    }
    return false;
  }

  return true;
}

bool CloudClient::Close(SSL *ssl, bool error) {
  ClientMessage cm;
  CloseConnection *cc = cm.mutable_close();
  cc->set_error(error);

  string s;
  CHECK(cm.SerializeToString(&s)) << "Could not serialize the CloseConnection"
                                     " message";

  CHECK(SendData(ssl, s)) << "Could not send a CloseConnection to the"
                             " server";
  return true;
}
}  // namespace cloudproxy
