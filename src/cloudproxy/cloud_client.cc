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

#include <sstream>
#include <fstream>

#include <glog/logging.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/base64w.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "tao/attestation.pb.h"
#include "tao/tao_auth.h"
#include "tao/util.h"

using std::ifstream;
using std::stringstream;

using keyczar::base::Base64WEncode;
using keyczar::base::PathExists;
using keyczar::base::ScopedSafeString;

using tao::Attestation;
using tao::SignData;
using tao::TaoChildChannel;
using tao::TaoAuth;

namespace cloudproxy {

CloudClient::CloudClient(const string &tls_cert, const string &tls_key,
                         const string &secret,
                         const string &public_policy_keyczar,
                         const string &public_policy_pem,
                         const string &server_addr, ushort server_port,
                         TaoAuth *auth_manager)
    : bio_(nullptr),
      public_policy_key_(
          keyczar::Verifier::Read(public_policy_keyczar.c_str())),
      context_(SSL_CTX_new(TLSv1_2_client_method())),
      users_(new CloudUserManager()),
      auth_manager_(auth_manager) {
  // Set the policy_key to handle bytes, not strings.
  public_policy_key_->set_encoding(keyczar::Keyczar::NO_ENCODING);

  ScopedSafeString encoded_secret(new string());
  CHECK(Base64WEncode(secret, encoded_secret.get()))
      << "Could not encode the secret as a Base64W string";

  // Check to see if the public/private keys exist. If not, create them.
  FilePath fp(tls_cert);
  if (!PathExists(fp)) {
    CHECK(CreateECDSAKey(tls_key, tls_cert, *encoded_secret, "US", "Google",
                         "client"))
        << "Could not create new keys for OpenSSL for the client";
  }

  // set up the TLS connection with the cert and keys and trust DB
  CHECK(SetUpSSLCTX(context_.get(), public_policy_pem, tls_cert, tls_key,
                    *encoded_secret))
      << "Could not set up the client TLS connection";

  bio_ = BIO_new_ssl_connect(context_.get());
  SSL *ssl = nullptr;

  BIO_get_ssl(bio_, &ssl);
  CHECK(ssl) << "Could not get the SSL pointer for the TLS bio";
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  stringstream ss;
  ss << server_port;
  string host_and_port = server_addr + string(":") + ss.str();

  BIO_set_conn_hostname(bio_, const_cast<char *>(host_and_port.c_str()));
}

bool CloudClient::Connect(const TaoChildChannel &t) {
  int r = BIO_do_connect(bio_);
  if (r <= 0) {
    LOG(ERROR) << "Could not connect to the server";
    LOG(ERROR) << "The OpenSSL error was: " << ERR_error_string(r, NULL);
    return false;
  }

  LOG(INFO) << "Connected to the server";
  // get an attestation for our X.509 cert and send it to the server,
  // then check the server's reply
  SSL *cur_ssl = nullptr;
  BIO_get_ssl(bio_, &cur_ssl);
  ScopedX509Ctx self_cert(SSL_get_certificate(cur_ssl));
  CHECK_NOTNULL(self_cert.get());

  ScopedX509Ctx peer_cert(SSL_get_peer_certificate(cur_ssl));
  CHECK_NOTNULL(peer_cert.get());

  string serialized_client_cert;
  CHECK(SerializeX509(self_cert.get(), &serialized_client_cert))
      << "Could not serialize the client certificate";

  ClientMessage cm;
  string *signature = cm.mutable_attestation();
  CHECK(t.Attest(serialized_client_cert, signature))
      << "Could not get a SignedAttestation for our client certificate";

  string serialized_cm;
  CHECK(cm.SerializeToString(&serialized_cm))
      << "Could not serialize the ClientMessage(Attestation)";

  CHECK(SendData(bio_, serialized_cm)) << "Could not send attestation";

  // now listen for the connection
  string serialized_sm;
  CHECK(ReceiveData(bio_, &serialized_sm))
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
  CHECK(auth_manager_->VerifyAttestation(sm.attestation(), &data))
      << "The Attestation from the server did not pass verification";

  CHECK_EQ(data.compare(serialized_peer_cert), 0)
      << "The Attestation passed verification, but the data didn't match";

  LOG(INFO) << "Channel authentication complete";
  // once we get here, both sides have verified their quotes and know
  // that they are talked to authorized applications under the Tao.
  return true;
}

bool CloudClient::AddUser(const string &user, const string &key_path,
                          const string &password) {
  if (users_->HasKey(user)) {
    LOG(ERROR) << "User " << user << " already has a key";
    return false;
  }

  return users_->AddSigningKey(user, key_path, password);
}

bool CloudClient::Authenticate(const string &subject,
                               const string &binding_file) {
  // check to see if we have already authenticated this subject
  if (users_->IsAuthenticated(subject)) {
    LOG(ERROR) << "User " << subject << " is already authenticated";
    return true;
  }

  // check to see if we have the key for this user. If not, then we can't
  // authenticate
  CHECK(users_->HasKey(subject)) << "No key loaded for user " << subject;

  keyczar::Keyczar *signer = nullptr;
  CHECK(users_->GetKey(subject, &signer)) << "Could not get the key for user "
                                          << subject;

  // send to the server an AUTH request
  ClientMessage cm;
  Auth *a = cm.mutable_auth();
  a->set_subject(subject);

  string serialized_cm;
  CHECK(cm.SerializeToString(&serialized_cm)) << "Could not serialize the"
                                                 " ClientMessage(Auth)";

  CHECK(SendData(bio_, serialized_cm)) << "Could not request auth";

  // now listen for the connection
  string serialized_sm;
  CHECK(ReceiveData(bio_, &serialized_sm)) << "Could not get a"
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
  CHECK(SignData(serialized_chall, &sig, signer)) << "Could not sign the"
                                                     " challenge";

  ClientMessage cm2;
  Response *r = cm2.mutable_response();
  r->set_serialized_chall(serialized_chall);
  r->set_signature(sig);

  SignedSpeaksFor *ssf = r->mutable_binding();

  // now create a SignedSpeaksFor annotation from the corresponding signed file
  // for this user
  ifstream ssf_file(binding_file.c_str());
  CHECK(ssf_file) << "Could not open " << binding_file;
  ssf->ParseFromIstream(&ssf_file);

  CHECK(cm2.SerializeToString(&serialized_cm))
      << "Could not serialize"
         " the Response to the Challenge";

  CHECK(SendData(bio_, serialized_cm)) << "Could not send"
                                                " Response";

  LOG(INFO) << "Auth successful: waiting for reply";
  return HandleReply();
}

bool CloudClient::SendAction(const string &owner, const string &object_name,
                             Op op, bool handle_reply) {
  ClientMessage cm;
  Action *a = cm.mutable_action();
  a->set_subject(owner);
  a->set_verb(op);
  a->set_object(object_name);

  string s;
  CHECK(cm.SerializeToString(&s)) << "Could not serialize Action";
  CHECK(SendData(bio_, s)) << "Could not send the Action to CloudServer";
  if (handle_reply) {
    return HandleReply();
  } else {
    return true;
  }
}

bool CloudClient::Create(const string &owner, const string &object_name) {
  return SendAction(owner, object_name, CREATE, true);
}

bool CloudClient::Destroy(const string &requestor, const string &object_name) {
  return SendAction(requestor, object_name, DESTROY, true);
}

bool CloudClient::Read(const string &requestor, const string &object_name,
                       const string &output_name) {
  // cloud client ignores the output name, since it's not reading any data from
  // the server
  return SendAction(requestor, object_name, READ, true);
}

bool CloudClient::Write(const string &requestor, const string &input_name,
                        const string &object_name) {
  // cloud client ignores the input name, since it's not writing any data to
  // the server
  return SendAction(requestor, object_name, WRITE, true);
}

bool CloudClient::HandleReply() {
  string s;
  if (!ReceiveData(bio_, &s)) {
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

  LOG(INFO) << "The operation was successful";
  return true;
}

bool CloudClient::Close(bool error) {
  ClientMessage cm;
  CloseConnection *cc = cm.mutable_close();
  cc->set_error(error);

  string s;
  CHECK(cm.SerializeToString(&s)) << "Could not serialize the CloseConnection"
                                     " message";

  CHECK(SendData(bio_, s)) << "Could not send a CloseConnection to the"
                                    " server";
  SSL *cur_ssl = nullptr;
  BIO_get_ssl(bio_, &cur_ssl);
  if (SSL_shutdown(cur_ssl) == 0) {
    // Then we need to call it again to really shut down the connection.
    SSL_shutdown(cur_ssl);
  }

  return true;
}
}  // namespace cloudproxy
