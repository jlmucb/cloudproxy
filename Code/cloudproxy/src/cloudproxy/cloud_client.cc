//  File: cloud_client.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the CloudClient class used to
// communicate with CloudServer instances
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#include "cloudproxy/cloud_client.h"

#include <glog/logging.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/base64w.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "tao/quote.pb.h"

#include <sstream>
#include <fstream>

using std::ifstream;
using std::stringstream;

using keyczar::base::Base64WEncode;
using keyczar::base::PathExists;
using keyczar::base::ScopedSafeString;

using tao::Quote;
using tao::SignedQuote;
using tao::Tao;
using tao::WhitelistAuthorizationManager;

namespace cloudproxy {

CloudClient::CloudClient(const string &tls_cert, const string &tls_key,
                         const string &secret,
                         const string &public_policy_keyczar,
                         const string &public_policy_pem,
                         const string &whitelist_path,
                         const string &server_addr, ushort server_port)
    : bio_(nullptr),
      public_policy_key_(
          keyczar::Verifier::Read(public_policy_keyczar.c_str())),
      context_(SSL_CTX_new(TLSv1_2_client_method())),
      users_(new CloudUserManager()),
      auth_manager_(new WhitelistAuthorizationManager()) {

  // set the policy_key to handle bytes, not strings
  public_policy_key_->set_encoding(keyczar::Keyczar::NO_ENCODING);

  CHECK(auth_manager_->Init(whitelist_path, *public_policy_key_))
      << "Could not initialize the whitelist authorization manager";

  ScopedSafeString encoded_secret(new string());
  CHECK(Base64WEncode(secret, encoded_secret.get()))
    << "Could not encode the secret as a Base64W string";

  // check to see if the public/private keys exist. If not, create them
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

  bio_.reset(BIO_new_ssl_connect(context_.get()));
  SSL *ssl = nullptr;

  BIO_get_ssl(bio_.get(), &ssl);
  CHECK(ssl) << "Could not get the SSL pointer for the TLS bio";
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  stringstream ss;
  ss << server_port;
  string host_and_port = server_addr + string(":") + ss.str();

  BIO_set_conn_hostname(bio_.get(), const_cast<char *>(host_and_port.c_str()));
}

bool CloudClient::Connect(const Tao &t) {
  int r = BIO_do_connect(bio_.get());
  if (r <= 0) {
    LOG(ERROR) << "Could not connect to the server";
    return false;
  }

  // get a quote for our X.509 cert and send it to the server, then
  // check the server's reply
  SSL *cur_ssl = nullptr;
  BIO_get_ssl(bio_.get(), &cur_ssl);
  ScopedX509Ctx self_cert(SSL_get_certificate(cur_ssl));
  CHECK_NOTNULL(self_cert.get());

  ScopedX509Ctx peer_cert(SSL_get_peer_certificate(cur_ssl));
  CHECK_NOTNULL(peer_cert.get());

  string serialized_client_cert;
  CHECK(SerializeX509(self_cert.get(), &serialized_client_cert))
      << "Could not serialize the client certificate";
  string signature;
  CHECK(t.Quote(serialized_client_cert, &signature))
      << "Could not get a SignedQuote for our client certificate";

  ClientMessage cm;
  SignedQuote *sq = cm.mutable_quote();
  CHECK(sq->ParseFromString(signature))
      << "Could not parse a SignedQuote from the Tao quote";

  string serialized_cm;
  CHECK(cm.SerializeToString(&serialized_cm))
      << "Could not serialize the ClientMessage(SignedQuote)";

  CHECK(SendData(bio_.get(), serialized_cm)) << "Could not send quote";

  // now listen for the connection
  string serialized_sm;
  CHECK(ReceiveData(bio_.get(), &serialized_sm))
      << "Could not get a reply from the server";

  ServerMessage sm;
  CHECK(sm.ParseFromString(serialized_sm))
      << "Could not deserialize the message from the server";

  CHECK(sm.has_quote()) << "The server did not reply with a quote";

  // check the quote from the server
  string serialized_server_quote;
  CHECK(sm.quote().SerializeToString(&serialized_server_quote))
      << "Could not serialize the server's SignedQuote";

  string serialized_peer_cert;
  CHECK(SerializeX509(peer_cert.get(), &serialized_peer_cert))
      << "Could not serialize the server's X.509 certificate";

  CHECK(t.VerifyQuote(serialized_peer_cert, serialized_server_quote))
      << "The SignedQuote from the server did not pass verification";

  // check that this is an authorized hash
  Quote server_quote;
  CHECK(server_quote.ParseFromString(sm.quote().serialized_quote()))
      << "Could not deserialize the Quote from the server";
  CHECK(auth_manager_->IsAuthorized(server_quote.hash()))
      << "The server hash " << server_quote.hash()
      << " in the SignedQuote was not authorized";

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

  shared_ptr<keyczar::Keyczar> signer;
  CHECK(users_->GetKey(subject, &signer)) << "Could not get the key for user "
                                          << subject;

  // send to the server an AUTH request
  ClientMessage cm;
  Auth *a = cm.mutable_auth();
  a->set_subject(subject);

  string serialized_cm;
  CHECK(cm.SerializeToString(&serialized_cm)) << "Could not serialize the"
                                                 " ClientMessage(Auth)";

  CHECK(SendData(bio_.get(), serialized_cm)) << "Could not request auth";

  // now listen for the connection
  string serialized_sm;
  CHECK(ReceiveData(bio_.get(), &serialized_sm)) << "Could not get a"
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
  CHECK(SignData(serialized_chall, &sig, signer.get())) << "Could not sign the"
                                                           " challenge";

  ClientMessage cm2;
  Response *r = cm2.mutable_response();
  r->set_serialized_chall(serialized_chall);
  r->set_signature(sig);

  SignedSpeaksFor *ssf = r->mutable_binding();

  // now create a SignedSpeaksFor annotation from the corresponding signed file
  // for this user
  ifstream ssf_file(binding_file.c_str());
  ssf->ParseFromIstream(&ssf_file);

  CHECK(cm2.SerializeToString(&serialized_cm))
      << "Could not serialize"
         " the Response to the Challenge";

  CHECK(SendData(bio_.get(), serialized_cm)) << "Could not send"
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
  CHECK(SendData(bio_.get(), s)) << "Could not send the Action to CloudServer";
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
  if (!ReceiveData(bio_.get(), &s)) {
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

  CHECK(SendData(bio_.get(), s)) << "Could not send a CloseConnection to the"
                                    " server";
  return true;
}
}  // namespace cloudproxy
