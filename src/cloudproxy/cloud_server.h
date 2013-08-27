//  File: cloud_server.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudServer class is used to implement CloudProxy
// applications
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



#ifndef CLOUDPROXY_CLOUD_SERVER_H_
#define CLOUDPROXY_CLOUD_SERVER_H_

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloud_server_thread_data.h"
#include "cloudproxy/util.h"
#include "tao/tao.h"
#include "tao/quote.pb.h"
#include "tao/whitelist_authorization_manager.h"
#include <openssl/ssl.h>
#include <keyczar/openssl/util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <pthread.h>

#include <map>
#include <mutex>
#include <thread>
#include <string>
#include <set>

using std::map;
using std::mutex;
using std::thread;
using std::set;
using std::string;

namespace cloudproxy {

// A server that handles requests from a CloudClient (and a base class for all
// such servers). This class handles requests from a CloudClient and checks its
// ACL database to see if the operations is authorized by CloudProxy policy.
class CloudServer {
 public:
  static const int NonceSize = 16;

  // Creates a CloudServer with a given key store, location of its signed ACL
  // database, and the port on which to listen. It also needs the location of
  // the public policy key in two ways: one as a PEM file for use in TLS, and
  // one as public RSA keyczar directory
  CloudServer(const string &tls_cert, const string &tls_key,
              const string &tls_password, const string &public_policy_keyczar,
              const string &public_policy_pem, const string &acl_location,
              const string &whitelist_location, const string &host,
              ushort port);

  virtual ~CloudServer() {}

  // Start listening to the port and handle connections as they arrive.
  // The Tao implementation allows the server to check that programs
  // that connect to it are allowed by the Tao and to get a
  // SignedAttestation for its key
  bool Listen(const tao::Tao &t);

 protected:
  // TODO(tmroeder): in C++14, make these shared_mutex and support readers
  // and writers semantics

  // mutex for authorization
  mutex auth_m_;

  // mutex for key management
  mutex key_m_;

  // mutex for data operations
  mutex data_m_;

  // mutex for Tao communication
  mutex tao_m_;

  // Handles specific requests for resources. In this superclass
  // implementation, it just deals with names in a std::set. Subclasses
  // override these methods to implement their functionality
  virtual bool HandleCreate(const Action &action, BIO *bio, string *reason,
                            bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleDestroy(const Action &action, BIO *bio, string *reason,
                             bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleWrite(const Action &action, BIO *bio, string *reason,
                           bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleRead(const Action &action, BIO *bio, string *reason,
                          bool *reply, CloudServerThreadData &cstd);

  // sends a reply to the client with a given success code and error message
  bool SendReply(BIO *bio, bool success, const string &reason);

 private:

  // handles an incoming message from a client
  bool ListenAndHandle(BIO *bio, string *reason, bool *reply);
  void HandleConnection(BIO *bio, const tao::Tao *t);
  bool HandleMessage(const ClientMessage &message, BIO *bio, string *reason,
                     bool *reply, bool *close, CloudServerThreadData &cstd,
                     const tao::Tao &t);
  bool HandleAuth(const Auth &auth, BIO *bio, string *reason, bool *reply,
                  CloudServerThreadData &cstd);
  bool HandleResponse(const Response &response, BIO *bio, string *reason,
                      bool *reply, CloudServerThreadData &cstd);
  bool HandleAttestation(const tao::SignedAttestation &attest, BIO *bio, string *reason,
			 bool *reply, CloudServerThreadData &cstd, const tao::Tao &t);

  // the public policy key, used to check signatures
  scoped_ptr<keyczar::Keyczar> public_policy_key_;

  // (static) random number generator for generating challenges
  keyczar::RandImpl *rand_;

  // a context object that stores all the TLS parameters for the connection
  ScopedSSLCtx context_;

  // the main BIO set up for this connection
  keyczar::openssl::ScopedBIO bio_;

  // an accept BIO that listens on the TLS connection
  keyczar::openssl::ScopedBIO abio_;

  // an object for managing authorization policy
  scoped_ptr<CloudAuth> auth_;

  // an object that manages keys for users known to the server
  scoped_ptr<CloudUserManager> users_;

  // a simple object management tool: a set of object names
  set<string> objects_;

  // authorized hashes of programs
  scoped_ptr<tao::WhitelistAuthorizationManager> auth_manager_;

  DISALLOW_COPY_AND_ASSIGN(CloudServer);
};
}

#endif  // CLOUDPROXY_CLOUD_SERVER_H_
