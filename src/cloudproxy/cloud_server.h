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

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <glog/logging.h>
#include <openssl/ssl.h>
#include <keyczar/openssl/util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <pthread.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"

using std::map;
using std::mutex;
using std::thread;
using std::set;
using std::string;

namespace keyczar {
class Keyczar;
}  // namespace keyczar

namespace tao {
class TaoAuth;
class TaoChildChannel;
}  // namespace tao

namespace cloudproxy {

class CloudAuth;
class CloudServerThreadData;
class CloudUserManager;

/// A server that handles requests from a CloudClient (and a base class for all
/// such servers). This class handles requests from a CloudClient and checks its
/// ACL database to see if the operations is authorized by CloudProxy policy.
class CloudServer {
 public:
  static const int NonceSize = 16;

  /// Create a CloudServer.
  /// @param tls_cert The path to use for an OpenSSL TLS certificate.
  /// @param tls_key The path to use for an OpenSSL TLS private key.
  /// @param tls_password The file to use for a Tao-sealed TLS password to use
  /// to encrypt the private key.
  /// @param public_policy_keyczar The path to the public policy key.
  /// @param public_policy_pem The path to an OpenSSL representation of the
  /// public policy key.
  /// @param acl_location The path to a signed ACL giving permissions for
  /// operations on the server.
  /// @param host The name or IP address of the host to bind the server to.
  /// @param port The port to bind the server to.
  /// @param auth_manager An authorization manager to use to verify Tao
  /// attestations.
  CloudServer(const string &tls_cert, const string &tls_key,
              const string &tls_password, const string &public_policy_keyczar,
              const string &public_policy_pem, const string &acl_location,
              const string &host, ushort port, tao::TaoAuth *auth_manager);

  virtual ~CloudServer() {}

  /// Start listening to the port and handle connections as they arrive.
  /// The Tao implementation allows the server to check that programs
  /// that connect to it are allowed by the Tao and to get a
  /// Attestation for its key
  /// @param t A connection to a host Tao.
  bool Listen(const tao::TaoChildChannel &t);

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

  /// @{
  /// Check an action and perform the operation it requests.
  /// @param action The action requested by a client
  /// @param bio A channel for communication with the requesting client.
  /// @param[out] reason A string to fill with an error message if the action is
  /// not authorized.
  /// @param[out] reply Indicates success or failure of the action.
  /// @return A value that indicates whether or not the action was performed
  /// without errors.
  virtual bool HandleCreate(const Action &action, BIO *bio, string *reason,
                            bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleDestroy(const Action &action, BIO *bio, string *reason,
                             bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleWrite(const Action &action, BIO *bio, string *reason,
                           bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleRead(const Action &action, BIO *bio, string *reason,
                          bool *reply, CloudServerThreadData &cstd);
  /// @}

  /// Send a reply to the client with a given success code and error message
  /// @param bio A channel for communication with the client.
  /// @param success The success value to communicate in the reply.
  /// @param reason The reason for failure, if the action failed.
  bool SendReply(BIO *bio, bool success, const string &reason);

 private:

  /// Listen on a bio and handle an incoming message from a client. Spawn a
  /// thread for each connection.
  /// @param bio A channel to listen for client requests on.
  /// @param t A connection to a host Tao to use in handling requests
  void HandleConnection(BIO *bio, const tao::TaoChildChannel *t);

  /// Handle a message from a client.
  /// @param message A client message.
  /// @param bio A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the request succeeded.
  /// @param ctsd Context for this thread.
  /// @param t The Tao host connection to use.
  bool HandleMessage(const ClientMessage &message, BIO *bio, string *reason,
                     bool *reply, bool *close, CloudServerThreadData &cstd,
                     const tao::TaoChildChannel &t);

  /// Handle a request to authorize a user.
  /// @param auth An authorization request.
  /// @param bio A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the request succeeded.
  /// @param ctsd Context for this thread.
  bool HandleAuth(const Auth &auth, BIO *bio, string *reason, bool *reply,
                  CloudServerThreadData &cstd);

  /// Handle a response from a client.
  /// @param auth A response from a client.
  /// @param bio A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the response was valid.
  /// @param ctsd Context for this thread.
  bool HandleResponse(const Response &response, BIO *bio, string *reason,
                      bool *reply, CloudServerThreadData &cstd);

  /// Handle an attestation from a client.
  /// @param auth An attestation to check.
  /// @param bio A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the attestation was valid.
  /// @param ctsd Context for this thread.
  bool HandleAttestation(const string &attestation, BIO *bio, string *reason,
                         bool *reply, CloudServerThreadData &cstd,
                         const tao::TaoChildChannel &t);

  // The public policy key, used to check signatures.
  scoped_ptr<keyczar::Keyczar> public_policy_key_;

  // A (static) random number generator for generating challenges.
  keyczar::RandImpl *rand_;

  // A context object that stores all the TLS parameters for the connection.
  ScopedSSLCtx context_;

  // The main BIO set up for this connection.
  keyczar::openssl::ScopedBIO bio_;

  // An accept BIO that listens on the TLS connection.
  keyczar::openssl::ScopedBIO abio_;

  // An object for managing authorization policy.
  scoped_ptr<CloudAuth> auth_;

  // An object that manages keys for users known to the server.
  scoped_ptr<CloudUserManager> users_;

  // A simple object management tool: a set of object names.
  set<string> objects_;

  // Authorized hashes of programs and VerifyAttestation.
  scoped_ptr<tao::TaoAuth> auth_manager_;

  DISALLOW_COPY_AND_ASSIGN(CloudServer);
};
}

#endif  // CLOUDPROXY_CLOUD_SERVER_H_
