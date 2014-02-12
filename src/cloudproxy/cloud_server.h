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

#include <pthread.h>

#include <mutex>
#include <set>
#include <string>

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/openssl/util.h>
#include <openssl/ssl.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/tao_domain.h"

using std::mutex;
using std::set;
using std::string;

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
  /// @param server_config_path A directory to use for keys and TLS files.
  /// @param acl_location The path to a signed ACL giving permissions for
  /// operations on the server.
  /// @param host The name or IP address of the host to bind the server to.
  /// @param port The port to bind the server to.
  /// @param channel A connection to the host Tao. Ownership is taken.
  /// @param admin The configuration for this administrative domain. Ownership
  /// is taken.
  CloudServer(const string &server_config_path, const string &acl_location,
              const string &host, const string &port,
              tao::TaoChildChannel *channel, tao::TaoDomain *admin);
  virtual ~CloudServer() {}

  /// Start listening to the port and handle connections as they arrive.
  /// The Tao implementation allows the server to check that programs
  /// that connect to it are allowed by the Tao and to get a
  /// Attestation for its key.
  /// @param single_channel Whether or not to stop after a single connection.
  bool Listen(bool single_channel);

 protected:
  // TODO(tmroeder): in C++14, make these shared_mutex and support readers
  // and writers semantics

  /// mutex for authorization
  mutex auth_m_;

  /// mutex for key management
  mutex key_m_;

  /// mutex for data operations
  mutex data_m_;

  /// mutex for Tao communication
  mutex tao_m_;

  // Handles specific requests for resources. In this superclass
  // implementation, it just deals with names in a std::set. Subclasses
  // override these methods to implement their functionality

  /// @{
  /// Check an action and perform the operation it requests.
  /// @param action The action requested by a client
  /// @param ssl A channel for communication with the requesting client.
  /// @param[out] reason A string to fill with an error message if the action is
  /// not authorized.
  /// @param[out] reply Indicates success or failure of the action.
  /// @param cstd A context parameter for the thread.
  /// @return A value that indicates whether or not the action was performed
  /// without errors.
  virtual bool HandleCreate(const Action &action, SSL *ssl, string *reason,
                            bool *reply,
                            CloudServerThreadData &cstd);  // NOLINT
  virtual bool HandleDestroy(const Action &action, SSL *ssl, string *reason,
                             bool *reply,
                             CloudServerThreadData &cstd);  // NOLINT
  virtual bool HandleWrite(const Action &action, SSL *ssl, string *reason,
                           bool *reply, CloudServerThreadData &cstd);  // NOLINT
  virtual bool HandleRead(const Action &action, SSL *ssl, string *reason,
                          bool *reply, CloudServerThreadData &cstd);  // NOLINT
                                                                      /// @}

  /// Send a reply to the client with a given success code and error message
  /// @param ssl A channel for communication with the client.
  /// @param success The success value to communicate in the reply.
  /// @param reason The reason for failure, if the action failed.
  bool SendReply(SSL *ssl, bool success, const string &reason);

 private:
  /// Configuration for this administrative domain
  scoped_ptr<tao::TaoDomain> admin_;

  /// Listen on a socket and handle an incoming message from a client. Spawn a
  /// thread for each connection.
  /// @param accept_sock A connected to use to establish an SSL connection.
  void HandleConnection(int accept_sock);

  /// Handle a message from a client.
  /// @param message A client message.
  /// @param ssl A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the request succeeded.
  /// @param ctsd Context for this thread.
  bool HandleMessage(const ClientMessage &message, SSL *ssl, string *reason,
                     bool *reply, bool *close,
                     CloudServerThreadData &cstd);  // NOLINT

  /// Handle a request to authorize a user.
  /// @param auth An authorization request.
  /// @param ssl A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the request succeeded.
  /// @param ctsd Context for this thread.
  bool HandleAuth(const Auth &auth, SSL *ssl, string *reason, bool *reply,
                  CloudServerThreadData &cstd);  // NOLINT

  /// Handle a response from a client.
  /// @param auth A response from a client.
  /// @param ssl A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the response was valid.
  /// @param ctsd Context for this thread.
  bool HandleResponse(const Response &response, SSL *ssl, string *reason,
                      bool *reply, CloudServerThreadData &cstd);  // NOLINT

  /// Handle an attestation from a client.
  /// @param auth An attestation to check.
  /// @param ssl A channel to use for replies to the client.
  /// @param[out] reason The reason for failure, if any.
  /// @param[out] reply Whether or not the attestation was valid.
  /// @param ctsd Context for this thread.
  bool HandleAttestation(const string &attestation, SSL *ssl, string *reason,
                         bool *reply, CloudServerThreadData &cstd);  // NOLINT

  /// A (static) random number generator for generating challenges.
  keyczar::RandImpl *rand_;

  /// The host and port to serve from.
  /// @{
  string host_;  // currently ignored: we listen on any interface
  string port_;
  /// @}

  /// A context object that stores all the TLS parameters for the connection.
  ScopedSSLCtx context_;

  /// An object for managing authorization policy.
  scoped_ptr<CloudAuth> auth_;

  /// An object that manages keys for users known to the server.
  scoped_ptr<CloudUserManager> users_;

  /// A simple object management tool: a set of object names.
  set<string> objects_;

  /// A connection to the host Tao.
  scoped_ptr<tao::TaoChildChannel> host_channel_;

  /// A signing key.
  scoped_ptr<tao::Keys> keys_;

  DISALLOW_COPY_AND_ASSIGN(CloudServer);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_CLOUD_SERVER_H_
