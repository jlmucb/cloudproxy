//  File: cloud_server.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Base class for hosted program server that listens on a TCP port
// and does TLS+Tao authentication with peers.
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

#include <mutex>
#include <string>

#include "cloudproxy/util.h"
#include "tao/keys.h"

namespace tao {
class TaoGuard;
}

namespace cloudproxy {
class CloudChannel;

/// A server that listens on a TCP port and does TLS+Tao authentication with
/// peers. Messages are exchanged using protobuf Message streams. Subclasses
/// implement handlers that respond to incoming messages.
class CloudServer {
 public:
  /// Constructor.
  /// @param host The name or IP address of the host to bind the server to.
  /// @param port The port to bind the server to.
  /// @param guard A guard implementation for authorizing peer connection attempts.
  /// Subclasses may use this to authorize operations by peers.
  /// TODO(kwalsh) Maybe add option to authenticate not as our actual name, but
  /// as some subprincipal of our actual name?
  CloudServer(const string &host, const string &port, tao::TaoGuard *guard);
  virtual bool Init();
  virtual ~CloudServer() {}

  /// Listen on the port and handle connections as they arrive.
  virtual bool Listen();

  /// Shut down the listening thread. This is safe to call from handler threads
  /// or other threads.
  virtual bool Shutdown();

 protected:
  /// Handle requests from peers. This class handles only basic connection
  /// management and authentication. Subclasses handle other operations.

  /// Handle a new, unauthenticated connection. This is invoked on a new thread
  /// for each connection. It completes TLS and Tao authentication handshake,
  /// queries the guard for authorization to connect, invokes
  /// HandleAuthenticatedConnection(), then closes the connection.
  /// @param chan A newly allocated connection. Ownership is taken.
  virtual void HandleNewConnection(CloudChannel *chan);

  /// Handle requests on an authenticated connection. Subclasses implement this.
  /// @param chan An authenticated connection. Ownership is not taken.
  virtual bool HandleAuthenticatedConnection(CloudChannel *chan) = 0;
 
  /// The host to serve from. Currently ignored: we listen on any interface.
  string host_;

  /// The port to server from.
  string port_;

  /// A guard for authorization queries.
  scoped_ptr<tao::TaoGuard> guard_;
  
 private:
  /// A context object that stores TLS parameters.
  ScopedSSLCtx tls_context_;

  /// A signing key for TLS.
  scoped_ptr<tao::Signer> tls_key_;

  /// A self-signed certificate for the TLS key.
  string tls_self_cert_;

  /// Delegation for the TLS key, signed on our behalf by the host Tao.
  string tls_delegation_;

  /// The server socket.
  tao::ScopedFd server_sock_;
 
  /// A mutex to protect server_sock_.
  std::mutex server_sock_mutex_;

  DISALLOW_COPY_AND_ASSIGN(CloudServer);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_CLOUD_SERVER_H_
