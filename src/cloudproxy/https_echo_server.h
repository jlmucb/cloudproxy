//  File: https_echo_server.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
// Description: HttpsEchoServer class that echoes https requests.
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
#ifndef CLOUDPROXY_HTTPS_ECHO_SERVER_H_
#define CLOUDPROXY_HTTPS_ECHO_SERVER_H_

#include <string>

#include <glog/logging.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <keyczar/openssl/util.h>
#include <openssl/ssl.h>

#include "cloudproxy/util.h"
#include "tao/util.h"

using std::string;

namespace keyczar {
class Keyczar;
}  // namespace keyczar

namespace cloudproxy {

class CloudServerThreadData;

/// A simple https server echos whatever message https client sends.
class HttpsEchoServer {
 public:
  /// Create an HttpsEchoServer.
  /// @param admin The administrative domain for this server.
  /// @param server_keys A directory for server keys and TLS files. If the files
  /// don't yet exist, they will be created (admin must be unlocked in this
  /// case).
  /// @param secret The secret for encrypting server keys.
  /// @param host The name or IP address of the host to bind the server to.
  /// @param port The port to bind the server to.
  HttpsEchoServer(const string &server_config_path, const string &host,
                  const string &port, tao::TaoChildChannel *channel,
                  tao::TaoDomain *admin);

  /// Start listening to the port and handle connections as they arrive.
  /// @param t A server socket.
  /// @param single_channel Whether or not to stop after a single connection.
  bool Listen(bool single_channel);

 protected:
  // Handle requests for https resources.
  virtual bool HandleHttpsRequest(const string &https_request, bool *reply,
                                  string *https_response,
                                  CloudServerThreadData &cstd);  // NOLINT

 private:
  /// Configuration for this administrative domain
  scoped_ptr<tao::TaoDomain> admin_;

  /// Listen on a bio and handle an incoming message from a client. Spawn a
  /// thread for each connection.
  /// @param accept_sock A connected to use to establish an SSL connection.
  /// @param t A connection to a host Tao to use in handling requests
  void HandleConnection(int accept_sock);

  // A (static) random number generator for no reason.
  keyczar::RandImpl *rand_;

  // The host and port to serve from.
  string host_;  // currently ignored: we listen on any interface
  string port_;

  // A context object that stores all the TLS parameters for the connection.
  ScopedSSLCtx context_;

  /// A connection to the host Tao.
  scoped_ptr<tao::TaoChildChannel> host_channel_;

  /// A signing key.
  scoped_ptr<tao::Keys> keys_;

  bool GetTaoCAX509Chain(const string &details_text);

  DISALLOW_COPY_AND_ASSIGN(HttpsEchoServer);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_HTTPS_ECHO_SERVER_H_
