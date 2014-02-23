//  File: http_echo_server.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
// Description: HttpEchoServer class that echoes http requests.
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

#ifndef CLOUDPROXY_HTTP_ECHO_SERVER_H_
#define CLOUDPROXY_HTTP_ECHO_SERVER_H_

#include <string>
#include <glog/logging.h>
#include <keyczar/keyczar.h>  // DISALLOW_COPY_AND_ASSIGN

using std::string;

namespace cloudproxy {
/// A simple http server echos whatever message http client sends.
class HttpEchoServer {
 public:
  /// Create an HttpEchoServer.
  /// @param host The name or IP address of the host to bind the server to.
  /// @param port The port to bind the server to.
  HttpEchoServer(const string &host, const string &port);

  virtual ~HttpEchoServer() {}

  /// Start listening to the port and handle connections as they arrive.
  /// @param t A server socket.
  /// @param single_channel Whether or not to stop after a single connection.
  bool Listen(bool single_channel);

 protected:
  // Handle requests for http resources.
  virtual bool HandleHttpRequest(const string &http_request, bool *reply,
                                 string *http_response);

 private:
  /// Listen on a bio and handle an incoming message from a client. Spawn a
  /// thread for each connection.
  /// @param accept_sock A connected to use to establish an SSL connection.
  /// @param t A connection to a host Tao to use in handling requests
  void HandleConnection(int accept_sock);

  // The host and port to serve from.
  string host_;  // currently ignored: we listen on any interface
  string port_;

  DISALLOW_COPY_AND_ASSIGN(HttpEchoServer);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_HTTP_ECHO_SERVER_H_
