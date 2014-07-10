//  File: http_echo_server.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
// Description: Implementation of the HttpEchoServer class that echoes
// http requests.
//
//  Copyright (c) 2013, Kevin Walsh  All rights reserved.
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
#include <sys/socket.h>
#include <sys/unistd.h>

#include <sstream>
#include <thread>

#include <glog/logging.h>

#include "cloudproxy/http_echo_server.h"
#include "cloudproxy/util.h"
#include "tao/util.h"

using std::string;
using std::stringstream;
using std::thread;

using tao::OpenTCPSocket;
using tao::ScopedFd;

#define READ_BUFFER_LEN 16384

namespace cloudproxy {

HttpEchoServer::HttpEchoServer(const string &host, const string &port)
    : host_(host), port_(port) {}

bool HttpEchoServer::Listen(bool single_channel) {
  // Set up a TCP connection for the given host and port.
  ScopedFd sock(new int(-1));

  if (!OpenTCPSocket(host_, port_, sock.get())) {
    LOG(ERROR) << "Could not open a TCP socket on port " << host_ << ":"
               << port_;
    return false;
  }

  while (true) {
    int accept_sock = accept(*sock, NULL, NULL);
    if (accept_sock == -1) {
      PLOG(ERROR) << "Could not accept a connection on the socket";
      return false;
    }

    if (single_channel) {
      HandleConnection(accept_sock);
      return true;
    } else {
      thread t(&HttpEchoServer::HandleConnection, this, accept_sock);
      t.detach();
    }
  }

  return true;
}

void HttpEchoServer::HandleConnection(int accept_sock) {
  ScopedFd sock(new int(accept_sock));

  size_t buffer_len = READ_BUFFER_LEN;
  unique_ptr<char[]> buf(new char[buffer_len]);

  // read up to, and including, the first "\r\n\r\n"
  size_t filled_len = 0;
  size_t request_len = 0;
  while (request_len == 0 && filled_len < buffer_len) {
    int in_len = ReceivePartialData(*sock, buf.get(), filled_len, buffer_len);
    if (in_len < 0) {
      LOG(ERROR) << "Connection failed before request could be read";
      return;
    }
    if (in_len == 0) {
      LOG(ERROR) << "Connection closed before request could be read";
      return;
    }

    filled_len += in_len;
    for (unsigned int i = filled_len - in_len; i < filled_len; i++) {
      if (i >= 4 && !memcmp(buf.get() + i - 4 + 1, "\r\n\r\n", 4)) {
        request_len = i + 1;
        break;
      }
    }
  }

  if (request_len == 0) {
    LOG(ERROR) << "HTTP request was invalid";
    return;
  }

  string http_request(buf.get(), request_len);

  bool reply = true;
  string http_response;
  bool rv = HandleHttpRequest(http_request, &reply, &http_response);

  if (rv && reply) {
    unsigned int response_len = http_response.length();
    int out_len = write(*sock, http_response.c_str(), response_len);
    if (out_len == 0)
      LOG(ERROR) << "HTTP session closed before response was sent\n";
    else if (out_len < 0)
      LOG(ERROR) << "HTTP session failed before response was sent\n";
    else if (static_cast<unsigned int>(out_len) != response_len)
      LOG(ERROR) << "Failed to send complete http response.";
  }
}

bool HttpEchoServer::HandleHttpRequest(const string &http_request, bool *reply,
                                       string *http_response) {
  VLOG(1) << "Processing http request\n"
          << "---- BEGIN HTTP REQUEST ----";
  VLOG(1) << http_request << "----- END HTTP REQUEST -----";

  stringstream msg;
  string status;
  if (http_request.length() > 4 && http_request.substr(0, 4) == "GET ") {
    status = "HTTP/1.1 200 OK";
    msg << "<html><head><title>Echo</title></head>"
        << "<body>"
        << "<h3>Echo</h3>"
        << "<pre>" << http_request << "</pre>"
        << "</body>"
        << "</html>";
  } else {
    status = "HTTP/1.1 404 Not Found";
    msg << "<html><head><title>Sorry</title></head>"
        << "<body>"
        << "<h3>Sorry...</h3>"
        << "<p>Invalid request.</p>"
        << "</body>"
        << "</html>";
  }
  stringstream out;
  out << status << "\r\n"
      << "Content-Type: text/html; charset=UTF-8\r\n"
      << "Content-Length: " << msg.str().length() << "\r\n"
      << "Connection: close\r\n"
      << "\r\n" << msg.str();
  http_response->assign(out.str());
  return true;
}

}  // namespace cloudproxy
