//  File: cloud_server.cc
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
#include "cloudproxy/cloud_server.h"

#include <thread>

#include <glog/logging.h>

#include "cloudproxy/cloud_channel.h"
#include "tao/keys.h"
#include "tao/tao.h"
#include "tao/tao_guard.h"

using std::lock_guard;
using std::mutex;
using std::thread;

using tao::Keys;
using tao::Tao;
using tao::TaoGuard;

namespace cloudproxy {

CloudServer::CloudServer(const string &host, const string &port,
                         TaoGuard *guard)
    : host_(host),
      port_(port),
      guard_(guard),
      tls_key_(new Keys("CloudServer", Keys::Signing)),
      server_sock_(new int(-1)) {}

bool CloudServer::Init() {
  Tao *host_tao = Tao::GetHostTao();
  if (host_tao == nullptr) {
    LOG(ERROR) << "No host tao available";
    return false;
  }
  if (!tls_key_->InitTemporaryHosted(host_tao)) {
    LOG(ERROR) << "Could not initialize CloudServer keys";
    return false;
  }
  if (!tls_key_->GetHostDelegation(&tls_delegation_)) {
    LOG(ERROR) << "Could not load delegation for attestation key";
    return false;
  }
  // x509 details are mostly not used by peers, so we use arbitrary constants
  // here. However, commonname must match the Key nickname, above.
  string nickname = tao::quotedString(tls_key_->Nickname());
  string details = string("country: \"US\" "
                          "state: \"Washington\" "
                          "organization: \"Google\" ") +
                   "commonname: " + nickname;
  if (!tls_key_->CreateSelfSignedX509(details, &tls_self_cert_)) {
    LOG(ERROR) << "Could not create self signed x509";
    return false;
  }
  if (!SetUpSSLServerCtx(*tls_key_, tls_self_cert_, &tls_context_)) {
    LOG(ERROR) << "Could not set up server TLS";
    return false;
  }
  return true;
}

bool CloudServer::Listen() {
  // Set up a TCP connection for the given host and port.
  int sock;
  {
    lock_guard<mutex> l(server_sock_mutex_);
    if (*server_sock_ != -1) {
      LOG(ERROR) << "Socket is already open";
      return false;
    }
    if (!tao::OpenTCPSocket(host_, port_, &sock)) {
      LOG(ERROR) << "Could not open TCP socket on " << host_ << ":" << port_;
      return false;
    }
    *server_sock_ = sock;
  }

  while (true) {
    int accept_sock = accept(sock, nullptr, nullptr);
    if (accept_sock < 0) {
      {
        lock_guard<mutex> l(server_sock_mutex_);
        if (sock != *server_sock_) {
          break;
        }
        *server_sock_ = -1;
      }
      PLOG(ERROR) << "Could not accept a connection on the socket";
      close(sock);
      return false;
    }

    scoped_ptr<CloudChannel> conn(new CloudChannel(tls_context_.get(), accept_sock));
    thread t(&CloudServer::HandleNewConnection, this, conn.release());
    t.detach();
  }
  // Someone called shutdown() on the socket.
  close(sock);
  LOG(INFO) << "CloudServer socket closed";
  return true;
}

bool CloudServer::Shutdown() {
  int sock;
  {
    lock_guard<mutex> l(server_sock_mutex_);
    sock = *server_sock_;
    *server_sock_ = -1;
  }
  if (sock < 0) {
    LOG(ERROR) << "Socket was not open";
    return false;
  }
  LOG(INFO) << "Shutting down server socket";
  shutdown(sock, SHUT_RD);
  return true;
}

void CloudServer::HandleNewConnection(CloudChannel *unscoped_chan) {
  scoped_ptr<CloudChannel> chan(unscoped_chan);
  if (!chan->TLSServerHandshake()) {
    LOG(ERROR) << "TLS handshake failed";
    return;
  }
  if (!chan->TaoHandshake(tls_delegation_)) {
    LOG(ERROR) << "Tao handshake failed";
    return;
  }
  if (!guard_->IsAuthorized(chan->PeerName(), "Connect",
                           list<string>{chan->SelfName()})) {
    LOG(ERROR) << "Peer is not authorized to connect to this process";
    chan->Abort("authorization denied");
    return;
  }
  if (!HandleAuthenticatedConnection(chan.get())) {
    LOG(ERROR) << "Error handling requests on authenticated channel";
    if (!chan->IsClosed())
      chan->Abort("unknown error");
    return;
  }
  if (!chan->IsClosed())
    chan->Disconnect();
}

}  // namespace cloudproxy
