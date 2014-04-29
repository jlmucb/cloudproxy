//  File: unix_domain_socket_tao_admin_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of the client side of
//    UnixDomainSocketTaoAdminChannel.
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

#include "tao/unix_domain_socket_tao_admin_channel.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <string>

#include <glog/logging.h>

#include "tao/util.h"

namespace tao {
UnixDomainSocketTaoAdminChannel::UnixDomainSocketTaoAdminChannel(
    const string &tao_socket_path)
    : tao_socket_path_(tao_socket_path), sock_(new int(-1)) {}

bool UnixDomainSocketTaoAdminChannel::Init() {
  if (!ConnectToUnixDomainSocket(tao_socket_path_, sock_.get())) {
    LOG(ERROR) << "Could not open unnamed client socket";
    return false;
  }
  return true;
}

bool UnixDomainSocketTaoAdminChannel::Destroy() {
  sock_.reset(new int(-1));
  return true;
}

bool UnixDomainSocketTaoAdminChannel::ReceiveMessage(
    google::protobuf::Message *m) const {
  // try to receive an integer
  CHECK(m) << "m was null";
  if (*sock_ < 0) {
    LOG(ERROR) << "Can't send with an empty socket";
    return false;
  }
  return tao::ReceiveMessage(*sock_, m);
}

bool UnixDomainSocketTaoAdminChannel::SendMessage(
    const google::protobuf::Message &m) const {
  if (*sock_ < 0) {
    LOG(ERROR) << "Can't send with an empty fd";
    return false;
  }
  return tao::SendMessage(*sock_, m);
}
}  // namespace tao
