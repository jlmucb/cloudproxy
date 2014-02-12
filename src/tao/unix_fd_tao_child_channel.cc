//  File: unix_fd_tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of the child side of UnixFdTaoChildChannel.
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

#include "tao/unix_fd_tao_child_channel.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "tao/util.h"

namespace tao {
UnixFdTaoChildChannel::UnixFdTaoChildChannel() : readfd_(-1), writefd_(-1) {}

UnixFdTaoChildChannel::UnixFdTaoChildChannel(int readfd, int writefd)
    : readfd_(readfd), writefd_(writefd) {}

bool UnixFdTaoChildChannel::ReceiveMessage(google::protobuf::Message *m) const {
  // try to receive an integer
  CHECK(m) << "m was null";
  if (readfd_ < 0) {
    LOG(ERROR) << "Can't send with an empty fd";
    return false;
  }

  return tao::ReceiveMessage(readfd_, m);
}

bool UnixFdTaoChildChannel::SendMessage(
    const google::protobuf::Message &m) const {
  if (writefd_ < 0) {
    LOG(ERROR) << "Can't send with an empty fd";
    return false;
  }

  return tao::SendMessage(writefd_, m);
}
}  // namespace tao
