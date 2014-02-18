//  File: kvm_unix_tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of the child side of KvmUnixTaoChannel
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

#include "tao/kvm_unix_tao_child_channel.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "tao/kvm_unix_tao_channel_params.pb.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

namespace tao {
KvmUnixTaoChildChannel::KvmUnixTaoChildChannel(const string &params)
    : UnixFdTaoChildChannel(), params_(params) {}

bool KvmUnixTaoChildChannel::Init() {
  // Parse the params into the file descriptors for reading and writing.
  TaoChildChannelParams tccp;
  if (!tccp.ParseFromString(params_)) {
    LOG(ERROR) << "Could not parse the child params";
    return false;
  }

  KvmUnixTaoChannelParams kutcp;
  if (!kutcp.ParseFromString(tccp.params())) {
    LOG(ERROR) << "Could not parse the channel information from the params";
    return false;
  }

  string file = string("/dev/virtio-ports/") + kutcp.guest_device();
  readfd_ = open(file.c_str(), O_RDWR | O_APPEND);
  if (readfd_ == -1) {
    PLOG(ERROR) << "Could not open " << file << " for read-write";
    return false;
  }

  writefd_ = readfd_;
  return true;
}
}  // namespace tao
