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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "tao/kvm_unix_tao_channel_params.pb.h"
#include "tao/tao_child_channel_params.pb.h"

namespace tao {
KvmUnixTaoChildChannel::KvmUnixTaoChildChannel(const string &params)
    : fd_(0), params_(params) {}

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

  // This channel always uses /dev/ttyS0 for now.
  fd_ = open("/dev/ttyS0", O_RDWR | O_EXCL);
  if (fd_ == -1) {
    PLOG(ERROR) << "Could not open /dev/ttyS0 in exclusive mode for read-write";
    return false;
  }

  return true;
}

bool KvmUnixTaoChildChannel::ReceiveMessage(google::protobuf::Message *m) const {
  // try to receive an integer
  CHECK(m) << "m was null";

  size_t len;
  ssize_t bytes_read = read(fd_, &len, sizeof(size_t));
  if (bytes_read != sizeof(size_t)) {
    LOG(ERROR) << "Could not receive a size on the channel";
    return false;
  }

  // then read this many bytes as the message
  scoped_array<char> bytes(new char[len]);
  bytes_read = read(fd_, bytes.get(), len);

  // TODO(tmroeder): add safe integer library
  if (bytes_read != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not read the right number of bytes from the fd";
    return false;
  }

  string serialized(bytes.get(), len);
  return m->ParseFromString(serialized);
}

bool KvmUnixTaoChildChannel::SendMessage(
    const google::protobuf::Message &m) const {
  // send the length then the serialized message
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }

  size_t len = serialized.size();
  ssize_t bytes_written = write(fd_, &len, sizeof(size_t));
  if (bytes_written != sizeof(size_t)) {
    LOG(ERROR) << "Could not write the length to the fd " << fd_;
    return false;
  }

  bytes_written = write(fd_, serialized.data(), len);
  if (bytes_written != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not wire the serialized message to the fd";
    return false;
  }

  return true;
}
}  // namespace tao
