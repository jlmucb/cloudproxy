//  File: pipe_tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of the child side of PipeTaoChannel
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

#include <tao/pipe_tao_child_channel.h>
#include <tao/pipe_tao_channel_params.pb.h>
#include <tao/tao_child_channel_params.pb.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>

namespace tao {
PipeTaoChildChannel::PipeTaoChildChannel(const string &params)
    : readfd_(0), writefd_(0), params_(params) {}

bool PipeTaoChildChannel::Init() {

  // Parse the params into the file descriptors for reading and writing.
  TaoChildChannelParams tccp;
  if (!tccp.ParseFromString(params_)) {
    LOG(ERROR) << "Could not parse the child params";
    return false;
  }

  PipeTaoChannelParams ptcp;
  if (!ptcp.ParseFromString(tccp.params())) {
    LOG(ERROR) << "Could not parse the pipe file descriptors from the params";
    return false;
  }

  readfd_ = ptcp.readfd();
  writefd_ = ptcp.writefd();

  LOG(INFO) << "Got readfd = " << readfd_;
  LOG(INFO) << "Got writefd = " << writefd_;

  return true;
}

bool PipeTaoChildChannel::ReceiveMessage(google::protobuf::Message *m) const {
  // try to receive an integer
  CHECK(m) << "m was null";

  size_t len;
  ssize_t bytes_read = read(readfd_, &len, sizeof(size_t));
  if (bytes_read != sizeof(size_t)) {
    LOG(ERROR) << "Could not receive a size on the channel";
    return false;
  }

  // then read this many bytes as the message
  scoped_array<char> bytes(new char[len]);
  bytes_read = read(readfd_, bytes.get(), len);

  // TODO(tmroeder): add safe integer library
  if (bytes_read != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not read the right number of bytes from the fd";
    return false;
  }

  string serialized(bytes.get(), len);
  return m->ParseFromString(serialized);
}

bool PipeTaoChildChannel::SendMessage(
    const google::protobuf::Message &m) const {
  // send the length then the serialized message
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }

  size_t len = serialized.size();
  ssize_t bytes_written = write(writefd_, &len, sizeof(size_t));
  if (bytes_written != sizeof(size_t)) {
    LOG(ERROR) << "Could not write the length to the fd " << writefd_;
    return false;
  }

  bytes_written = write(writefd_, serialized.data(), len);
  if (bytes_written != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not wire the serialized message to the fd";
    return false;
  }

  return true;
}
}  // namespace tao
