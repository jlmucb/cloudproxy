//  File: fd_message_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A MessageChannel that communicates over Unix file descriptors.
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
#include "tao/fd_message_channel.h"

#include <unistd.h>

#include <list>
#include <string>

#include <glog/logging.h>

#include "tao/util.h"

namespace tao {

/// 20 MB is the maximum allowed message on our channel implementations.
constexpr size_t FDMessageChannel::MaxMessageSize;

bool FDMessageChannel::Close() {
  if (readfd_ != -1) {
    close(readfd_);
  }
  if (writefd_ != -1 && writefd_ != readfd_) {
    close(writefd_);
  }
  readfd_ = writefd_ = -1;
  return true;
}

bool FDMessageChannel::SendMessage(const google::protobuf::Message &m) const {
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }
  return SendString(writefd_, serialized);
}

bool FDMessageChannel::ReceiveMessage(google::protobuf::Message *m,
                                      bool *eof) const {
  string s;
  if (!ReceiveString(readfd_, MaxMessageSize, &s, eof)) {
    LOG(ERROR) << "Could not recieve message";
    return false;
  } else if (*eof) {
    return true;
  }
  if (!m->ParseFromString(s)) {
    LOG(ERROR) << "Could not parse message";
    return false;
  }
  return true;
}

bool FDMessageChannel::GetFileDescriptors(list<int> *keep_open) const {
  if (readfd_ != -1) {
    keep_open->push_back(readfd_);
  }
  if (writefd_ != -1 && writefd_ != readfd_) {
    keep_open->push_back(writefd_);
  }
  return true;
}

bool FDMessageChannel::SerializeToString(string *params) const {
  stringstream out;
  out << "tao::FDMessageChannel(" << readfd_ << ", " << writefd_ << ")";
  params->assign(out.str());
  return true;
}

FDMessageChannel *FDMessageChannel::DeserializeFromString(
    const string &params) {
  stringstream in(params);
  skip(in, "tao::FDMessageChannel(");
  if (!in) return nullptr;  // not for us
  int rfd, wfd;
  in >> rfd;
  skip(in, ", ");
  in >> wfd;
  skip(in, ")");
  if (!in || (in.get() && !in.eof())) {
    LOG(ERROR) << "Could not deserialize FDMessageChannel";
    return nullptr;
  }
  return new FDMessageChannel(rfd, wfd);
}

}  // namespace tao
