//  File: message_channel.cc
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
#include "tao/message_channel.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <list>
#include <string>

#include <glog/logging.h>
#include <google/protobuf/message.h>

#include "tao/util.h"

namespace tao {
constexpr size_t MessageChannel::DefaultMaxMessageSize;

bool MessageChannel::SendString(const string &s) {
  uint32_t net_len = htonl(s.size());
  return SendData(&net_len, sizeof(net_len)) && SendData(s.c_str(), s.size());
}

bool MessageChannel::SendMessage(const google::protobuf::Message &m) {
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    Close();  // Not really necessary, but simplifies semantics.
    return false;
  }
  return SendString(serialized);
}

bool MessageChannel::ReceiveData(void *buffer, size_t buffer_len, bool *eof) {
  if (IsClosed()) {
    LOG(ERROR) << "Can't receive data, channel is already closed";
    *eof = true;
    return true;
  } else {
    *eof = false;
  }
  size_t filled_len = 0;
  while (filled_len != buffer_len) {
    size_t recv_len;
    if (!ReceivePartialData(
            reinterpret_cast<unsigned char *>(buffer) + filled_len,
            buffer_len - filled_len, &recv_len, eof)) {
      LOG(ERROR) << "Failed to read data";
      return false;
    } else if (*eof && filled_len != 0) {
      LOG(ERROR) << "Failed to read complete data";
      return false;
    } else if (*eof) {
      return true;
    }
    filled_len += recv_len;
  }
  return true;
}

bool MessageChannel::ReceiveString(string *s, bool *eof) {
  uint32_t net_len;
  if (!ReceiveData(&net_len, sizeof(net_len), eof)) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  } else if (*eof) {
    return true;
  }
  uint32_t len = ntohl(net_len);
  if (len > MaxMessageSize()) {
    LOG(ERROR) << "Message exceeded maximum allowable size";
    Close();
    return false;
  }
  unique_ptr<char[]> temp_data(new char[len]);
  if (!ReceiveData(temp_data.get(), static_cast<size_t>(len), eof) || *eof) {
    LOG(ERROR) << "Could not get the data";
    return false;
  }
  s->assign(temp_data.get(), len);
  return true;
}

bool MessageChannel::ReceiveMessage(google::protobuf::Message *m, bool *eof) {
  string s;
  if (!ReceiveString(&s, eof)) {
    LOG(ERROR) << "Could not receive message";
    return false;
  } else if (*eof) {
    return true;
  }
  if (!m->ParseFromString(s)) {
    LOG(ERROR) << "Could not parse message";
    Close();
    return false;
  }
  return true;
}

}  // namespace tao
