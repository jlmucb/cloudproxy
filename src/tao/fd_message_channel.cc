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

#include <arpa/inet.h>
#include <unistd.h>

#include <list>
#include <string>

#include <glog/logging.h>

#include "tao/util.h"

namespace tao {

void FDMessageChannel::FDClose() {
  if (readfd_ != -1) {
    close(readfd_);
  }
  if (writefd_ != -1 && writefd_ != readfd_) {
    close(writefd_);
  }
  readfd_ = writefd_ = -1;
}

bool FDMessageChannel::SendData(const void *buffer, size_t buffer_len) {
  if (IsClosed()) {
    LOG(ERROR) << "Could not send data, channel already closed";
    return false;
  }
  int bytes_written = write(writefd_, buffer, buffer_len);
  if (bytes_written < 0) {
    PLOG(ERROR) << "Could not send data";
    Close();
    return false;
  }
  if (static_cast<size_t>(bytes_written) != buffer_len) {
    LOG(ERROR) << "Could not send complete data";
    Close();
    return false;
  }
  return true;
}

bool FDMessageChannel::ReceivePartialData(void *buffer, size_t max_recv_len,
                                          size_t *recv_len, bool *eof) {
  if (IsClosed()) {
    LOG(ERROR) << "Can't receive data, channel is already closed";
    *eof = true;
    return true;
  } else {
    *eof = false;
  }
  int in_len =
      read(readfd_, reinterpret_cast<unsigned char *>(buffer), max_recv_len);
  if (in_len == 0) {
    *eof = true;
    Close();
    return true;
  } else if (in_len < 0) {
    PLOG(ERROR) << "Failed to read data from file descriptor";
    Close();
    return false;
  }
  *recv_len = in_len;
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
