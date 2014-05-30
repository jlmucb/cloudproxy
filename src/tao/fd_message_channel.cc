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

/// Send data to a file descriptor.
/// @param fd The file descriptor to use to send the data.
/// @param buffer The buffer containing data to send.
/// @param buffer_len The length of buffer.
static bool SendData(int fd, const void *buffer, size_t buffer_len) {
  int bytes_written = write(fd, buffer, buffer_len);
  if (bytes_written < 0) {
    PLOG(ERROR) << "Could not send data";
    return false;
  }
  if (static_cast<size_t>(bytes_written) != buffer_len) {
    LOG(ERROR) << "Could not send complete data";
    return false;
  }
  return true;
}

/// Send a string to a file descriptor.
/// @param fd The file descriptor to use to send the string.
/// @param s The string to send.
static bool SendString(int fd, const string &s) {
  uint32_t net_len = htonl(s.size());
  return SendData(fd, &net_len, sizeof(net_len)) &&
         SendData(fd, s.c_str(), s.size());
}

bool FDMessageChannel::SendMessage(const google::protobuf::Message &m) const {
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }
  return SendString(writefd_, serialized);
}

/// Receive partial data from a file descriptor. This reads into buffer[i],
/// where filled_len <= i < buffer_len, and it returns the number of bytes read,
/// or 0 if end of stream, or negative on error.
/// @param fd The file descriptor to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param filed_len The length of buffer that is already filled.
/// @param buffer_len The total length of buffer.
static int ReceivePartialData(int fd, void *buffer, size_t filled_len,
                              size_t buffer_len) {
  if (fd < 0 || buffer == nullptr || filled_len >= buffer_len) {
    LOG(ERROR) << "Invalid ReceivePartialData parameters";
    return -1;
  }
  int in_len = read(fd, reinterpret_cast<unsigned char *>(buffer) + filled_len,
                    buffer_len - filled_len);
  if (in_len < 0) PLOG(ERROR) << "Failed to read data from file descriptor";
  return in_len;
}

/// Receive data from a file descriptor.
/// @param fd The file descriptor to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param buffer_len The length of buffer.
/// @param[out] eof Will be set to true iff end of stream reached.
static bool ReceiveData(int fd, void *buffer, size_t buffer_len, bool *eof) {
  *eof = false;
  size_t filled_len = 0;
  while (filled_len != buffer_len) {
    int in_len = ReceivePartialData(fd, buffer, filled_len, buffer_len);
    if (in_len == 0) {
      *eof = true;
      return (filled_len == 0);  // fail only on truncated message
    }
    if (in_len < 0) return false;  // fail on errors
    filled_len += in_len;
  }
  return true;
}

/// Receive a string from a file descriptor.
/// @param fd The file descriptor to use to receive the data.
/// @param max_size The maximum allowable size string to receive.
/// @param[out] s The string to receive the data.
/// @param[out] eof Will be set to true iff end of stream reached.
static bool ReceiveString(int fd, size_t max_size, string *s, bool *eof) {
  uint32_t net_len;
  if (!ReceiveData(fd, &net_len, sizeof(net_len), eof)) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  } else if (*eof) {
    return true;
  }
  uint32_t len = ntohl(net_len);
  if (len > max_size) {
    LOG(ERROR) << "Message exceeded maximum allowable size";
    return false;
  }
  scoped_array<char> temp_data(new char[len]);
  if (!ReceiveData(fd, temp_data.get(), static_cast<size_t>(len), eof) ||
      *eof) {
    LOG(ERROR) << "Could not get the data";
    return false;
  }
  s->assign(temp_data.get(), len);
  return true;
}

bool FDMessageChannel::ReceiveMessage(google::protobuf::Message *m,
                                      bool *eof) const {
  string s;
  if (!ReceiveString(readfd_, MaxMessageSize, &s, eof)) {
    LOG(ERROR) << "Could not receive message";
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
