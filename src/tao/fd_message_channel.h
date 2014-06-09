//  File: fd_message_channel.h
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
#ifndef TAO_FD_MESSAGE_CHANNEL_H_
#define TAO_FD_MESSAGE_CHANNEL_H_

#include <list>
#include <string>

#include "tao/message_channel.h"

#include "tao/util.h"

namespace tao {
//  A MessageChannel that communicates with a remote endpoint using a pair of
//  file descriptors. One file descriptor is used for sending messages, the
//  other for receiving messages. The descriptors can be the same. On Destroy(),
//  the file descriptors will be closed.
class FDMessageChannel : public MessageChannel {
 public:
  /// Construct FDMessageChannel.
  /// @param readfd The file descriptor to use for receiving messages.
  /// @param writefd The file descriptor to use for sending messages.
  FDMessageChannel(int readfd, int writefd)
      : readfd_(readfd), writefd_(writefd) {}

  virtual ~FDMessageChannel() { Close(); }

  /// These methods have the same semantics as MessageChannel.
  /// @{
  virtual bool SendMessage(const google::protobuf::Message &m) const;
  virtual bool ReceiveMessage(google::protobuf::Message *m, bool *eof) const;
  virtual bool SerializeToString(string *params) const;
  /// @}

  /// Receive raw data from the channel.
  /// @param[out] buffer The buffer to fill with data.
  /// @param buffer_len The length of buffer.
  /// @param[out] eof Will be set to true iff end of stream reached.
  virtual bool ReceiveData(void *buffer, size_t buffer_len, bool *eof) const;

  /// Receive a string from a file descriptor.
  /// @param max_size The maximum allowable size string to receive.
  /// @param[out] s The string to receive the data.
  /// @param[out] eof Will be set to true iff end of stream reached.
  virtual bool ReceiveString(size_t max_size, string *s, bool *eof) const;

  /// Send raw data to the channel.
  /// @param buffer The buffer containing data to send.
  /// @param buffer_len The length of buffer.
  virtual bool SendData(const void *buffer, size_t buffer_len) const;

  /// Send a raw string to the channel.
  /// @param s The string to send.
  virtual bool SendString(const string &s) const;

  /// Attempt to deserialize a channel.
  /// @param params Channel parameters from SerializeToString().
  static FDMessageChannel *DeserializeFromString(const string &params);

  /// Get a list of file descriptors that should be kept open across fork/exec.
  /// @param[out] keep_open The list of file descriptors to preserve.
  virtual bool GetFileDescriptors(list<int> *keep_open) const;

  /// Get the read file descriptor, e.g. to use for select().
  virtual int GetReadFileDescriptor() { return readfd_; }

  /// Get the write file descriptor.
  virtual int GetWriteFileDescriptor() { return writefd_; }

  /// Close the underlying file descriptors.
  virtual bool Close();

  /// Maximum 20 MB for message reception on this channel.
  static constexpr size_t MaxMessageSize = 20 * 1024 * 1024;

 protected:
  /// File descriptor for writing to host Tao.
  int readfd_;

  /// File descriptor for reading from host Tao.
  int writefd_;

  /// Receive partial data from a file descriptor. This reads into buffer[i],
  /// where filled_len <= i < buffer_len, and it returns the number of bytes
  /// read,
  /// or 0 if end of stream, or negative on error.
  /// @param[out] buffer The buffer to fill with data.
  /// @param filed_len The length of buffer that is already filled.
  /// @param buffer_len The total length of buffer.
  virtual int ReceivePartialData(void *buffer, size_t filled_len,
                                 size_t buffer_len) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(FDMessageChannel);
};

}  // namespace tao

#endif  // TAO_FD_MESSAGE_CHANNEL_H_
