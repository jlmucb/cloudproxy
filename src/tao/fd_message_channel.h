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
/// A MessageChannel that communicates with a remote endpoint using a pair of
/// file descriptors. One file descriptor is used for sending messages, the
/// other for receiving messages. The descriptors can be the same. On Close() or
/// object destruction the file descriptors will be closed.
class FDMessageChannel : public MessageChannel {
 public:
  /// Construct FDMessageChannel.
  /// @param readfd The file descriptor to use for receiving messages.
  /// @param writefd The file descriptor to use for sending messages.
  FDMessageChannel(int readfd, int writefd)
      : readfd_(readfd), writefd_(writefd) {}

  virtual ~FDMessageChannel() { FDClose(); }

  /// These methods have the same semantics as MessageChannel.
  /// @{
  virtual void Close() { FDClose(); }
  virtual bool IsClosed() const { return (readfd_ < 0 || writefd_ < 0); }
  virtual bool SendData(const void *buffer, size_t buffer_len);
  virtual bool SerializeToString(string *params) const;
  /// @}

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

 protected:
  /// File descriptor for writing to host Tao.
  int readfd_;

  /// File descriptor for reading from host Tao.
  int writefd_;

  /// These methods have the same semantics as MessageChannel.
  /// @{
  virtual bool ReceivePartialData(void *buffer, size_t max_recv_len,
                                  size_t *recv_len, bool *eof);
  /// @}

  /// A non-virtual version of Close for use in destructor.
  void FDClose();

 private:
  DISALLOW_COPY_AND_ASSIGN(FDMessageChannel);
};

}  // namespace tao

#endif  // TAO_FD_MESSAGE_CHANNEL_H_
