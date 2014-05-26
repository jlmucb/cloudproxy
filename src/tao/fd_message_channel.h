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

  virtual bool SendMessage(const google::protobuf::Message &m) const;

  virtual bool ReceiveMessage(google::protobuf::Message *m, bool *eof) const;

  virtual bool SerializeToString(string *params) const;

  static FDMessageChannel *DeserializeFromString(const string &params);

  virtual bool GetFileDescriptors(list<int> *keep_open) const;

  virtual int GetReadFileDescriptor() { return readfd_; }

  virtual bool Close();

  static constexpr size_t MaxMessageSize = 20 * 1024 * 1024;

 protected:
  /// File descriptor for writing to host Tao.
  int readfd_;

  /// File descriptor for reading from host Tao.
  int writefd_;

 private:
  DISALLOW_COPY_AND_ASSIGN(FDMessageChannel);
};
}  // namespace tao

#endif  // TAO_FD_MESSAGE_CHANNEL_H_
