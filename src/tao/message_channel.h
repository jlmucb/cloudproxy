//  File: rpc_channel.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: An interface for a Message channel.
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
#ifndef TAO_MESSAGE_CHANNEL_H_
#define TAO_MESSAGE_CHANNEL_H_

#include <list>
#include <string>

#include "tao/util.h"

namespace tao {
using std::string;

/// An interface for a channel that can send and receive Message objects.
class MessageChannel {
 public:
  MessageChannel() : maxMessageSize_(DefaultMaxMessageSize) {}
  virtual ~MessageChannel() {}  // sub-classes should Close() here.

  /// Close a channel. It is safe to call this multiple times.
  virtual void Close() = 0;

  /// Check if a channel is closed.
  virtual bool IsClosed() const = 0;

  /// Get the maximum message reception size.
  size_t MaxMessageSize() const { return maxMessageSize_; }

  /// Set the maximum message reception size.
  void SetMaxMessageSize(size_t size) { maxMessageSize_ = size; }

  /// Low-level functions for raw data.
  /// @{

  /// Send raw data to the channel.
  /// Failure will close the channel.
  /// @param buffer The buffer containing data to send.
  /// @param buffer_len The length of buffer.
  virtual bool SendData(const void *buffer, size_t buffer_len) = 0;

  /// Receive raw data from the channel.
  /// No maximum message size applies, the caller is expected to supply a
  /// reasonable buffer_len, which will be filled entirely.
  /// Failure or eof will close the channel.
  /// @param[out] buffer The buffer to fill with data.
  /// @param buffer_len The number of bytes to be filled.
  /// @param[out] eof Will be set to true iff end of stream reached.
  virtual bool ReceiveData(void *buffer, size_t buffer_len, bool *eof);

  /// @}

  /// Mid-level functions for strings.
  /// @{

  /// Send a raw string to the channel.
  /// Failure will close the channel.
  /// @param s The string to send.
  virtual bool SendString(const string &s);

  /// Receive a string from a file descriptor.
  /// Failure or eof will close the channel.
  /// @param max_size The maximum allowable size string to receive.
  /// @param[out] s The string to receive the data.
  /// @param[out] eof Will be set to true iff end of stream reached.
  virtual bool ReceiveString(string *s, bool *eof);

  /// @}

  /// High-level functions for Messages.
  /// @{

  /// Send a Message over the channel.
  /// Failure will close the channel.
  /// @param m The Message to send.
  virtual bool SendMessage(const google::protobuf::Message &m);

  /// Receive a Message over the channel.
  /// Failure or eof will close the channel.
  /// @param[out] m The received Message.
  /// @param[out] eof Will be set to true iff end of stream reached.
  virtual bool ReceiveMessage(google::protobuf::Message *m, bool *eof);

  /// @}

  /// Serialize channel parameters for passing across fork/exec or between
  /// processes, if possible. This does not close the channel. Not all channel
  /// types must necessarily be serializable.
  /// @param params[out] The serialized parameters.
  virtual bool SerializeToString(string *params) const { return false; }

  /// Maximum 20 MB for message reception on this channel by default.
  static constexpr size_t DefaultMaxMessageSize = 20 * 1024 * 1024;

 protected:
  /// The max Message (or string) reception size.
  size_t maxMessageSize_;

  /// Receive raw data from the channel.
  /// No maximum message size applies, the caller is expected to supply a
  /// reasonable buffer_len. Partial messages are accepted.
  /// Failure or eof will close the channel.
  /// @param[out] buffer The buffer to fill with data.
  /// @param max_recv_len The maximum number of bytes to be filled.
  /// @param[out] eof Will be set to true iff end of stream reached.
  virtual bool ReceivePartialData(void *buffer, size_t max_recv_len,
                                  size_t *recv_len, bool *eof) = 0;
};
}  // namespace tao

#endif  // TAO_MESSAGE_CHANNEL_H_
