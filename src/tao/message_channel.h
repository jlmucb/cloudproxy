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
using std::list;
using std::string;

/// An interface for a channel that can send and recive Message objects.
class MessageChannel {
 public:
  virtual ~MessageChannel() {}

  virtual bool Close() = 0;

  /// Send a Message over the channel.
  /// @param m The Message to send.
  virtual bool SendMessage(const google::protobuf::Message &m) const = 0;

  /// Receive a a Message over the channel.
  /// @param[out] m The received Message.
  /// @param[out] eof Will be set to true iff end of stream reached.
  virtual bool ReceiveMessage(google::protobuf::Message *resp, bool *eof) const = 0;

  /// Serialize channel parameters for passing across fork/exec or between
  /// processes, if possible. This does not close the channel. Not all channel
  /// types must necessarily be serializable. 
  /// @param params[out] The serialized parameters.
  virtual bool SerializeToString(string *params) const { return false; }
};
}  // namespace tao

#endif  // TAO_MESSAGE_CHANNEL_H_
