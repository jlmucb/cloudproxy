//  File: tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A class for communication between hosted programs and the Tao
//  and between administrative programs and the Tao. It implements the
//  high-level details of communication (like protobuf serialization) and
//  depends on subclasses for the details of byte transport
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

#ifndef TAO_TAO_CHANNEL_H_
#define TAO_TAO_CHANNEL_H_

#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"

using std::string;

namespace tao {

/// An RPC server class that handles communication with a set of remote
/// TaoChildChannel and TaoAdminChannel clients.
class TaoChannel {
 public:
  TaoChannel() {}
  virtual ~TaoChannel() {}

  /// Initialize the server, opening ports and allocating resources as needed.
  virtual bool Init() = 0;

  /// Listen for and process messages from child and admin channels until a
  /// shutdown is initiated.
  /// @param tao The Tao implementation that will handle received messages.
  virtual bool Listen(Tao *tao) = 0;

  /// Close ports and release any resources used by the server.
  virtual bool Destroy() = 0;

  /// Add a child to this channel and return the string that will let the child
  /// connect using the same type.
  /// @param child_hash The hash of the child to add.
  /// @param[out] params The Base64W-encoded TaoChildChannelParams that the
  /// child will use to connect to this TaoChannel.
  virtual bool AddChildChannel(const string &child_hash, string *params) = 0;

  /// Clean up host state for hosted program creation.
  /// @param child_hash The hash of the hosted program being created.
  virtual bool ChildCleanup(const string &child_hash) = 0;

  /// Clean up hosted program state during hosted program creation.
  /// @param child_hash The hash of the hosted program being created.
  virtual bool ParentCleanup(const string &child_hash) = 0;

  /// Provide new params for a hosted program.
  /// @param child_hash The hosted program associated with the new parameters.
  /// @param params The new parameters to use.
  virtual bool UpdateChildParams(const string &child_hash,
                                 const string &params) = 0;

 protected:
  /// Receive a protobuf on the channel. Subclasses implement this method for
  /// their particular channel type.
  /// @param[out] m The received message.
  /// @param child_hash The hosted program to receive a message from.
  virtual bool ReceiveMessage(google::protobuf::Message *m,
                              const string &child_hash) const = 0;

  /// Send a protobuf on a channel to a hosted program. Subclasses implement
  /// this method for their particular channel type.
  /// @param m The message to send.
  /// @param child_hash The hash of the hosted program to receive the message.
  virtual bool SendMessage(const google::protobuf::Message &m,
                           const string &child_hash) const = 0;

  /// Handle incoming messages on the channel.
  /// @param tao The Tao implementation that handles the message.
  /// @param hash The hash of the hosted program that sent the message.
  /// @param rpc The RPC containing the received message.
  virtual bool HandleRPC(Tao &tao, const string &hash,  // NOLINT
                         const TaoChannelRPC &rpc) const;

  /// Receive an RPC for a given hosted program.
  /// @param[out] rpc The received message.
  /// @param child_hash The hosted program to receive the message from.
  virtual bool GetRPC(TaoChannelRPC *rpc, const string &child_hash) const;

  /// Send a response to a hosted program.
  /// @param resp The response to send.
  /// @param child_hash The child to send the response to.
  virtual bool SendResponse(const TaoChannelResponse &resp,
                            const string &child_hash) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaoChannel);
};
}  // namespace tao

#endif  // TAO_TAO_CHANNEL_H_
