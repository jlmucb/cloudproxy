//  File: tao_child_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A class for communication from hosted program to the host
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

#ifndef TAO_TAO_CHILD_CHANNEL_H_
#define TAO_TAO_CHILD_CHANNEL_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel_rpc.pb.h"

using std::list;
using std::string;

namespace tao {
/// An interface that hosted programs use to communicate with a host Tao. It
/// implements the Tao but without the child_hash parameter, since the host
/// TaoChannel that will receive the message adds this parameter itself to the
/// call. See the Tao for the semantics of the Tao methods implemented by
/// TaoChildChannel.
class TaoChildChannel {
 public:
  TaoChildChannel() {}
  virtual ~TaoChildChannel() {}

  // Tao interface methods without the child hash parameter. See the Tao
  // interface for the semantics of these calls.
  virtual bool Init() { return true; }
  virtual bool Destroy() { return true; }
  virtual bool StartHostedProgram(const string &path, const list<string> &args,
                                  string *identifier);
  virtual bool RemoveHostedProgram(const string &child_hash);
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &data, string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data) const;
  virtual bool Attest(const string &data, string *attestation) const;

 protected:
  /// Receive a protobuf on the channel from a host. Subclasses implement this
  /// method for their particular channel type.
  /// @param[out] m The received message.
  virtual bool ReceiveMessage(google::protobuf::Message *m) const = 0;

  /// Send a protobuf on a channel to a host. Subclasses implement
  /// this method for their particular channel type.
  /// @param m The message to send.
  virtual bool SendMessage(const google::protobuf::Message &m) const = 0;

 private:
  /// Send an RPC to the host Tao.
  /// @param rpc The RPC containing the message.
  virtual bool SendRPC(const TaoChannelRPC &rpc) const;

  /// Receive an RPC response from the host Tao.
  /// @param[out] The response to an RPC.
  virtual bool GetResponse(TaoChannelResponse *resp) const;

  /// Sends a simple RPC containing a string and getting a string back. This is
  /// used for Seal, Unseal, and Attest.
  /// @param in The string to send.
  /// @param[out] out The string returned by the host Tao.
  /// @param rpc_type The type of RPC to send, like SEAL.
  bool SendAndReceiveData(const string &in, string *out, RPC rpc_type) const;

  DISALLOW_COPY_AND_ASSIGN(TaoChildChannel);
};
}  // namespace tao

#endif  // TAO_TAO_CHILD_CHANNEL_H_
