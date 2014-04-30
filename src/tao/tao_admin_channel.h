//  File: tao_admin_channel.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
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

#ifndef TAO_TAO_ADMIN_CHANNEL_H_
#define TAO_TAO_ADMIN_CHANNEL_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_admin_channel.pb.h"

using std::list;
using std::string;

namespace tao {
/// An interface that administrative programs use to communicate with a Tao.
/// Messages are sent along a channel to the Tao's TaoChannel RPC server.
class TaoAdminChannel {
 public:
  TaoAdminChannel() {}
  virtual ~TaoAdminChannel() {}

  /// Initialize by opening ports and acquiring resources as needed.
  virtual bool Init() { return true; }

  /// Disconnect ports and release resources acquired during Init().
  virtual bool Destroy() { return true; }

  /// Methods that invoke the administrative interfaces of the Tao.
  /// @{

  /// Request that the host Tao be shut down.
  virtual bool Shutdown() const;

  /// Request that the host Tao start a new program. See Tao for semantics.
  virtual bool StartHostedProgram(const string &path, const list<string> &args,
                                  string *identifier) const;

  /// Request that the host Tao remove a program. See Tao for semantics.
  virtual bool RemoveHostedProgram(const string &child_hash) const;

  /// @}

 protected:
  /// Receive a protobuf on the channel from a Tao. Subclasses implement this
  /// method for their particular channel type.
  /// @param[out] m The received message.
  virtual bool ReceiveMessage(google::protobuf::Message *m) const = 0;

  /// Send a protobuf on a channel to a Tao. Subclasses implement
  /// this method for their particular channel type.
  /// @param m The message to send.
  virtual bool SendMessage(const google::protobuf::Message &m) const = 0;

 private:
  /// Send an RPC to the Tao.
  /// @param rpc The RPC containing the message.
  virtual bool SendRPC(const TaoAdminRequest &rpc) const;

  /// Receive an RPC response from the Tao.
  /// @param[out] The response to an RPC.
  virtual bool GetResponse(TaoAdminResponse *resp) const;

  DISALLOW_COPY_AND_ASSIGN(TaoAdminChannel);
};
}  // namespace tao

#endif  // TAO_TAO_ADMIN_CHANNEL_H_
