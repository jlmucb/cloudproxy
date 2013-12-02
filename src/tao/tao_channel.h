//  File: tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A class for communication between hosted programs and
//  the Tao. It implements the high-level details of communication (like
//  protobuf serialization) and depends on subclasses for the details of
//  byte transport
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

#include <keyczar/base/basictypes.h> // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"

using std::string;

namespace tao {

// an RPC class that communicates with a remote Tao server. It takes the input
// parameters, bundles them up, and sends them along a channel (details of the
// channel depend on the implementation). The difference between the Tao and the
// TaoChannel is that the Tao takes information about the child hash making the
// request, whereas the TaoChannel is the interface the child uses to
// communicate with the Tao, and the child program is not allowed to choose an
// arbitrary hash to use. So, this hash is added by the channel infrastructure.
class TaoChannel {
 public:
  TaoChannel() {}
  virtual ~TaoChannel() {}

  // Start listening for messages from this child.
  virtual bool Listen(Tao *tao) = 0;

  // Add a child to this channel and return the string that will let the child
  // connect using the same type.
  virtual bool AddChildChannel(const string &child_hash, string *params) = 0;
  virtual bool ChildCleanup(const string &child_hash) = 0;
  virtual bool ParentCleanup(const string &child_hash) = 0;

 protected:
  // subclasses implement these methods for the underlying transport.
  virtual bool ReceiveMessage(google::protobuf::Message *m,
                              const string &child_hash) const = 0;
  virtual bool SendMessage(const google::protobuf::Message &m,
                           const string &child_hash) const = 0;

  // handle incoming messages on the channel
  virtual bool HandleRPC(Tao &tao, const string &hash,
                         const TaoChannelRPC &rpc) const;
  virtual bool GetRPC(TaoChannelRPC *rpc, const string &child_hash) const;
  virtual bool SendResponse(const TaoChannelResponse &resp,
                            const string &child_hash) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaoChannel);
};
}  // namespace tao

#endif  // TAO_TAO_CHANNEL_H_
