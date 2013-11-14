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

#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"

namespace tao {
// an RPC class that communicates with a remote Tao server. It takes the input
// parameters, bundles them up, and sends them along a channel (details of the
// channel depend on the implementation)
class TaoChannel : public Tao {
 public:
  virtual ~TaoChannel() {}

  // listen on the channel and handle incoming messages by passing them to the
  // Tao
  bool Listen(Tao *t) const;

  // Gets a serialized representation of the parameters the child needs to
  // communicate with the parent.
  virtual bool GetChildParams(string *params) const = 0;
  virtual bool ChildCleanup() = 0;
  virtual bool ParentCleanup() = 0;

  // Tao interface methods
  virtual bool Init() { return true; }
  virtual bool Destroy() { return true; }
  virtual bool StartHostedProgram(const string &path, const list<string> &args);
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &data, string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data) const;
  virtual bool Attest(const string &data, string *attestation) const;
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 protected:
  // subclasses implement these methods for the underlying transport.
  virtual bool ReceiveMessage(google::protobuf::Message *m) const = 0;
  virtual bool SendMessage(const google::protobuf::Message &m) const = 0;

 private:
  virtual bool GetRPC(TaoChannelRPC *rpc) const;
  virtual bool SendRPC(const TaoChannelRPC &rpc) const;
  virtual bool GetResponse(TaoChannelResponse *resp) const;
  virtual bool SendResponse(const TaoChannelResponse &resp) const;
  bool SendAndReceiveData(const string &in, string *out, RPC rpc_type) const;
};
}  // namespace tao

#endif  // TAO_TAO_CHANNEL_H_
