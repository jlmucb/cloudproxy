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

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include "tao/tao_channel_rpc.pb.h"

#include <list>
#include <string>

using std::list;
using std::string;

namespace tao {
class TaoChildChannel {
 public:
  TaoChildChannel() {}
  virtual ~TaoChildChannel() {}

  // Tao interface methods without the child hash parameter
  virtual bool Init() { return true; }
  virtual bool Destroy() { return true; }
  virtual bool StartHostedProgram(const string &path, const list<string> &args);
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &data, string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data) const;
  virtual bool Attest(const string &data, string *attestation) const;

 protected:
  // subclasses implement these methods for the underlying transport.
  virtual bool ReceiveMessage(google::protobuf::Message *m) const = 0;
  virtual bool SendMessage(const google::protobuf::Message &m) const = 0;

 private:
  virtual bool SendRPC(const TaoChannelRPC &rpc) const;
  virtual bool GetResponse(TaoChannelResponse *resp) const;
  bool SendAndReceiveData(const string &in, string *out, RPC rpc_type) const;

  DISALLOW_COPY_AND_ASSIGN(TaoChildChannel);
};
}  // namespace tao

#endif  // TAO_TAO_CHILD_CHANNEL_H_
