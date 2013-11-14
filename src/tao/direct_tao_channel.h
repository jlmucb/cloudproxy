//  File: direct_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A TaoChannel that calls directly to another Tao object
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

#ifndef TAO_DIRECT_TAO_CHANNEL_H_
#define TAO_DIRECT_TAO_CHANNEL_H_

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <tao/tao_channel.h>

namespace tao {
// a TaoChannel that interacts directly with an underlying Tao object
class DirectTaoChannel : public TaoChannel {
 public:
  // The parent constructor with its descriptors and the child descriptors.
  DirectTaoChannel(Tao *tao);
  virtual ~DirectTaoChannel() {}

  // Serializes the child_fds into a PipeTaoChannelParams protobuf.
  virtual bool GetChildParams(string *params) const { return false; }
  virtual bool ChildCleanup() { return true; }
  virtual bool ParentCleanup() { return true; }

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
  virtual bool ReceiveMessage(google::protobuf::Message *m) const { return false; }
  virtual bool SendMessage(const google::protobuf::Message &m) const { return false; }

 private:
  scoped_ptr<Tao> tao_;
  DISALLOW_COPY_AND_ASSIGN(DirectTaoChannel);
};
}

#endif  // TAO_DIRECT_TAO_CHANNEL_H_
