//  File: fake_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: FakeTaoChannel pretends to implement Tao communication
//  descriptors
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

#ifndef TAO_FAKE_TAO_CHANNEL_H_
#define TAO_FAKE_TAO_CHANNEL_H_

#include <tao/tao_channel.h>

namespace tao {
// a TaoChannel that doesn't actually do any communication
class FakeTaoChannel : public TaoChannel {
 public:
  FakeTaoChannel() {}
  virtual ~FakeTaoChannel() {}

  virtual bool Listen(Tao *t, const string &child_hash) { return true; }

  virtual bool AddChildChannel(const string &child_hash, string *params) {
    return true;
  }
  virtual bool ChildCleanup(const string &child_hash) { return true; }
  virtual bool ParentCleanup(const string &child_hash) { return true; }

 protected:
  virtual bool ReceiveMessage(google::protobuf::Message *m,
                              const string &child_hash) const {
    return false;
  }
  virtual bool SendMessage(const google::protobuf::Message &m,
                           const string &child_hash) const {
    return false;
  }

  DISALLOW_COPY_AND_ASSIGN(FakeTaoChannel);
};
}

#endif  // TAO_FAKE_TAO_CHANNEL_H_
