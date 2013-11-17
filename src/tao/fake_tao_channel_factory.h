//  File: fake_tao_channel_factory.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the Tao channel factory that creates a
//  FakeTaoChannel.
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

#ifndef TAO_FAKE_TAO_CHANNEL_FACTORY_H_
#define TAO_FAKE_TAO_CHANNEL_FACTORY_H_

#include "tao/fake_tao_channel.h"
#include "tao/tao_channel_factory.h"

#include <string>

using std::string;

namespace tao {
class FakeTaoChannelFactory : public TaoChannelFactory {
 public:
  FakeTaoChannelFactory() {}
  virtual ~FakeTaoChannelFactory() {}
  virtual TaoChannel *CreateTaoChannel() const { return new FakeTaoChannel(); }
  virtual string GetFactoryName() const { return "FakeTaoChannelFactory"; }

 private:
  DISALLOW_COPY_AND_ASSIGN(FakeTaoChannelFactory);
};
}  // namespace tao

#endif  // TAO_FAKE_TAO_CHANNEL_FACTORY_H_
