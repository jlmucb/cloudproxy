//  File: pipe_tao_channel_factory.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the Tao channel factory that creates a
//  pair of pipes.
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

#ifndef TAO_PIPE_TAO_CHANNEL_FACTORY_H_
#define TAO_PIPE_TAO_CHANNEL_FACTORY_H_

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <string>

using std::string;

namespace tao {
class TaoChannel;

class PipeTaoChannelFactory {
 public:
  PipeTaoChannelFactory();
  virtual ~PipeTaoChannelFactory() {}
  virtual TaoChannel *CreateTaoChannel() const;
  virtual string GetFactoryName() const { return "PipeTaoChannelFactory"; }
 private:
  DISALLOW_COPY_AND_ASSIGN(PipeTaoChannelFactory);
};
} // namespace tao

#endif // TAO_PIPE_TAO_CHANNEL_FACTORY_H_
