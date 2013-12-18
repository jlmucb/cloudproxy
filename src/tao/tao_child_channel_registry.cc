//  File: tao_child_channel_registry.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the TaoChildChannelRegistry
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

#include "tao/tao_child_channel_registry.h"

#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"

#include <glog/logging.h>

namespace tao {
bool TaoChildChannelRegistry::Register(const string &name,
                                       CreateChannel channel_creator) {
  auto channel_it = channel_types_.find(name);
  if (channel_it != channel_types_.end()) {
    LOG(ERROR) << "The channel type " << name << " already exists";
    return false;
  }

  channel_types_[name] = channel_creator;
  return true;
}

TaoChildChannel *TaoChildChannelRegistry::Create(const string &params) {
  TaoChildChannelParams tccp;
  if (!tccp.ParseFromString(params)) {
    LOG(ERROR) << "Could not parse the params";
    return nullptr;
  }

  auto channel_it = channel_types_.find(tccp.channel_type());
  if (channel_it == channel_types_.end()) {
    LOG(ERROR) << "Could not find channel type " << tccp.channel_type();
    return nullptr;
  }

  return channel_it->second(params);
}
} // end namespace tao
