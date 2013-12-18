//  File: fake_tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the FakeTaoChannel
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

#include "tao/fake_tao_channel.h"

#include "tao/tao_child_channel_params.pb.h"

#include <glog/logging.h>

namespace tao {
bool FakeTaoChannel::AddChildChannel(const string &child_hash, string *params) {
  TaoChildChannelParams tccp;
  tccp.set_channel_type("FakeTaoChannel");
  tccp.set_params("");
  if (!tccp.SerializeToString(params)) {
    LOG(ERROR) << "Could not serialize the fake params";
    return false;
  }

  return true;
}
} // end namespace tao
