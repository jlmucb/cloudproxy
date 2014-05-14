//  File: tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Interface used by hosted programs to access Tao services.
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
#include "tao/tao.h"

#include <cstdlib>

#include <glog/logging.h>

#include "tao/fd_message_channel.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

namespace tao {
Tao *Tao::host_tao_;

Tao *Tao::GetHostTao() {
  if (host_tao_ != nullptr) return host_tao_;
  const char *p = getenv(HostedProcessChannelEnvVar);
  if (p == nullptr) {
    LOG(ERROR) << "Missing environment variable " << HostedProcessChannelEnvVar;
    return nullptr;
  }
  string parent_channel_params(p);
  if (parent_channel_params.substr(0, 12) == "tao::TaoRPC:") {
    string channel_params = parent_channel_params.substr(12);
    scoped_ptr<MessageChannel> chan;
    if (channel_params.substr(0, 22) == "tao::FDMessageChannel(") {
      chan.reset(FDMessageChannel::DeserializeFromString(channel_params));
      if (chan.get() == nullptr) {
        LOG(ERROR) << "Could not create channel for TaoRPC";
        return nullptr;
      }
    } else {
      LOG(ERROR) << "Unrecognized channel for TaoRPC";
      return nullptr;
    }
    host_tao_ = new TaoRPC(chan.release());
  } else {
    LOG(ERROR) << "Unrecognized parent channel: " << parent_channel_params;
    return nullptr;
  }
  return host_tao_;
}

}  // namespace tao
