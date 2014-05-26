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
#include "tao/tpm_tao.h"
#include "tao/soft_tao.h"
#include "tao/util.h"

namespace tao {
Tao *Tao::host_tao_;

Tao *Tao::GetHostTao() {
  if (host_tao_ != nullptr) return host_tao_;
  const char *p = getenv(HostTaoEnvVar);
  if (p == nullptr || strlen(p) == 0) {
    LOG(ERROR) << "Missing environment variable " << HostTaoEnvVar;
    return nullptr;
  }
  string params(p);
  // Try each known type of Tao in turn.
  host_tao_ = TaoRPC::DeserializeFromString(params);
  if (host_tao_ != nullptr) return host_tao_;
  host_tao_ = SoftTao::DeserializeFromString(params);
  if (host_tao_ != nullptr) return host_tao_;
  host_tao_ = TPMTao::DeserializeFromString(params);
  if (host_tao_ != nullptr) return host_tao_;
  LOG(ERROR) << "Unrecognized host Tao channel: " << params;
  return nullptr;
}

}  // namespace tao
