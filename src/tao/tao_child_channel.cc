//  File: tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: High-level implementation of Tao communication for hosted
//  programs
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

#include "tao/tao_child_channel.h"

#include <glog/logging.h>

namespace tao {

bool TaoChildChannel::GetRandomBytes(size_t size, string *bytes) const {
  TaoChildRequest rpc;
  rpc.set_rpc(TAO_CHILD_RPC_GET_RANDOM_BYTES);
  rpc.set_size(size);
  TaoChildResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from host channel";
    else
      LOG(ERROR) << "RPC on host channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on host channel returned failure";
    return false;
  }
  if (!resp.has_data()) {
    LOG(ERROR) << "A successful call did not return enough data";
    return false;
  }
  bytes->assign(resp.data());
  return true;
}

bool TaoChildChannel::Seal(const string &data, int policy,
                           string *sealed) const {
  TaoChildRequest rpc;
  rpc.set_rpc(TAO_CHILD_RPC_SEAL);
  rpc.set_data(data);
  rpc.set_policy(policy);
  TaoChildResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from host channel";
    else
      LOG(ERROR) << "RPC on host channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on host channel returned failure";
    return false;
  }
  if (!resp.has_data()) {
    LOG(ERROR) << "A successful call did not return enough data";
    return false;
  }
  sealed->assign(resp.data());
  return true;
}

bool TaoChildChannel::Unseal(const string &sealed, string *data,
                             int *policy) const {
  TaoChildRequest rpc;
  rpc.set_rpc(TAO_CHILD_RPC_UNSEAL);
  rpc.set_data(sealed);
  TaoChildResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from host channel";
    else
      LOG(ERROR) << "RPC on host channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on host channel returned failure";
    return false;
  }
  if (!resp.has_data() || !resp.has_policy()) {
    LOG(ERROR) << "A successful call did not return enough data";
    return false;
  }
  data->assign(resp.data());
  *policy = resp.policy();
  return true;
}

bool TaoChildChannel::Attest(const string &stmt, string *attestation) const {
  TaoChildRequest rpc;
  rpc.set_rpc(TAO_CHILD_RPC_ATTEST);
  rpc.set_data(stmt);
  TaoChildResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from host channel";
    else
      LOG(ERROR) << "RPC on host channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on host channel returned failure";
    return false;
  }
  if (!resp.has_data()) {
    LOG(ERROR) << "A successful call did not return enough data";
    return false;
  }
  attestation->assign(resp.data());
  return true;
}
bool TaoChildChannel::GetHostedProgramFullName(string *full_name) const {
  TaoChildRequest rpc;
  rpc.set_rpc(TAO_CHILD_RPC_GET_HOSTED_PROGRAM_FULL_NAME);
  TaoChildResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from host channel";
    else
      LOG(ERROR) << "RPC on host channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on host channel returned failure";
    return false;
  }
  if (!resp.has_data()) {
    LOG(ERROR) << "A successful call did not return enough data";
    return false;
  }
  full_name->assign(resp.data());
  return true;
}

bool TaoChildChannel::ExtendName(const string &subprin) const {
  TaoChildRequest rpc;
  rpc.set_rpc(TAO_CHILD_RPC_EXTEND_NAME);
  rpc.set_data(subprin);
  TaoChildResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from host channel";
    else
      LOG(ERROR) << "RPC on host channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on host channel returned failure";
    return false;
  }
  return true;
}

}  // namespace tao
