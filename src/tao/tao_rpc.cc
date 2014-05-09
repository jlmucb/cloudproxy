//  File: tao_rpc.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: RPC client stub for channel-based Tao implementations.
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

#include "tao/tao_rpc.h"

#include <glog/logging.h>

namespace tao {

bool TaoRPC::GetTaoName(string *name) const {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_GET_TAO_NAME);
  return Request(rpc, name, nullptr /* policy */);
}

bool TaoRPC::ExtendTaoName(const string &subprin) const {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_EXTEND_TAO_NAME);
  rpc.set_data(subprin);
  return Request(rpc, nullptr /* data */, nullptr /* policy */);
}

bool TaoRPC::GetRandomBytes(size_t size, string *bytes) const {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_GET_RANDOM_BYTES);
  rpc.set_size(size);
  return Request(rpc, bytes, nullptr /* policy */);
}

bool TaoRPC::Attest(const string &stmt, string *attestation) const {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_ATTEST);
  rpc.set_data(stmt);
  return Request(rpc, attestation, nullptr /* policy */);
}

bool TaoRPC::Seal(const string &data, const string &policy,
                  string *sealed) const {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_SEAL);
  rpc.set_data(data);
  rpc.set_policy(policy);
  return Request(rpc, sealed, nullptr /* policy */);
}

bool TaoRPC::Unseal(const string &sealed, string *data, string *policy) const {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_UNSEAL);
  rpc.set_data(sealed);
  return Request(rpc, data, policy);
}

bool TaoRPC::Request(const TaoRPCRequest &req, string *data,
                     string *policy) const {
  TaoRPCResponse resp;
  if (!SendRPC(req) || !ReceiveRPC(&resp) || !resp.success()) {
    LOG(ERROR) << "RPC to Tao host failed";
    return false;
  }
  if (data != nullptr) {
    if (!resp.has_data()) {
      LOG(ERROR) << "RPC response from Tao host is missing data";
      return false;
    }
    data->assign(resp.data());
  }
  if (policy != nullptr) {
    if (!resp.has_policy()) {
      LOG(ERROR) << "RPC response from Tao host is missing policy";
      return false;
    }
    policy->assign(resp.policy());
  }
  return true;
}

}  // namespace tao
