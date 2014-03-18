//  File: tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: High-level implementation of Tao communication that
//  can function over any subclass that implements the pure virtual
//  functions in TaoChannel
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

#include "tao/tao_channel.h"

#include <glog/logging.h>

namespace tao {

// This version of HandleRPC() only handles hosted-program methods,
// not administrative methods.
bool TaoChannel::HandleRPC(Tao &tao, const string &hash,  // NOLINT
                           const TaoChannelRPC &rpc) const {
  // switch on the type of RPC and pass it to the tao function
  TaoChannelResponse resp;
  resp.set_rpc(rpc.rpc());

  string result_data;
  bool result = false;
  switch (rpc.rpc()) {
    case TAO_CHANNEL_RPC_SHUTDOWN:
    case TAO_CHANNEL_RPC_START_HOSTED_PROGRAM:
    case TAO_CHANNEL_RPC_REMOVE_HOSTED_PROGRAM:
      // These administrative RPCs are handled by subclasses.
      return false;
      break;
    case TAO_CHANNEL_RPC_GET_RANDOM_BYTES:
      if (!rpc.has_random()) {
        LOG(ERROR) << "Invalid RPC: must supply arguments for GetRandomBytes";
        break;
      }
      result = tao.GetRandomBytes(rpc.random().size(), &result_data);
      resp.set_data(result_data);
      break;
    case TAO_CHANNEL_RPC_SEAL:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply data for Seal";
        break;
      }
      result = tao.Seal(hash, rpc.data(), &result_data);
      resp.set_data(result_data);
      break;
    case TAO_CHANNEL_RPC_UNSEAL:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply sealed data for Unseal";
        break;
      }
      result = tao.Unseal(hash, rpc.data(), &result_data);
      resp.set_data(result_data);
      break;
    case TAO_CHANNEL_RPC_ATTEST:
      result = tao.Attest(hash, rpc.data(), &result_data);
      resp.set_data(result_data);
      break;
    default:
      LOG(ERROR) << "Unknown RPC " << rpc.rpc();
      break;
  }

  resp.set_success(result);
  SendResponse(resp, hash);

  return true;
}

bool TaoChannel::GetRPC(TaoChannelRPC *rpc, const string &child_hash) const {
  CHECK_NOTNULL(rpc);
  return ReceiveMessage(rpc, child_hash);
}

bool TaoChannel::SendResponse(const TaoChannelResponse &resp,
                              const string &child_hash) const {
  return SendMessage(resp, child_hash);
}
}  // namespace tao
