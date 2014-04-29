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
  TaoChannelRPC rpc;
  rpc.set_rpc(TAO_CHANNEL_RPC_GET_RANDOM_BYTES);
  GetRandomBytesArgs *grba = rpc.mutable_random();
  grba->set_size(size);

  SendRPC(rpc);

  // wait for a response
  TaoChannelResponse resp;
  GetResponse(&resp);

  if (resp.success()) {
    if (!resp.has_data()) {
      LOG(ERROR) << "The successful GetRandomBytes did not contain data";
      return false;
    }

    bytes->assign(resp.data().data(), resp.data().size());
  }

  return resp.success();
}

bool TaoChildChannel::SendAndReceiveData(const string &in, string *out,
                                         RPC rpc_type) const {
  CHECK_NOTNULL(out);

  TaoChannelRPC rpc;
  rpc.set_rpc(rpc_type);
  rpc.set_data(in);

  SendRPC(rpc);

  TaoChannelResponse resp;
  GetResponse(&resp);

  if (resp.success()) {
    if (!resp.has_data()) {
      LOG(ERROR) << "A successful call did not return data";
      return false;
    }

    out->assign(resp.data().data(), resp.data().size());
  }

  return resp.success();
}

bool TaoChildChannel::Seal(const string &data, string *sealed) const {
  return SendAndReceiveData(data, sealed, TAO_CHANNEL_RPC_SEAL);
}

bool TaoChildChannel::Unseal(const string &sealed, string *data) const {
  return SendAndReceiveData(sealed, data, TAO_CHANNEL_RPC_UNSEAL);
}

bool TaoChildChannel::Attest(const string &data, string *attestation) const {
  TaoChannelRPC rpc;
  rpc.set_rpc(TAO_CHANNEL_RPC_ATTEST);
  rpc.set_data(data);
  SendRPC(rpc);

  TaoChannelResponse resp;
  GetResponse(&resp);

  if (resp.success()) {
    if (!resp.has_data()) {
      LOG(ERROR) << "A successful Attest did not return data";
      return false;
    }

    attestation->assign(resp.data().data(), resp.data().size());
  }

  return resp.success();
}

bool TaoChildChannel::SendRPC(const TaoChannelRPC &rpc) const {
  return SendMessage(rpc);
}

bool TaoChildChannel::GetResponse(TaoChannelResponse *resp) const {
  CHECK_NOTNULL(resp);
  return ReceiveMessage(resp);
}
}  // namespace tao
