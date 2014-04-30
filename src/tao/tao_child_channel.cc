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

bool TaoChildChannel::SendAndReceiveData(const string &instr, int inval,
                                         string *out,
                                         TaoChildRequestType rpc_type) const {
  CHECK_NOTNULL(out);

  TaoChildRequest rpc;
  rpc.set_rpc(rpc_type);
  rpc.set_data(instr);
  rpc.set_size(inval);

  SendRPC(rpc);

  TaoChildResponse resp;
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

bool TaoChildChannel::GetRandomBytes(size_t size, string *bytes) const {
  return SendAndReceiveData("", size, bytes, TAO_CHILD_RPC_GET_RANDOM_BYTES);
}

bool TaoChildChannel::Seal(const string &data, string *sealed) const {
  return SendAndReceiveData(data, 0, sealed, TAO_CHILD_RPC_SEAL);
}

bool TaoChildChannel::Unseal(const string &sealed, string *data) const {
  return SendAndReceiveData(sealed, 0, data, TAO_CHILD_RPC_UNSEAL);
}

bool TaoChildChannel::Attest(const string &data, string *attestation) const {
  return SendAndReceiveData(data, 0, attestation, TAO_CHILD_RPC_ATTEST);
}

bool TaoChildChannel::SendRPC(const TaoChildRequest &rpc) const {
  return SendMessage(rpc);
}

bool TaoChildChannel::GetResponse(TaoChildResponse *resp) const {
  CHECK_NOTNULL(resp);
  return ReceiveMessage(resp);
}
}  // namespace tao
