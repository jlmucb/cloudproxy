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

#include "tao/fd_message_channel.h"

namespace tao {

bool TaoRPC::GetTaoName(string *name) {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_GET_TAO_NAME);
  return Request(&rpc, name, nullptr /* policy */);
}

bool TaoRPC::ExtendTaoName(const string &subprin) {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_EXTEND_TAO_NAME);
  rpc.set_data(subprin);
  return Request(&rpc, nullptr /* data */, nullptr /* policy */);
}

bool TaoRPC::GetRandomBytes(size_t size, string *bytes) {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_GET_RANDOM_BYTES);
  rpc.set_size(size);
  return Request(&rpc, bytes, nullptr /* policy */);
}

bool TaoRPC::GetSharedSecret(size_t size, const string &policy, string *bytes) {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_GET_SHARED_SECRET);
  rpc.set_size(size);
  rpc.set_policy(policy);
  return Request(&rpc, bytes, nullptr /* policy */);
}

bool TaoRPC::Attest(const Statement &stmt, string *attestation) {
  string serialized_stmt;
  if (!stmt.SerializePartialToString(&serialized_stmt)) {
    LOG(ERROR) << "Could not serialize partial statement";
    return false;
  }
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_ATTEST);
  rpc.set_data(serialized_stmt);
  return Request(&rpc, attestation, nullptr /* policy */);
}

bool TaoRPC::Seal(const string &data, const string &policy, string *sealed) {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_SEAL);
  rpc.set_data(data);
  rpc.set_policy(policy);
  return Request(&rpc, sealed, nullptr /* policy */);
}

bool TaoRPC::Unseal(const string &sealed, string *data, string *policy) {
  TaoRPCRequest rpc;
  rpc.set_rpc(TAO_RPC_UNSEAL);
  rpc.set_data(sealed);
  return Request(&rpc, data, policy);
}

bool TaoRPC::Request(TaoRPCRequest *req, string *data, string *policy) {
  req->set_seq(++last_seq_);
  TaoRPCResponse resp;
  bool eof;
  if (!channel_->SendMessage(*req)) {
    failure_msg_ = "Channel send failed";
    LOG(ERROR) << "RPC to Tao host failed: " << failure_msg_;
    return false;
  }
  if (!channel_->ReceiveMessage(&resp, &eof)) {
    failure_msg_ = "Channel receive failed";
    LOG(ERROR) << "RPC to Tao host failed: " << failure_msg_;
    return false;
  }
  if (eof) {
    failure_msg_ = "Channel is closed";
    LOG(ERROR) << "RPC to Tao host failed: " << failure_msg_;
    return false;
  }
  if (resp.has_error()) {
    failure_msg_ = resp.error();
    LOG(ERROR) << "RPC to Tao host failed: " << failure_msg_;
    return false;
  }
  if (resp.seq() != req->seq()) {
    failure_msg_ = "Unexpected sequence number in response";
    LOG(ERROR) << "RPC to Tao host failed: " << failure_msg_;
    return false;
  }
  if (data != nullptr) {
    if (!resp.has_data()) {
      failure_msg_ = "Malformed response (missing data)";
      LOG(ERROR) << "RPC to Tao host failed: " << failure_msg_;
      return false;
    }
    data->assign(resp.data());
  }
  if (policy != nullptr) {
    if (!resp.has_policy()) {
      failure_msg_ = "Malformed response (missing policy)";
      LOG(ERROR) << "RPC to Tao host failed: " << failure_msg_;
      return false;
    }
    policy->assign(resp.policy());
  }
  return true;
}

bool TaoRPC::SerializeToString(string *params) const {
  string channel_params;
  if (!channel_->SerializeToString(&channel_params)) {
    LOG(ERROR) << "Could not serialize TaoRPC";
    return false;
  }
  params->assign("tao::TaoRPC+" + channel_params);
  return true;
}

TaoRPC *TaoRPC::DeserializeFromString(const string &params) {
  stringstream in(params);
  skip(in, "tao::TaoRPC+");
  if (!in) return nullptr;  // not for us
  string channel_params;
  getline(in, channel_params, '\0');
  // Try each known channel type.
  MessageChannel *channel;
  channel = FDMessageChannel::DeserializeFromString(channel_params);
  if (channel != nullptr) return new TaoRPC(channel);
  LOG(ERROR) << "Unknown channel serialized for TaoRPC";
  return nullptr;
}

}  // namespace tao
