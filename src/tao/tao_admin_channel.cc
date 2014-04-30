//  File: tao_admin_channel.cc
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

#include "tao/tao_admin_channel.h"

#include <glog/logging.h>

namespace tao {
bool TaoAdminChannel::Shutdown() const {
  TaoAdminRequest rpc;
  rpc.set_rpc(TAO_ADMIN_RPC_SHUTDOWN);
  SendRPC(rpc);
  TaoAdminResponse resp;
  GetResponse(&resp);
  return resp.success();
}

bool TaoAdminChannel::StartHostedProgram(const string &path,
                                         const list<string> &args,
                                         string *identifier) const {
  TaoAdminRequest rpc;
  rpc.set_rpc(TAO_ADMIN_RPC_START_HOSTED_PROGRAM);

  rpc.set_path(path);
  for (const string &arg : args) {
    rpc.add_args(arg);
  }

  SendRPC(rpc);

  // wait for a response to the message
  TaoAdminResponse resp;
  GetResponse(&resp);

  if (resp.success()) {
    if (!resp.has_data()) {
      LOG(ERROR) << "A successful StartHostedProgram did not return data";
      return false;
    }

    identifier->assign(resp.data().data(), resp.data().size());
  }

  return resp.success();
}

bool TaoAdminChannel::RemoveHostedProgram(const string &child_hash) const {
  TaoAdminRequest rpc;
  rpc.set_rpc(TAO_ADMIN_RPC_REMOVE_HOSTED_PROGRAM);
  rpc.set_data(child_hash);

  SendRPC(rpc);

  TaoAdminResponse resp;
  GetResponse(&resp);

  return resp.success();
}

bool TaoAdminChannel::SendRPC(const TaoAdminRequest &rpc) const {
  return SendMessage(rpc);
}

bool TaoAdminChannel::GetResponse(TaoAdminResponse *resp) const {
  CHECK_NOTNULL(resp);
  return ReceiveMessage(resp);
}
}  // namespace tao
