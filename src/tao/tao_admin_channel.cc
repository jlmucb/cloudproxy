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

#include "tao/util.h"

namespace tao {
bool TaoAdminChannel::Shutdown() const {
  TaoAdminRequest rpc;
  rpc.set_rpc(TAO_ADMIN_RPC_SHUTDOWN);
  TaoAdminResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from admin channel";
    else
      LOG(ERROR) << "RPC on admin channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on admin channel returned failure";
    return false;
  }
  return true;
}

bool TaoAdminChannel::StartHostedProgram(const string &path,
                                         const list<string> &args,
                                         string *child_name) const {
  TaoAdminRequest rpc;
  rpc.set_rpc(TAO_ADMIN_RPC_START_HOSTED_PROGRAM);

  rpc.set_path(path);
  for (const string &arg : args) {
    rpc.add_args(arg);
  }

  TaoAdminResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from admin channel";
    else
      LOG(ERROR) << "RPC on admin channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on admin channel returned failure";
    return false;
  }
  if (!resp.has_data()) {
    LOG(ERROR) << "A successful StartHostedProgram did not return data";
    return false;
  }

  child_name->assign(resp.data().data(), resp.data().size());
  return true;
}

bool TaoAdminChannel::RemoveHostedProgram(const string &child_name) const {
  TaoAdminRequest rpc;
  rpc.set_rpc(TAO_ADMIN_RPC_REMOVE_HOSTED_PROGRAM);
  rpc.set_data(child_name);

  TaoAdminResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from admin channel";
    else
      LOG(ERROR) << "RPC on admin channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on admin channel returned failure";
    return false;
  }
  return true;
}

bool TaoAdminChannel::GetTaoFullName(string *tao_name) const {
  TaoAdminRequest rpc;
  rpc.set_rpc(TAO_ADMIN_RPC_GET_TAO_FULL_NAME);

  TaoAdminResponse resp;
  bool eof;
  if (!SendRPC(rpc) || !ReceiveRPC(&resp, &eof) || eof) {
    if (eof)
      LOG(ERROR) << "Unexpected disconnect from admin channel";
    else
      LOG(ERROR) << "RPC on admin channel failed";
    return false;
  }
  if (!resp.success()) {
    LOG(ERROR) << "RPC on admin channel returned failure";
    return false;
  }
  if (!resp.has_data()) {
    LOG(ERROR) << "A successful call did not return data";
    return false;
  }
  tao_name->assign(resp.data().data(), resp.data().size());
  return true;
}

}  // namespace tao
