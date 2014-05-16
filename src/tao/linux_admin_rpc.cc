//  File: linux_admin_rpc.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: RPC interface for administering a LinuxHost.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#include "tao/linux_admin_rpc.h"

#include <glog/logging.h>

#include "tao/util.h"

namespace tao {
bool LinuxAdminRPC::GetTaoHostName(string *name) const {
  LinuxAdminRPCRequest rpc;
  rpc.set_rpc(LINUX_ADMIN_RPC_GET_TAO_HOST_NAME);
  return Request(rpc, name);
}

bool LinuxAdminRPC::Shutdown() const {
  LinuxAdminRPCRequest rpc;
  rpc.set_rpc(LINUX_ADMIN_RPC_SHUTDOWN);
  return Request(rpc, nullptr /* data */);
}

bool LinuxAdminRPC::StartHostedProgram(const string &path,
                                         const list<string> &args,
                                         string *child_subprin) const {
  LinuxAdminRPCRequest rpc;
  rpc.set_rpc(LINUX_ADMIN_RPC_START_HOSTED_PROGRAM);
  rpc.set_path(path);
  for (const string &arg : args) rpc.add_args(arg);
  return Request(rpc, child_subprin);
}

bool LinuxAdminRPC::StopHostedProgram(const string &child_subprin) const {
  LinuxAdminRPCRequest rpc;
  rpc.set_rpc(LINUX_ADMIN_RPC_STOP_HOSTED_PROGRAM);
  rpc.set_data(child_subprin);
  return Request(rpc, nullptr /* data */);
}

bool LinuxAdminRPC::KillHostedProgram(const string &child_subprin) const {
  LinuxAdminRPCRequest rpc;
  rpc.set_rpc(LINUX_ADMIN_RPC_KILL_HOSTED_PROGRAM);
  rpc.set_data(child_subprin);
  return Request(rpc, nullptr /* data */);
}

bool LinuxAdminRPC::ListHostedPrograms(list<pair<string, int>> *child_info) const {
  LinuxAdminRPCRequest rpc;
  rpc.set_rpc(LINUX_ADMIN_RPC_LIST_HOSTED_PROGRAMS);
  string data;
  LinuxAdminRPCHostedProgramList info;
  if (!Request(rpc, &data) ||
      !info.ParseFromString(data) ||
      info.name_size() != info.pid_size())
      return false;
  child_info->clear();
  for (int i = 0; i < info.name_size(); i++) {
    child_info->push_back(make_pair(info.name(i), info.pid(i)));
  }
  return true;
}

bool LinuxAdminRPC::Request(const LinuxAdminRPCRequest &req, string *data) const {
  LinuxAdminRPCResponse resp;
  bool eof;
  if (!channel_->SendMessage(req) || !channel_->ReceiveMessage(&resp, &eof) ||
      eof || !resp.success()) {
    LOG(ERROR) << "RPC to LinuxTao host failed";
    return false;
  }
  if (data != nullptr) {
    if (!resp.has_data()) {
      LOG(ERROR) << "RPC response from LinuxTao host is missing data";
      return false;
    }
    data->assign(resp.data());
  }
  return true;
}

}  // namespace tao
