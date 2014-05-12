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

#include <list>
#include <string>

#include <glog/logging.h>

namespace tao {

bool TaoChannel::HandleChildRPC(Tao *tao, string *child_name,
                                const TaoChildRequest &rpc,
                                TaoChildResponse *resp) const {
  resp->set_rpc(rpc.rpc());

  string result_data, tao_name;
  int result_policy = 0;
  bool success = false;
  switch (rpc.rpc()) {
    case TAO_CHILD_RPC_GET_RANDOM_BYTES:
      if (!rpc.has_size()) {
        LOG(ERROR) << "Invalid RPC: must supply arguments for GetRandomBytes";
        break;
      }
      success = tao->GetRandomBytes(*child_name, rpc.size(), &result_data);
      break;
    case TAO_CHILD_RPC_SEAL:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply data for Seal";
        break;
      }
      success = tao->Seal(*child_name, rpc.data(), rpc.policy(), &result_data);
      break;
    case TAO_CHILD_RPC_UNSEAL:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply sealed data for Unseal";
        break;
      }
      success =
          tao->Unseal(*child_name, rpc.data(), &result_data, &result_policy);
      if (success) resp->set_policy(result_policy);
      break;
    case TAO_CHILD_RPC_ATTEST:
      success = tao->Attest(*child_name, rpc.data(), &result_data);
      break;
    case TAO_CHILD_RPC_GET_HOSTED_PROGRAM_FULL_NAME:
      success = tao->GetHostedProgramFullName(*child_name, &result_data);
      VLOG(0) << "got " << success << " for full name, " << *child_name
              << " --> " << result_data;
      break;
    case TAO_CHILD_RPC_EXTEND_NAME:
      // TODO(kwalsh) Check well-formedness of rpc.data() as a subprin name
      success = tao->ExtendName(child_name, rpc.data());
      success = true;
      break;
    default:
      LOG(ERROR) << "Unknown RPC " << rpc.rpc();
      break;
  }

  resp->set_success(success);
  if (success) resp->set_data(result_data);

  return true;
}

bool TaoChannel::HandleAdminRPC(Tao *tao, const TaoAdminRequest &rpc,
                                TaoAdminResponse *resp,
                                bool *shutdown_request) const {
  resp->set_rpc(rpc.rpc());
  bool success = true;
  string child_name, tao_name;
  switch (rpc.rpc()) {
    case TAO_ADMIN_RPC_SHUTDOWN:
      *shutdown_request = true;
      success = true;
      break;
    case TAO_ADMIN_RPC_START_HOSTED_PROGRAM:
      success = HandleProgramCreation(tao, rpc, &child_name);
      if (success) resp->set_data(child_name);
      break;
    case TAO_ADMIN_RPC_REMOVE_HOSTED_PROGRAM:
      // string child_name = rpc.to_be_determined();
      // success = tao.RemoveHostedProgram(child_name);
      // if (success)
      //   programs_to_erase_.push_back(child_name);
      LOG(ERROR) << "Not yet implemented";
      success = false;
      break;
    case TAO_ADMIN_RPC_GET_TAO_FULL_NAME:
      success = tao->GetTaoFullName(&tao_name);
      if (success) resp->set_data(tao_name);
      break;
    default:
      LOG(ERROR) << "Unknown RPC " << rpc.rpc();
      break;
      return true;  // TaoChannel::HandleRPC() already send the reply.
  }

  resp->set_success(success);

  return true;
}

bool TaoChannel::HandleProgramCreation(Tao *tao, const TaoAdminRequest &rpc,
                                       string *child_name) const {
  if (!rpc.has_path()) {
    LOG(ERROR) << "Program creation request is missing path";
    return false;
  }
  list<string> args;
  for (int i = 0; i < rpc.args_size(); i++) {
    args.push_back(rpc.args(i));
  }
  if (!tao->StartHostedProgram(rpc.path(), args, child_name)) {
    LOG(ERROR) << "Could not start hosted program " << rpc.path();
    return false;
  }
  return true;
}

}  // namespace tao
