//  File: linux_host.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A Tao host environment based on Linux processes.
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
#include "tao/linux_host.h"

#include <glog/logging.h>

#include "tao/util.h"

namespace tao {


bool LinuxHost::Init() {
  scoped_ptr<Keys> keys(new Keys("linux_host", path_, Keys::Signing | Keys::Crypting));
  tao_host_.reset(new TaoHost(keys, host_tao_.release()));
  if (!tao_host.Init()) {
    LOG(ERROR) << "Could not initialize TaoHost";
    return false;
  }

  // create process factory, pipe channels
  // create admin channel
}


bool LinuxHost::HandleChildRPC(Tao *tao, string *child_name,
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

bool LinuxHost::HandleAdminRPC(Tao *tao, const TaoAdminRequest &rpc,
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
  }

  resp->set_success(success);

  return true;
}

bool LinuxHost::HandleProgramCreation(Tao *tao, const TaoAdminRequest &rpc,
                                       string *child_subprin) {
  if (!rpc.has_path()) {
    LOG(ERROR) << "Program creation request is missing path";
    return false;
  }
  string path = rpc.path();
  list<string> args;
  for (int i = 0; i < rpc.args_size(); i++) {
    args.push_back(rpc.args(i));
  }

  // What is in a name?
  // * We add program hash: child can't be trusted to add that.
  // * We don't add arg hash: child can add it at top of main if desired. If the
  // child is trustworthy under some arguments, then the top of main is
  // probably trustworthy under any arguments (unless certain arguments exploit
  // the to of main, e.g. buffer overflow in arg processing).
  // * We don't add env hash, but maybe we should, esp. LD_PRELOAD, etc.
  // * We don't add pid: child can add it at top of main if desired. But it is
  // not globally unique across reboots or even within a single boot, so it
  // doesn't really mean much. 
  // * We (optionally) add a monotonic counter: child can't easily do that. If
  // the host Tao hunderlying this Tao host gives out names that change across
  // restarts (i.e. reboots of TPM), then the counter will ensure that our hosted
  // programs have names that change across restart (i.e. kill and run again
  // within same host Tao). Otherwise, if our Tao name does not vary but is
  // constant across restarts (i.e. reboots of the TPM), then the counter would
  // do little. 
  // TODO(kwalsh) Use random ID instead, to make unique child names despite
  // non-unique host Tao names?

  if (!child_factory_->MakeHostedProgramSubprin(next_child_id_, path, &child_subprin)) {
    LOG(ERROR) << "Could not make hosted program name";
    return false;
  }

  string our_name;
  if (!tao_host_->GetTaoName(&our_name)) {
    LOG(ERROR) << "Could not get tao host name";
    return false;
  }

  CHECK(false);
  // if (!child_policy_->IsAuthorizedToExecute(our_name + "::" + *child_subprin)) {
  //     LOG(ERROR) << "Hosted program ::" << elideString(*child_subprin)
  //                << " is not authorized to run on this Tao host";
  //     return false;
  // }

  VLOG(2) << "Hosted program ::" << elideString(*child_subprin)
          << " is authorized to run on this Tao host";

  scoped_ptr<ProcessFactory::HostedProcess> child;
  if (!child_factory_->StartHostedProgram(&child_channel_factory, path, args,
                                          *child_subprin, &child)) {
    LOG(ERROR) << "Could not start hosted program ::" << elideString(*child_subprin);
    return false;
  }

  hosted_processes_[*child_subprin] = child;

  if (next_child_id_ != 0) {
    next_child_id_++;
    if (next_child_id_ == 0) {
      LOG(WARNING) << "Exhasted child ID space, disabling child IDs for future children";
    }
  }

  return true;
}

bool LinuxHost::StopHostedProgram(const string &child_subprin) {
  return child_factory_->StopHostedProgram(&child_channel_factory,
                                          child_subprin);
}

bool LinuxHost::Listen() {
  if (*admin_socket_ == -1) {
    LOG(ERROR) << "The UnixFdTaoChannel must be initialized with Init";
    return false;
  }
  ScopedSelfPipeFd stop_fd(new int(GetSelfPipeSignalFd(SIGTERM)));
  if (*stop_fd < 0) {
    LOG(ERROR) << "Could not create self-pipe";
    return false;
  }

  // Keep SIGPIPE from killing this program when a child dies and is connected
  // over a pipe.
  // TODO(tmroeder): maybe this step should be generalized and put in the apps/
  // code rather than in the library.
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  struct sigaction old_act;
  if (sigaction(SIGPIPE, &act, &old_act) < 0) {
    PLOG(ERROR) << "Could not set up the handler to block SIGPIPE";
    return false;
  }

  bool graceful_shutdown = false;
  while (!graceful_shutdown) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int fd, max_fd = 0;

    fd = *stop_fd;
    FD_SET(fd, &read_fds);
    if (fd > max_fd) max_fd = fd;

    int admin_fd = admin_channel_factory_->GetListenFileDescriptor();
    fd = admin_fd;
    FD_SET(fd, &read_fds);
    if (fd > max_fd) max_fd = fd;

    for (auto &admin : admin_clients_) {
      fd = admin->GetReadFileDescriptor();
      FD_SET(fd, &read_fds);
      if (fd > max_fd) max_fd = fd;
    }

    for (auto &child : hosted_processes_) {
      fd = child->rpc_channel->GetReadFileDescriptor();
      FD_SET(fd, &read_fds);
      if (fd > max_fd) max_fd = fd;
    }

    int err = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (err == -1 && errno == EINTR) {
      // Do nothing.
      continue;
    }
    if (err == -1) {
      PLOG(ERROR) << "Error selecting descriptors";
      break;  // Abnormal termination.
    }

    if (FD_ISSET(*stop_fd, &read_fds)) {
      char b;
      if (read(*stop_fd, &b, 1) < 0) {
        PLOG(ERROR) << "Error reading signal number";
        break;  // Abnormal termination.
      }
      int signum = 0xff & static_cast<int>(b);
      LOG(INFO) << "LinuxHost: received signal " << signum << ", shutting down";
      graceful_shutdown = true;
      continue;
    }

    // Check for requests from child channels.
    for (auto it = hosted_processes_.begin(); it != hosted_processes.end(); /**/ ) {
      auto &child = *it;
      fd = child->channel->GetReadFileDescriptor();
      TaoChildRequest rpc;
      TaoChildResponse resp;
      string subprin = child->subprin;
      bool eof = false;
      if (!FD_ISSET(fd, &read_fds)) {
        ++it;
      } else if (!child->channel->ReceiveChildRequest(&rpc, &eof) || eof ||
                 !HandleChildRPC(child, rpc, &resp) ||
                 !child->channel->SendChildResponse(resp)) {
        if (eof)
          LOG(INFO) << "Lost connection to ::" << subprin;
        else
          LOG(ERROR) << "Error handling RPC for ::" << subprin;
        LOG(INFO) << "Closing channel for ::" << subprin;
        child->channel->Close();
        it = hosted_processes_->erase(it);
        tao_host_->RemovedHostedProgram(subprin);
      } else {
        ++it;
      }
    }

    // Check for requests from admin channels.
    for (auto it = admin_clients_->begin(); it != admin_clients_->end(); /**/) {
      auto &admin = *it;
      fd = admin->GetReadFileDescriptor();
      TaoAdminRequest rpc;
      TaoAdminResponse resp;
      bool eof;
      if (!FD_ISSET(fd, &read_fds)) {
        ++it;
      } else if (!admin->ReceiveAdminRequest(&rpc, &eof) || eof ||
                 !HandleAdminRPC(tao, rpc, &resp, &graceful_shutdown) ||
                 !admin->SendAdminResponse(fd, resp)) {
        if (eof)
          LOG(INFO) << "Lost admin connection";
        else
          LOG(ERROR) << "Error handling RPC on admin channel";
        LOG(INFO) << "Closing admin channel";
        admin->Close();
        it = admin_clients_->erase(it);
      } else {
        ++it;
      }
    }

    // Check for new admin channels.
    if (FD_ISSET(admin_fd, &read_fds)) {
      scoped_ptr<FDMessageChannel> admin(
          admin_channel_factory_->AcceptConnection());
      if (admin.get() != nullptr) {
        admin_clients_->push_back(admin);
      }
    }
  }

  // Restore the old SIGPIPE signal handler.
  if (sigaction(SIGPIPE, &old_act, nullptr) < 0) {
    PLOG(ERROR) << "Could not restore the old signal handler.";
    return false;
  }

  return graceful_shutdown;
}

{
  if (!OpenUnixDomainSocket(admin_socket_path_, admin_socket_.get())) {
    LOG(ERROR) << "Could not open a socket to accept administrative requests";
    return false;
  }
}

{
  admin_socket_.reset(new int(-1));
  for (int fd : admin_descriptors_) close(fd);
  admin_descriptors_.clear();
}

}  // namespace tao
