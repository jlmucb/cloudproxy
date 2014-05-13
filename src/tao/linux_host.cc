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

#include <signal.h>

#include <glog/logging.h>

#include "tao/fd_message_channel.h"
#include "tao/keys.h"
#include "tao/linux_process_factory.h"
#include "tao/pipe_factory.h"
#include "tao/tao_host.h"
#include "tao/unix_socket_factory.h"
#include "tao/util.h"
#include "tao/linux_host.pb.h"

namespace tao {
bool LinuxHost::Init() {
  scoped_ptr<Keys> keys(new Keys("linux_host", path_, Keys::Signing | Keys::Crypting));
  if (!keys->InitHosted(*host_tao_, Tao::SealPolicyDefault)) {
    LOG(ERROR) << "Could not obtain keys";
    return false;
  }
  tao_host_.reset(new TaoHost(keys.release(), host_tao_.release()));
  if (!tao_host_->Init()) {
    LOG(ERROR) << "Could not initialize TaoHost";
    return false;
  }
  child_factory_.reset(new LinuxProcessFactory());
  child_channel_factory_.reset(new PipeFactory());
  admin_channel_factory_.reset(
      new UnixSocketFactory(FilePath(path_).Append("admin_socket").value()));
  if (!admin_channel_factory_->Init()) {
    LOG(ERROR) << "Could not initialize admin channel socket";
    return false;
  }
  return true;
}

bool LinuxHost::HandleTaoRPC(HostedLinuxProcess *child,
                             const TaoRPCRequest &rpc,
                             TaoRPCResponse *resp) const {
  resp->set_rpc(rpc.rpc());

  string result_data;
  string result_policy;
  bool success = false;
  switch (rpc.rpc()) {
    case TAO_RPC_GET_TAO_NAME:
      success = tao_host_->GetTaoName(child->subprin, &result_data);
      break;
    case TAO_RPC_EXTEND_TAO_NAME:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply data for ExtendName";
        break;
      }
      success = tao_host_->ExtendTaoName(child->subprin, rpc.data());
      if (success) {
        child->subprin += "::" + rpc.data();
      }
      break;
    case TAO_RPC_GET_RANDOM_BYTES:
      if (!rpc.has_size()) {
        LOG(ERROR) << "Invalid RPC: must supply arguments for GetRandomBytes";
        break;
      }
      success = tao_host_->GetRandomBytes(child->subprin, rpc.size(), &result_data);
      break;
    case TAO_RPC_ATTEST:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply arguments for GetRandomBytes";
        break;
      } else {
        Statement s;
        if (!s.ParsePartialFromString(rpc.data()) ||
            !(s.has_delegate() || s.has_predicate_name())) {
          LOG(ERROR) << "Invalid RPC: must supply legal partial statement";
          break;
        } else {
          success = tao_host_->Attest(child->subprin, &s, &result_data);
        }
      }
      break;
    case TAO_RPC_SEAL:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply data for Seal";
        break;
      }
      success =
          HandleSeal(child->subprin, rpc.data(), rpc.policy(), &result_data);
      break;
    case TAO_RPC_UNSEAL:
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply sealed data for Unseal";
        break;
      }
      success = HandleUnseal(child->subprin, rpc.data(), &result_data,
                             &result_policy);
      if (success) resp->set_policy(result_policy);
      break;
    default:
      LOG(ERROR) << "Unknown Tao RPC " << rpc.rpc();
      break;
  }

  resp->set_success(success);
  if (success) resp->set_data(result_data);

  return true;
}

bool LinuxHost::HandleAdminRPC(const LinuxAdminRPCRequest &rpc,
                               LinuxAdminRPCResponse *resp,
                               bool *shutdown_request) {
  resp->set_rpc(rpc.rpc());
  bool success = false;
  string child_subprin, tao_name;
  switch (rpc.rpc()) {
    case LINUX_ADMIN_RPC_SHUTDOWN:
      *shutdown_request = true;
      success = true;
      break;
    case LINUX_ADMIN_RPC_START_HOSTED_PROGRAM:
      success = HandleStartHostedProgram(rpc, &child_subprin);
      if (success) resp->set_data(child_subprin);
      break;
    case LINUX_ADMIN_RPC_STOP_HOSTED_PROGRAM:
      success = HandleStopHostedProgram(rpc);
      break;
    case LINUX_ADMIN_RPC_GET_TAO_HOST_NAME:
      resp->set_data(tao_host_->TaoHostName());
      success = true;
      break;
    default:
      LOG(ERROR) << "Unknown Linux Admin RPC " << rpc.rpc();
      break;
  }

  resp->set_success(success);

  return true;
}

bool LinuxHost::HandleStartHostedProgram(const LinuxAdminRPCRequest &rpc,
                                         string *child_subprin) {
  if (!rpc.has_path()) {
    LOG(ERROR) << "Hosted program creation request is missing path";
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

  if (!child_factory_->MakeHostedProgramSubprin(next_child_id_, path, child_subprin)) {
    LOG(ERROR) << "Could not make hosted program name";
    return false;
  }

  string our_name = tao_host_->TaoHostName();

  CHECK(false);
  // if (!child_policy_->IsAuthorizedToExecute(our_name + "::" + *child_subprin)) {
  //     LOG(ERROR) << "Hosted program ::" << elideString(*child_subprin)
  //                << " is not authorized to run on this Tao host";
  //     return false;
  // }

  VLOG(2) << "Hosted program ::" << elideString(*child_subprin)
          << " is authorized to run on this Tao host";

  scoped_ptr<HostedLinuxProcess> child;
  if (!child_factory_->StartHostedProgram(*child_channel_factory_, path, args,
                                          *child_subprin, &child)) {
    LOG(ERROR) << "Could not start hosted program ::" << elideString(*child_subprin);
    return false;
  }

  hosted_processes_.push_back(
      std::shared_ptr<HostedLinuxProcess>(child.release()));

  if (next_child_id_ != 0) {
    next_child_id_++;
    if (next_child_id_ == 0) {
      LOG(WARNING) << "Exhasted child ID space, disabling child IDs for future children";
    }
  }

  return true;
}

bool LinuxHost::HandleStopHostedProgram(const LinuxAdminRPCRequest &rpc) {
  if (!rpc.has_data()) {
    LOG(ERROR) << "Hosted Program stop request is missing child subprin";
    return false;
  }
  string child_subprin = rpc.data();
  int killed = 0;
  int errors = 0;
  for (auto it = hosted_processes_.begin(); it != hosted_processes_.end(); /**/ ) {
    HostedLinuxProcess *child = it->get();
    if (child->subprin != child_subprin) {
      ++it;
    } else if (!child_factory_->StopHostedProgram(child)) {
      errors++;
      it = hosted_processes_.erase(it);  // remove so we ignore future RPCs
    } else {
      killed++;
      it = hosted_processes_.erase(it);
    }
  }
  if (killed == 0 && errors == 0) {
    LOG(ERROR) << "There are no children named ::" << child_subprin;
    return false;
  } else if (errors > 0) {
    LOG(ERROR) << "Killed only " << killed << " of " << killed + errors
               << " children matching ::" << child_subprin;
    return false;
  } else {
    LOG(ERROR) << "Killed " << killed << " children matching ::" << child_subprin;
    return true;
  }
}

bool LinuxHost::HandleSeal(const string &child_subprin, const string &data,
                           const string &policy, string *sealed) const {
  LinuxHostSealedBundle bundle;
  bundle.set_policy(policy);
  bundle.set_data(data);
  if (policy == Tao::SealPolicyDefault ||
      policy == Tao::SealPolicyConservative) {
    // We are using keys to seal and unseal that are shared among all "similar"
    // LinuxHost instances. For LinuxHost, the default and conservative policies
    // means any process running the same program binary as the caller hosted on
    // a "similar" LinuxHost.
    bundle.set_policy_info(child_subprin);
  } else if (policy == Tao::SealPolicyLiberal) {
    // The most liberal we can do is allow any hosted process running on a
    // "similar" LinuxHost instance.
  } else {
    // TODO(kwalsh) support more policies, e.g. using ACLGuard?
    LOG(ERROR) << "Seal policy not supported: " << policy;
    return false;
  }
  if (!tao_host_->Encrypt(bundle, sealed)) {
    LOG(ERROR) << "Could not encrypt seal bundle";
    return false;
  }
  return true;
}

bool LinuxHost::HandleUnseal(const string &child_subprin, const string &sealed,
                             string *data, string *policy) const {
  LinuxHostSealedBundle bundle;
  if (!tao_host_->Decrypt(sealed, &bundle)) {
    LOG(ERROR) << "Could not decrypted seal bundle";
    return false;
  }
  if (bundle.policy() == Tao::SealPolicyDefault ||
      bundle.policy() == Tao::SealPolicyConservative) {
    const string &seal_child_subprin = bundle.policy_info();
    if (child_subprin != seal_child_subprin) {
      LOG(ERROR) << "Hosted program ::" << elideString(child_subprin)
                 << " is not authorized to unseal this data";
      return false;
    }
  } else if (bundle.policy() == Tao::SealPolicyLiberal) {
    // Allow all.
  } else {
    // TODO(kwalsh) support more policies, e.g. using ACLGuard?
    LOG(ERROR) << "Seal policy not supported: " << bundle.policy();
    return false;
  }
  data->assign(bundle.data());
  policy->assign(bundle.policy());
  return true;
}

bool LinuxHost::Listen() {
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
    for (auto it = hosted_processes_.begin(); it != hosted_processes_.end(); /**/ ) {
      HostedLinuxProcess *child = it->get();
      fd = child->rpc_channel->GetReadFileDescriptor();
      TaoRPCRequest rpc;
      TaoRPCResponse resp;
      string subprin = child->subprin;
      bool eof = false;
      if (!FD_ISSET(fd, &read_fds)) {
        ++it;
      } else if (!child->rpc_channel->ReceiveMessage(&rpc, &eof) || eof ||
                 !HandleTaoRPC(child, rpc, &resp) ||
                 !child->rpc_channel->SendMessage(resp)) {
        if (eof)
          LOG(INFO) << "Lost connection to ::" << subprin;
        else
          LOG(ERROR) << "Error handling RPC for ::" << subprin;
        LOG(INFO) << "Closing channel for ::" << subprin;
        child->rpc_channel->Close();
        it = hosted_processes_.erase(it);
        tao_host_->RemovedHostedProgram(subprin);
      } else {
        ++it;
      }
    }

    // Check for requests from admin channels.
    for (auto it = admin_clients_.begin(); it != admin_clients_.end(); /**/) {
      FDMessageChannel *admin = it->get();
      fd = admin->GetReadFileDescriptor();
      LinuxAdminRPCRequest rpc;
      LinuxAdminRPCResponse resp;
      bool eof;
      if (!FD_ISSET(fd, &read_fds)) {
        ++it;
      } else if (!admin->ReceiveMessage(&rpc, &eof) || eof ||
                 !HandleAdminRPC(rpc, &resp, &graceful_shutdown) ||
                 !admin->SendMessage(resp)) {
        if (eof)
          LOG(INFO) << "Lost admin connection";
        else
          LOG(ERROR) << "Error handling RPC on admin channel";
        LOG(INFO) << "Closing admin channel";
        admin->Close();
        it = admin_clients_.erase(it);
      } else {
        ++it;
      }
    }

    // Check for new admin channels.
    if (FD_ISSET(admin_fd, &read_fds)) {
      scoped_ptr<FDMessageChannel> admin(
          admin_channel_factory_->AcceptConnection());
      if (admin.get() != nullptr) {
        admin_clients_.push_back(
            std::shared_ptr<FDMessageChannel>(admin.release()));
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

}  // namespace tao
