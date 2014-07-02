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

#include <list>

#include <glog/logging.h>

#include "tao/fd_message_channel.h"
#include "tao/keys.h"
#include "tao/linux_admin_rpc.h"
#include "tao/linux_host.pb.h"
#include "tao/linux_process_factory.h"
#include "tao/pipe_factory.h"
#include "tao/tao_host.h"
#include "tao/tao_root_host.h"
#include "tao/tao_stacked_host.h"
#include "tao/unix_socket_factory.h"
#include "tao/util.h"

namespace tao {
bool LinuxHost::InitStacked(Tao *host_tao) {
  if (host_tao == nullptr) {
    LOG(ERROR) << "No host tao connection available";
    return false;
  }
  // Before attempting to initialize keys or doing anything else, make sure the
  // policy unique name becomes part of our name.
  string policy_subprin;
  if (!child_policy_->GetSubprincipalName(&policy_subprin)) {
    LOG(ERROR) << "Could not obtain policy name";
    return false;
  }
  // Make sure name extension happens *before* keys initialized, so they are
  // sealed to proper name.
  if (!host_tao->ExtendTaoName(policy_subprin)) {
    LOG(ERROR) << "Could not extend with policy name";
    return false;
  }
  scoped_ptr<Keys> keys(
      new Keys(path_, Keys::Signing | Keys::Crypting | Keys::Deriving));
  if (!keys->InitHosted(host_tao, Tao::SealPolicyDefault)) {
    LOG(ERROR) << "Could not obtain keys";
    return false;
  }
  tao_host_.reset(new TaoStackedHost(keys.release(), host_tao));
  return Init();
}

bool LinuxHost::InitRoot(const string &pass) {
  // There is no point in extending our own name in root mode -- we have the
  // key so we can do anything, including undoing an extend operation, and no
  // other principal should ever be led to believe otherwise.
  scoped_ptr<Keys> keys(
      new Keys(path_, Keys::Signing | Keys::Crypting | Keys::Deriving));
  if (!keys->InitWithPassword(pass)) {
    LOG(ERROR) << "Could not unlock keys";
    return false;
  }
  tao_host_.reset(new TaoRootHost(keys.release()));
  return Init();
}

bool LinuxHost::Init() {
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
      LOG(INFO) << "GetTaoName() for ::" << elideString(child->subprin);
      result_data = tao_host_->TaoHostName() + "::" + child->subprin;
      success = true;
      break;
    case TAO_RPC_EXTEND_TAO_NAME:
      LOG(INFO) << "ExtendTaoName() for ::" << elideString(child->subprin);
      if (!rpc.has_data() && rpc.data() != "") {
        LOG(ERROR) << "Invalid RPC: must supply data for ExtendName";
        break;
      }
      // TODO(kwalsh) Sanity checking on subprin format.
      child->subprin += "::" + rpc.data();
      success = true;
      break;
    case TAO_RPC_GET_RANDOM_BYTES:
      LOG(INFO) << "GetRandomBytes() for ::" << elideString(child->subprin);
      if (!rpc.has_size()) {
        LOG(ERROR) << "Invalid RPC: must supply arguments for GetRandomBytes";
        break;
      }
      success =
          tao_host_->GetRandomBytes(child->subprin, rpc.size(), &result_data);
      break;
    case TAO_RPC_GET_SHARED_SECRET:
      LOG(INFO) << "GetSharedSecret() for ::" << elideString(child->subprin);
      if (!rpc.has_size() || !rpc.has_policy()) {
        LOG(ERROR) << "Invalid RPC: must supply arguments for GetSharedSecret";
        break;
      }
      success = HandleGetSharedSecret(child->subprin, rpc.size(), rpc.policy(),
                                      &result_data);
      break;
    case TAO_RPC_ATTEST:
      LOG(INFO) << "Attest() for ::" << elideString(child->subprin);
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
      LOG(INFO) << "Seal() for ::" << elideString(child->subprin);
      if (!rpc.has_data()) {
        LOG(ERROR) << "Invalid RPC: must supply data for Seal";
        break;
      }
      success =
          HandleSeal(child->subprin, rpc.data(), rpc.policy(), &result_data);
      break;
    case TAO_RPC_UNSEAL:
      LOG(INFO) << "Unseal() for ::" << elideString(child->subprin);
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
      resp->set_reason("Unknown Tao RPC");
      success = false;
      break;
  }
  LOG(INFO) << "Result: " << (success ? "OK" : "FAIL");

  resp->set_success(success);
  if (success) resp->set_data(result_data);
  // TODO(kwalsh) Propagate other error messages?

  return true;
}

bool LinuxHost::HandleAdminRPC(const LinuxAdminRPCRequest &rpc,
                               LinuxAdminRPCResponse *resp,
                               bool *shutdown_request) {
  resp->set_rpc(rpc.rpc());
  bool success = false;
  string child_subprin, tao_name;
  string failure_msg;
  switch (rpc.rpc()) {
    case LINUX_ADMIN_RPC_SHUTDOWN:
      LOG(INFO) << "Shutdown()";
      *shutdown_request = true;
      success = true;
      break;
    case LINUX_ADMIN_RPC_START_HOSTED_PROGRAM:
      LOG(INFO) << "StartHostedProgram()";
      success = HandleStartHostedProgram(rpc, &child_subprin, &failure_msg);
      if (success)
        resp->set_data(child_subprin);
      else
        resp->set_reason(failure_msg);
      break;
    case LINUX_ADMIN_RPC_STOP_HOSTED_PROGRAM:
      LOG(INFO) << "StopHostedProgram()";
      success = HandleStopHostedProgram(rpc, SIGTERM, &failure_msg);
      if (!success) resp->set_reason(failure_msg);
      break;
    case LINUX_ADMIN_RPC_LIST_HOSTED_PROGRAMS:
      LOG(INFO) << "ListHostedPrograms()";
      {
        LinuxAdminRPCHostedProgramList info;
        for (auto &child : hosted_processes_) {
          info.add_name(child->subprin);
          info.add_pid(child->pid);
        }
        string data;
        success = info.SerializeToString(&data);
        if (success) resp->set_data(data);
      }
      break;
    case LINUX_ADMIN_RPC_KILL_HOSTED_PROGRAM:
      LOG(INFO) << "KillHostedProgram()";
      success = HandleStopHostedProgram(rpc, SIGKILL, &failure_msg);
      if (!success) resp->set_reason(failure_msg);
      break;
    case LINUX_ADMIN_RPC_GET_TAO_HOST_NAME:
      LOG(INFO) << "GetTaoHostName()";
      resp->set_data(tao_host_->TaoHostName());
      success = true;
      break;
    default:
      LOG(ERROR) << "Unknown Linux Admin RPC " << rpc.rpc();
      resp->set_reason("Unknown Linux Admin RPC");
      success = false;
      break;
  }

  LOG(INFO) << "Result: " << (success ? "OK" : "FAIL");
  resp->set_success(success);

  return true;
}

bool LinuxHost::HandleStartHostedProgram(const LinuxAdminRPCRequest &rpc,
                                         string *child_subprin,
                                         string *failure_msg) {
  if (!rpc.has_path()) {
    failure_msg->assign("Hosted program creation request is missing path");
    LOG(ERROR) << *failure_msg;
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
  // the host Tao underlying this Tao host gives out names that change across
  // restarts (i.e. reboots of TPM), then the counter will ensure that our
  // hosted
  // programs have names that change across restart (i.e. kill and run again
  // within same host Tao). Otherwise, if our Tao name does not vary but is
  // constant across restarts (i.e. reboots of the TPM), then the counter would
  // do little.
  // TODO(kwalsh) Use random ID instead, to make unique child names despite
  // non-unique host Tao names?

  if (!child_factory_->MakeHostedProgramSubprin(next_child_id_, path,
                                                child_subprin)) {
    failure_msg->assign("Could not make hosted program name");
    LOG(ERROR) << *failure_msg;
    return false;
  }

  string our_name = tao_host_->TaoHostName();

  if (!child_policy_->IsAuthorized(our_name + "::" + *child_subprin, "Execute",
                                   list<unique_ptr<Term>>{})) {
    LOG(ERROR)
        << "Hosted program denied authorization to execute on this host\n"
        << "Program: ::" << elideString(*child_subprin) << "\n"
        << "LinuxHost: " << elideString(our_name);
    failure_msg->assign(
        "Authorization to execute the hosted program is denied");
    return false;
  }

  LOG(INFO) << "Hosted program ::" << elideString(*child_subprin)
            << " is authorized to run on this Tao host";

  scoped_ptr<HostedLinuxProcess> child;
  if (!child_factory_->StartHostedProgram(*child_channel_factory_, path, args,
                                          *child_subprin, &child)) {
    LOG(ERROR) << "Could not start hosted program ::"
               << elideString(*child_subprin);
    failure_msg->assign("Could not start the hosted program");
    return false;
  }

  hosted_processes_.push_back(
      std::shared_ptr<HostedLinuxProcess>(child.release()));

  if (next_child_id_ != 0) {
    next_child_id_++;
    if (next_child_id_ == 0) {
      LOG(WARNING) << "Exhausted child ID space, disabling child IDs for "
                      "future children";
    }
  }

  return true;
}

bool LinuxHost::HandleStopHostedProgram(const LinuxAdminRPCRequest &rpc,
                                        int signum, string *failure_msg) {
  if (!rpc.has_data()) {
    failure_msg->assign("Hosted Program stop request is missing child subprin");
    LOG(ERROR) << *failure_msg;
    return false;
  }
  string child_subprin = rpc.data();
  int killed = 0;
  int errors = 0;
  for (auto it = hosted_processes_.begin(); it != hosted_processes_.end();
       /**/) {
    HostedLinuxProcess *child = it->get();
    if (child->subprin != child_subprin) {
      ++it;
      continue;
    }
    child->rpc_channel->Close();  // close channel to prevent future RPCs
    if (!child_factory_->StopHostedProgram(child, signum)) {
      errors++;
      ++it;  // leave it in case it exits later
    } else {
      killed++;
      // it = hosted_processes_.erase(it);
      ++it;  // leave it in so SIGCHLD can remove it
    }
  }
  if (killed == 0 && errors == 0) {
    LOG(ERROR) << "There are no hosted programs named ::"
               << elideString(child_subprin);
    failure_msg->assign("No such hosted program");
    return false;
  } else if (errors > 0) {
    LOG(ERROR) << "Signaled only " << killed << " of " << (killed + errors)
               << " children matching ::" << child_subprin;
    failure_msg->assign("Some matching hosted programs could not be killed");
    return false;
  } else {
    LOG(INFO) << "Signaled " << killed
              << " children matching ::" << elideString(child_subprin);
    return true;
  }
}

bool LinuxHost::HandleGetSharedSecret(const string &child_subprin, int size,
                                      const string &policy,
                                      string *bytes) const {
  if (size < 0) {
    LOG(ERROR) << "Invalid size parameter";
    return false;
  }
  // Chose a unique tag based on policy (and child_subprin).
  string tag;
  if (policy == Tao::SharedSecretPolicyDefault ||
      policy == Tao::SharedSecretPolicyConservative) {
    // We are using a master key-deriving key shared among all "similar"
    // LinuxHost instances. For LinuxHost, the default and conservative policies
    // means any process running the same program binary as the caller hosted on
    // a "similar" LinuxHost.
    // TODO(kwalsh) conservative policy could include PID, other child info
    tag = policy + "|" + child_subprin;
  } else if (policy == Tao::SharedSecretPolicyLiberal) {
    // The most liberal we can do is allow any hosted process running on a
    // "similar" LinuxHost instance.
    tag = policy;
  } else {
    // TODO(kwalsh) support more policies... but how?
    LOG(ERROR) << "GetSharedSecret policy not supported: " << policy;
    return false;
  }
  if (!tao_host_->GetSharedSecret(tag, size, bytes)) {
    LOG(ERROR) << "Could not get shared secret";
    return false;
  }
  return true;
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
    // TODO(kwalsh) conservative policy could include PID, other child info
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

bool LinuxHost::HandleChildSignal() {
  int pid = child_factory_->WaitForHostedProgram();
  if (pid == 0 || pid == -1) return false;
  for (auto it = hosted_processes_.begin(); it != hosted_processes_.end();
       ++it) {
    HostedLinuxProcess *child = it->get();
    if (child->pid == pid) {
      LOG(INFO) << "LinuxHost: removed dead hosted program ::"
                << elideString(child->subprin);
      child->rpc_channel->Close();
      child->pid = 0;
      hosted_processes_.erase(it);
      return true;
    }
  }
  LOG(WARNING) << "Could not find hosted program with PID " << pid;
  for (auto &child : hosted_processes_) {
    LOG(INFO) << "PID " << child->pid << " subprin "
              << elideString(child->subprin);
  }
  return false;
}

bool LinuxHost::Listen() {
  // When we get SIGTERM, we do a graceful shutdown.
  // Also, restart system calls interrupted by this signal if possible.
  ScopedSelfPipeFd stop_fd(new int(GetSelfPipeSignalFd(SIGTERM, SA_RESTART)));
  if (*stop_fd < 0) {
    LOG(ERROR) << "Could not create SIGTERM self-pipe";
    return false;
  }
  // When we get SIGCHLD, we wait for it then remove it from process list.
  // Also, don't get notified when child stops or resumes.
  // Also, YES let children be zombies, so omit SA_NOCLDWAIT.
  // Also, restart system calls interrupted by this signal if possible.
  ScopedSelfPipeFd child_fd(
      new int(GetSelfPipeSignalFd(SIGCHLD, SA_RESTART | SA_NOCLDSTOP)));
  if (*child_fd < 0) {
    LOG(ERROR) << "Could not create SIGCHLD self-pipe";
    return false;
  }
  // When we get SIGPIPE, we just ignore it.
  // Also, restart system calls interrupted by this signal if possible.
  ScopedSelfPipeFd pipe_fd(new int(GetSelfPipeSignalFd(SIGPIPE, SA_RESTART)));
  if (*pipe_fd < 0) {
    LOG(ERROR) << "Could not create SIGPIPE self-pipe";
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

    fd = *child_fd;
    FD_SET(fd, &read_fds);
    if (fd > max_fd) max_fd = fd;

    fd = *pipe_fd;
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

    VLOG(3) << "LinuxTao: Waiting...";
    google::FlushLogFiles(google::INFO);
    int err = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (err == -1 && errno == EINTR) {
      // Do nothing.
      continue;
    }
    VLOG(3) << "LinuxTao: Checking channels...";
    if (err == -1) {
      PLOG(ERROR) << "Error selecting descriptors";
      break;  // Abnormal termination.
    }

    if (FD_ISSET(*pipe_fd, &read_fds)) {
      char b;
      if (read(*pipe_fd, &b, 1) < 0) {
        PLOG(ERROR) << "Error reading signal number";
        break;  // Abnormal termination.
      }
      int signum = 0xff & static_cast<int>(b);
      VLOG(3) << "LinuxHost: received SIGPIPE " << signum << ", ignoring";
      // Do nothing.
    }

    if (FD_ISSET(*stop_fd, &read_fds)) {
      char b;
      if (read(*stop_fd, &b, 1) < 0) {
        PLOG(ERROR) << "Error reading signal number";
        break;  // Abnormal termination.
      }
      int signum = 0xff & static_cast<int>(b);
      LOG(INFO) << "LinuxHost: received SIGTERM " << signum
                << ", shutting down";
      graceful_shutdown = true;
      continue;
    }

    // Check for requests from child channels.
    for (auto it = hosted_processes_.begin(); it != hosted_processes_.end();
         /**/) {
      HostedLinuxProcess *child = it->get();
      fd = child->rpc_channel->GetReadFileDescriptor();
      TaoRPCRequest rpc;
      TaoRPCResponse resp;
      string subprin = child->subprin;
      bool eof = false;
      if (!FD_ISSET(fd, &read_fds)) {
        ++it;
        continue;
      }
      VLOG(3) << "Host process request";
      if (!child->rpc_channel->ReceiveMessage(&rpc, &eof) || eof ||
          !HandleTaoRPC(child, rpc, &resp) ||
          !child->rpc_channel->SendMessage(resp)) {
        if (eof)
          LOG(INFO) << "Lost connection to ::" << elideString(subprin);
        else
          LOG(ERROR) << "Error handling RPC for ::" << elideString(subprin);
        LOG(INFO) << "Closing channel for ::" << elideString(subprin);
        child->rpc_channel->Close();
        // leave it in so StopHostedProgram or SIGCHLD can remove it
        // it = hosted_processes_.erase(it);
        // tao_host_->RemovedHostedProgram(subprin);
        ++it;
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
        continue;
      }
      VLOG(3) << "Admin request";
      if (!admin->ReceiveMessage(&rpc, &eof) || eof ||
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
      VLOG(3) << "Admin connection";
      scoped_ptr<FDMessageChannel> admin(
          admin_channel_factory_->AcceptConnection());
      if (admin.get() != nullptr) {
        admin_clients_.push_back(
            std::shared_ptr<FDMessageChannel>(admin.release()));
      }
    }

    // Reap children that have exited.
    if (FD_ISSET(*child_fd, &read_fds)) {
      char b;
      if (read(*child_fd, &b, 1) < 0) {
        PLOG(ERROR) << "Error reading signal number";
        break;  // Abnormal termination.
      }
      int signum = 0xff & static_cast<int>(b);
      LOG(INFO) << "LinuxHost: received SIGCHLD " << signum
                << ", reaping children";
      if (!HandleChildSignal()) {
        LOG(WARNING) << "Could not reap child";
      }
      while (HandleChildSignal()) {
      }
    }
  }

  LOG(INFO) << "LinuxHost: Shutting down";
  return graceful_shutdown;
}

LinuxAdminRPC *LinuxHost::Connect(const string &path) {
  string sock_path = FilePath(path).Append("admin_socket").value();
  scoped_ptr<MessageChannel> chan(UnixSocketFactory::Connect(sock_path));
  if (chan.get() == nullptr) {
    LOG(ERROR) << "Could not connect to LinuxHost at " << sock_path;
    return nullptr;
  }
  return new LinuxAdminRPC(chan.release());
}

}  // namespace tao
