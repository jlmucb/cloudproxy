//  File: linux_host.h
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
#ifndef TAO_LINUX_HOST_H_
#define TAO_LINUX_HOST_H_

#include <list>
#include <memory>
#include <string>

#include "tao/linux_admin_rpc.pb.h"
#include "tao/tao.h"
#include "tao/tao_rpc.pb.h"
#include "tao/util.h"

#include "tao/linux_process_factory.h"
#include "tao/pipe_factory.h"
#include "tao/tao_guard.h"
#include "tao/tao_host.h"
#include "tao/unix_socket_factory.h"

namespace tao {
using std::string;

class FDMessageChannel;
class HostedLinuxProcess;
class LinuxAdminRPC;

/// A Tao host environment in which hosted programs are Linux processes. Pipes
/// are used for communication with the hosted processes. A unix-domain socket
/// accepts administrative commands for controlling the host, e.g. starting
/// hosted processes, stopping hosted processes, or shutting down the host. The
/// linuxTao can be run in "stacked" mode (on top of a host Tao) or in "root"
/// mode (without an underlying host Tao).
class LinuxHost {
 public:
  /// Construct a LinuxHost.
  /// @param policy A guard for enforcing execution policy. This policy's unique
  /// name will become part of this tao host's name. Ownership is taken.
  /// @param path A directory for storing keys and other state.
  /// @param pass A password for unlocking keys. This is only used if
  LinuxHost(TaoGuard *policy, const string &path)
      : path_(path), next_child_id_(0), child_policy_(policy) {}

  /// Open ports and acquire resources for a stacked Tao.
  /// @param host_tao The host Tao, i.e. obtained from Tao::GetHostTao().
  virtual bool InitStacked(Tao *host_tao);

  /// Open ports and acquire resources for a root Tao.
  /// @param pass The password for unlocking signing and crypting keys.
  virtual bool InitRoot(const string &pass);

  virtual ~LinuxHost() {}

  /// Set the ID of the next child to be created. Child IDs will not be used
  /// unless this method is called with a non-zero ID.
  /// @param id The ID.
  virtual void SetNextChildID(unsigned int id) { next_child_id_ = id; }

  /// Get the ID of the next child to be created. If Child IDs are disabled,
  /// then this method returns 0.
  virtual unsigned int GetNextChildID() { return next_child_id_; }

  /// Listen for and process messages from child and admin channels until a
  /// shutdown is initiated.
  virtual bool Listen();

  static LinuxAdminRPC *Connect(const string &path);

  virtual string TaoHostName() { return tao_host_->TaoHostName(); }

  virtual string DebugString() const {
    return elideString(tao_host_->TaoHostName());
  }

 protected:
  /// Handle incoming messages from a hosted program.
  /// @param tao The Tao implementation that handles the message.
  /// @param[in,out] child The hosted program that sent the message.
  /// If the child requests a name extension, this will be modified.
  /// @param rpc The RPC containing the received message.
  /// @param[out] resp The response to send if return value is true.
  virtual bool HandleTaoRPC(HostedLinuxProcess *child, const TaoRPCRequest &rpc,
                            TaoRPCResponse *resp) const;

  /// Handle incoming messages from an administrative program.
  /// @param tao The Tao implementation that handles the message.
  /// @param rpc The RPC containing the received message.
  /// @param[out] resp The response to send if return value is true.
  /// @param[out] shutdown_request Set to true if shutdown is requested.
  virtual bool HandleAdminRPC(const LinuxAdminRPCRequest &rpc,
                              LinuxAdminRPCResponse *resp,
                              bool *shutdown_request);

 protected:
  /// Common initialization.
  bool Init();

  /// Handle a StartHostedProgram RPC.
  /// @param rpc The RPC containing the StartHostedProgram request.
  /// @param[out] child_subprin The name for the new hosted program.
  /// @param[out] failure_msg A failure message, if any.
  bool HandleStartHostedProgram(const LinuxAdminRPCRequest &rpc,
                                string *child_subprin, string *failure_msg);

  /// Handle a StopHostedProgram or KillHostedProgram RPC.
  /// @param rpc The RPC containing the StopHostedProgram request.
  /// @param signum The signal that should be sent to matching hosted programs.
  /// @param[out] failure_msg A failure message, if any.
  bool HandleStopHostedProgram(const LinuxAdminRPCRequest &rpc, int signum,
                               string *failure_msg);

  /// Handle a SIGCHLD signal.
  bool HandleChildSignal();

  /// Handle a Seal RPC.
  /// @param child_subprin The name of the requesting hosted program.
  /// @param data The data to be sealed.
  /// @param policy The policy under which to seal the data.
  /// @param[out] sealed The sealed data.
  bool HandleSeal(const string &child_subprin, const string &data,
                  const string &policy, string *sealed) const;

  /// Handle an Unseal RPC.
  /// @param child_subprin The name of the requesting hosted program.
  /// @param sealed The sealed data.
  /// @param[out] data The unsealed data.
  /// @param[out] policy The policy under which the data was sealed.
  bool HandleUnseal(const string &child_subprin, const string &sealed,
                    string *data, string *policy) const;

  /// The tao host.
  scoped_ptr<TaoHost> tao_host_;

  /// Path to config directory.
  string path_;

  /// The ID of the next child to create, or 0 to disable monotonic child IDs.
  unsigned int next_child_id_;

  /// The hosted program factory, responsible for starting and stopping hosted
  /// programs and giving them names.
  scoped_ptr<LinuxProcessFactory> child_factory_;

  /// The child channel factory, responsible for setting up and tearing down the
  /// channel between this Tao host and hosted program.
  scoped_ptr<PipeFactory> child_channel_factory_;

  /// The admin channel factory, responsible for setting up and tearing down
  /// channels between this Tao host and administrative programs.
  scoped_ptr<UnixSocketFactory> admin_channel_factory_;

  /// The hosted program policy agent, responsible for deciding whether a hosted
  /// program should be allowed to execute.
  /// TODO(kwalsh) Maybe also helps with seal/unseal policy enforcement?
  scoped_ptr<TaoGuard> child_policy_;

  list<std::shared_ptr<HostedLinuxProcess>> hosted_processes_;

  list<std::shared_ptr<FDMessageChannel>> admin_clients_;

 private:
  DISALLOW_COPY_AND_ASSIGN(LinuxHost);
};
}  // namespace tao

#endif  // TAO_LINUX_HOST_H_
