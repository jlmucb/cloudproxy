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

#include <string>

#include "tao/tao.h"

namespace tao {
using std::string;

class TaoHost;

/// A Tao host environment in which hosted programs are Linux processes. Pipes
/// are used for communication with the hosted processes. A unix-domain socket
/// accepts administrative commands for controlling the host, e.g. starting
/// hosted processes, stopping hosted processes, or shutting down the host.
class LinuxHost {
 public:
  /// Construct a LinuxHost.
  /// @param host_tao The host Tao on which this environment is running.
  /// Ownership is taken.
  /// @param path A directory for storing keys and other state.
  LinuxHost(Tao *host_tao, const string &path)
      : host_tao_(host_tao), path_(path) {}

  /// Open ports and aquire resources.
  virtual bool Init();

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
  virtual bool Listen() = 0;

 protected:
  /// Handle incoming messages from a hosted program.
  /// @param tao The Tao implementation that handles the message.
  /// @param[in,out] child_name The name of the hosted program that sent the
  /// message. If the child requests a name extension, this will be modified.
  /// @param rpc The RPC containing the received message.
  /// @param[out] resp The response to send if return value is true.
  virtual bool HandleChildRPC(Tao *tao, string *child_name,
                              const TaoChildRequest &rpc,
                              TaoChildResponse *resp) const;

  /// Handle incoming messages from an administrative program.
  /// @param tao The Tao implementation that handles the message.
  /// @param rpc The RPC containing the received message.
  /// @param[out] resp The response to send if return value is true.
  /// @param[out] shutdown_request Set to true if shutdown is requested.
  virtual bool HandleAdminRPC(Tao *tao, const TaoAdminRequest &rpc,
                              TaoAdminResponse *resp,
                              bool *shutdown_request) const;

 protected:
  /// Handle the StartHostedProgram RPC.
  /// @param tao The Tao implementation that handles the message.
  /// @param rpc The RPC containing the StartHostedProgram request.
  /// @param[out] child_name The name for the new hosted program.
  bool HandleProgramCreation(Tao *tao, const TaoAdminRequest &rpc,
                             string *child_name) const;


  /// The host tao.
  scoped_ptr<Tao> host_tao_;

  /// The tao host.
  scoped_ptr<TaoHost> tao_host_;

  /// Path to config directory.
  string path_;

  /// The ID of the next child to create, or 0 to disable monootonic child IDs.
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
  //scoped_ptr<ACLGuard> child_policy_;

  list<HostedLinuxProcess> hosted_processes_;

  list<scoped_ptr<FDMessageChannel>> admin_clients_;

 private:
  DISALLOW_COPY_AND_ASSIGN(LinuxHost);
};
}  // namespace tao

#endif  // TAO_LINUX_HOST_H_
