//  File: linux_admin_rpc.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
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
#ifndef TAO_LINUX_ADMIN_RPC_H_
#define TAO_LINUX_ADMIN_RPC_H_

#include <list>
#include <string>

#include "tao/message_channel.h"
#include "tao/linux_admin_rpc.pb.h"
#include "tao/util.h"

namespace tao {
using std::list;
using std::string;

// RPC interface for administering a LinuxHost.
class LinuxAdminRPC {
 public:
  /// Construct a TaoRPC.
  /// @param channel The channel over which to send and recieve messages.
  /// Ownership is taken.
  LinuxAdminRPC(MessageChannel *channel) : channel_(channel) {}

  /// Methods that invoke the administrative interfaces of LinuxTao.
  /// @{
  
  /// Request the full name of the LinuxTao. 
  virtual bool GetTaoHostName(string *name) const;

  /// Request the LinuxTao be shut down.
  virtual bool Shutdown() const;

  /// Request the LinuxTao start a new hosted program. 
  /// @param path The path to the hosted program binary.
  /// @param args The arguments for the hosted program.
  /// @param[out] child_subprin The subprincipal name of the new hosted program.
  virtual bool StartHostedProgram(const string &path, const list<string> &args,
                                  string *child_subprin) const;

  /// Request the LinuxTao stop a hosted program. If there are multiple hosted
  /// programs with the same name, all of them will be stopped.
  /// @param[out] child_subprin The subprincipal name of the hosted program(s).
  virtual bool StopHostedProgram(const string &child_subprin) const;

  /// @}

 protected:
  /// The channel over which to send and receive messages.
  scoped_ptr<MessageChannel> channel_;

 private:
  /// Do an RPC request/response interaction with the LinuxTao host.
  /// @param req The request to send.
  /// @param[out] data The returned data, if not nullptr.
  bool Request(const LinuxAdminRPCRequest &req, string *data) const;

  DISALLOW_COPY_AND_ASSIGN(LinuxAdminRPC);
};
}  // namespace tao

#endif  // TAO_LINUX_ADMIN_RPC_H_