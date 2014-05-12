//  File: tao_host_env.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A base class for implementating a Tao host environment.
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
#ifndef TAO_TAO_HOST_ENV_H_
#define TAO_TAO_HOST_ENV_H_

#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao.h"
#include "tao/tao_admin_channel.pb.h"
#include "tao/tao_child_channel.pb.h"

using std::string;

namespace tao {
/// A base class for implementing a Tao host environment that provides the Tao
/// interface and services to hosted programs. This class provides a partial
/// implementation for driving a TaoHost.  Derived classes specialize this
/// implementation for specific environments, e.g. a Linux OS, a Linux process
/// group, a hypervisor, or a JVM.
class TaoHostEnv {
 public:
  /// Construct a TaoHostEnv.
  /// @param tao The Tao
  TaoHostEnv(TaoChildChannel {}
  virtual ~TaoHostEnv() {}

  /// Initialize the server, opening ports and allocating resources as needed.
  virtual bool Init() = 0;

  /// Listen for and process messages from child and admin channels until a
  /// shutdown is initiated.
  /// @param tao The Tao implementation that will handle received messages.
  virtual bool Listen(Tao *tao) = 0;

  /// Close ports and release any resources used by the server.
  virtual bool Destroy() = 0;

  /// Add a child to this channel and return the string that will let the child
  /// connect using the same type.
  /// @param tentative_child_name The tentative name of the child to add.
  /// @param[out] params The Base64W-encoded TaoChildChannelParams that the
  /// child will use to connect to this TaoHostEnv.
  virtual bool AddChildChannel(const string &tentative_child_name,
                               string *params) = 0;

  /// Clean up host state in child during hosted program creation.
  /// @param encoded_params The Base64W-encoded TaoChildChannelParams that the
  /// child will use to connect to this TaoHostEnv.
  /// @param subprin A subprincipal name used to finalize our name.
  virtual bool ChildCleanup(const string &encoded_params,
                            const string &subprin) = 0;

  /// Clean up hosted program state in host during hosted program creation.
  /// @param tentative-child_name Name of the hosted program being created.
  virtual bool ParentCleanup(const string &tentative_child_name) = 0;

  /// Provide new params for a hosted program.
  /// @param tentative_child_name The name associated with the new parameters.
  /// @param params The new parameters to use.
  virtual bool UpdateChildParams(const string &tentative_child_name,
                                 const string &params) = 0;

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

 private:
  /// Handle the StartHostedProgram RPC.
  /// @param tao The Tao implementation that handles the message.
  /// @param rpc The RPC containing the StartHostedProgram request.
  /// @param[out] child_name The name for the new hosted program.
  bool HandleProgramCreation(Tao *tao, const TaoAdminRequest &rpc,
                             string *child_name) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaoHostEnv);
};
}  // namespace tao

#endif  // TAO_TAO_HOST_ENV_H_
