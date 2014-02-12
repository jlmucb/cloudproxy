//  File: process_factory.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A factory that creates child processes.
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

#ifndef TAO_PROCESS_FACTORY_H_
#define TAO_PROCESS_FACTORY_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/hosted_program_factory.h"

using std::list;
using std::string;

namespace tao {
/// A factory that creates hosted programs as processes. It forks and execs the
/// hosted program, making sure to clean up host state before exec.
class ProcessFactory : public HostedProgramFactory {
 public:
  ProcessFactory() {}
  virtual ~ProcessFactory() {}

  /// Compute the hash of a hosted program. The arguments are the same as the
  /// first three arguments of CreateHostedProgram.
  virtual bool HashHostedProgram(const string &name, const list<string> &args,
                                 string *child_hash) const;

  /// Start a process, using fork/exec, and pass it the params it needs to
  /// communicate with the host Tao.
  /// @param name The name of the file to execute.
  /// @param args The arguments for the process. CreateHostedProgram will add a
  /// final argument: the Base64W-encoding of a TaoChildChannelParams that
  /// specifies the file descriptors to use for Tao communication.
  /// @param child_hash The hash of the hosted program.
  /// @param parent_channel The channel to use for establishing communication
  /// with the hosted program.
  /// @param[out] identifier An identifier for the hosted program: e.g., a PID
  /// for a process
  virtual bool CreateHostedProgram(const string &name, const list<string> &args,
                                   const string &child_hash,
                                   TaoChannel &parent_channel,
                                   string *identifier) const;
  virtual string GetFactoryName() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProcessFactory);
};
}  // namespace tao

#endif  // TAO_PROCESS_FACTORY_H_
