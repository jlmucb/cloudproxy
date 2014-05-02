//  File: hosted_program_factory.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An interface for code that starts hosted programs
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

#ifndef TAO_HOSTED_PROGRAM_FACTORY_H_
#define TAO_HOSTED_PROGRAM_FACTORY_H_

#include <list>
#include <string>

using std::list;
using std::string;

namespace tao {
class TaoChannel;

/// An interface for factories that create hosted programs in the Tao. There are
/// many possible implementations: the factory could create process, it could
/// create threads, it could create virtual machines, or it could even create
/// Linux components.
class HostedProgramFactory {
 public:
  virtual ~HostedProgramFactory() {}

  virtual bool Init() { return true; }
  virtual bool Destroy() { return true; }

  /// Compute a tentative unique name for a hosted program.
  /// The semantics of each input argument depends on the factory
  /// implementation.
  /// @param id A (tentative) locally-unique id for the hosted program.
  /// @param path The path of the hosted program binary.
  /// @param args The arguments for the hosted program.
  /// @param[out] tentative_child_name A tentative unique name.
  /// TODO(kwalsh) This is ugly. Result is tentative because we don't know the
  ///   PID yet, and we want that as part of the name. Process will
  ///   drop to subprin as soon as it starts to match the finalized name. But
  ///   the tentative name is enough for checking authorization to execute.
  virtual bool GetHostedProgramTentativeName(
      int id, const string &path, const list<string> &args,
      string *tentative_child_name) const = 0;

  /// Create a hosted program, passing channel information.
  /// The semantics of each input argument depends on the factory
  /// implementation.
  /// @param id A (finalized) locally-unique id for the hosted program.
  /// @param path The path of the hosted program binary.
  /// @param args The arguments for the hosted program.
  /// @param tentative_child_name The tentative name the program.
  /// @param parent_channel Used to create child's host channel.
  /// @param[out] The finalized child name.
  virtual bool CreateHostedProgram(int id, const string &name,
                                   const list<string> &args,
                                   const string &tentative_child_name,
                                   TaoChannel *parent_channel,
                                   string *child_name) const = 0;

  /// Return a string that represents the factory. This can be
  /// used for implementing a registry of factories.
  virtual string GetFactoryName() const = 0;

  /// Parse a child name into its component parts.
  /// Ideally, these details would be specific to a factory implementation, but
  /// LinuxTao needs to parse these names to enforce execution, seal and unseal
  /// policies.
  /// @param child_name A tentative or finalized child name.
  /// @param[out] id The unique id number.
  /// @param[out] path The path to the program binary.
  /// @param[out] prog_hash Hash of the program binary.
  /// @param[out] arg_hash Hash of the program arguments.
  /// @param[out] pid The process ID, or emptystring for a tentative name.
  /// @param[out] subprin Any remaining components, or emptystring.
  virtual bool ParseChildName(string child_name, int *id, string *path,
                              string *prog_hash, string *arg_hash, string *pid,
                              string *subprin) const = 0;

 protected:
  /// Create a child name from its component parts.
  /// Ideally, these details would be specific to a factory implementation, but
  /// LinuxTao needs to parse these names to enforce execution, seal and unseal
  /// policies.
  /// @param id A unique id number.
  /// @param path The path to the program binary.
  /// @param prog_hash Hash of the program binary.
  /// @param arg_hash Hash of the program arguments.
  /// @param pid The process ID, or emptystring if not yet know.
  virtual string CreateChildName(int id, const string &path,
                                 const string &prog_hash,
                                 const string &arg_hash, string pid) const = 0;
};
}  // namespace tao

#endif  // TAO_HOSTED_PROGRAM_FACTORY_H_
