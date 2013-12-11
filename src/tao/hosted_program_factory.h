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

// An interface for factories that create hosted programs in the Tao. There are
// many possible implementations: the factory could create process, it could
// create threads, it could create virtual machines, or it could even create
// Linux components.
class HostedProgramFactory {
 public:
  virtual ~HostedProgramFactory() {}

  virtual bool Init() { return true; }
  virtual bool Destroy() { return true; }

  virtual bool HashHostedProgram(const string &name, const list<string> &args,
                                 string *child_hash) const = 0;

  // Create a hosted program and pass it channel information. The meaning of
  // each argument depends on the factory implementation.
  //
  // @param name The name of the program to create
  // @param args The arguments to pass to the program
  // @param child_hash The hash of this program (used in the channels)
  // @param parent_channel A channel that can be used to get information the
  // child can use to connect to the parent channel
  // @returns true if hosted-program creation was successful
  virtual bool CreateHostedProgram(const string &name, const list<string> &args,
                                   const string &child_hash,
                                   TaoChannel &parent_channel) const = 0;

  // GetFactoryName returns a string that represents the factory. This can be
  // used for implementing a registry of factories, thought it's not currently
  // used this way in libtao.
  virtual string GetFactoryName() const = 0;
};
}  // namespace tao

#endif  // TAO_HOSTED_PROGRAM_FACTORY_H_
