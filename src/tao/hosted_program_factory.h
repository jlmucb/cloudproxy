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

class HostedProgramFactory {
 public:
  virtual ~HostedProgramFactory() {}
  virtual bool CreateHostedProgram(const string &name, const list<string> &args,
                                   TaoChannel &parent_channel) const = 0;
  virtual string GetFactoryName() const = 0;
};
} // namespace tao

#endif // TAO_HOSTED_PROGRAM_FACTORY_H_
