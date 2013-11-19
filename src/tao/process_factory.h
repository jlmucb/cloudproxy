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

#include "tao/hosted_program_factory.h"

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <list>
#include <string>

using std::list;
using std::string;

namespace tao {
class ProcessFactory : public HostedProgramFactory {
 public:
  ProcessFactory() {}
  virtual ~ProcessFactory() {}
  virtual bool CreateHostedProgram(const string &name,
				   const list<string> &args,
                                   const string &child_hash,
				   TaoChannel &parent_channel) const;
  virtual string GetFactoryName() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProcessFactory);
};
}  // namespace tao

#endif  // TAO_PROCESS_FACTORY_H_
