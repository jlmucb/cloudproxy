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

  virtual bool GetHostedProgramTentativeName(
      int id, const string &path, const list<string> &args,
      string *tentative_child_name) const;

  virtual bool CreateHostedProgram(int id, const string &name,
                                   const list<string> &args,
                                   const string &tentative_child_name,
                                   TaoChannel *parent_channel,
                                   string *child_name) const;

  virtual string GetFactoryName() const;

  virtual bool ParseChildName(string child_name, int *id, string *path,
                              string *prog_hash, string *arg_hash, string *pid,
                              string *subprin) const;

 protected:
  virtual string CreateChildName(int id, const string &path,
                                 const string &prog_hash,
                                 const string &arg_hash, string pid) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProcessFactory);
};
}  // namespace tao

#endif  // TAO_PROCESS_FACTORY_H_
