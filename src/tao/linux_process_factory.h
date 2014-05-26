//  File: linux_process_factory.h
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
#ifndef TAO_LINUX_PROCESS_FACTORY_H_
#define TAO_LINUX_PROCESS_FACTORY_H_

#include <list>
#include <string>

#include "tao/util.h"

namespace tao {
using std::list;
using std::string;

class PipeFactory;
class FDMessageChannel;

/// A struct to hold data about a hosted process.
struct HostedLinuxProcess {
  string subprin;
  int pid;
  scoped_ptr<FDMessageChannel> rpc_channel;
};

/// A factory that creates hosted programs as processes. It forks and execs the
/// hosted program, making sure to clean up host state before exec.
class LinuxProcessFactory {
 public:
  LinuxProcessFactory() {}
  virtual ~LinuxProcessFactory() {}

  virtual bool MakeHostedProgramSubprin(int id, const string &path,
                                        string *subprin) const;

  virtual bool StartHostedProgram(const PipeFactory &child_channel_factory,
                                  const string &path, const list<string> &args,
                                  const string &subprin,
                                  scoped_ptr<HostedLinuxProcess> *child) const;

  virtual bool StopHostedProgram(HostedLinuxProcess *child, int signum) const;

  virtual int WaitForHostedProgram() const;

  virtual string FormatHostedProgramSubprin(int id,
                                            const string &prog_hash) const;

  virtual bool ParseHostedProgramSubprin(const string &subprin, int *id,
                                         string *prog_hash,
                                         string *extension) const;

 protected:
  static bool CloseAllFileDescriptorsExcept(const list<int> &keep_open);

 private:
  DISALLOW_COPY_AND_ASSIGN(LinuxProcessFactory);
};
}  // namespace tao

#endif  // TAO_LINUX_PROCESS_FACTORY_H_
