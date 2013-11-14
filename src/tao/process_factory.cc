//  File: process_factory.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the hosted program factory that creates
//  processes.
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

#include <tao/process_factory.h>
#include <tao/tao_channel.h>
#include <vector>

using std::vector;

namespace tao {
bool ProcessFactory::CreateHostedProgram(const string &name,
                                         const list<string> &args,
					 TaoChannel &parent_channel) const {
  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork";
    return false;
  }

  if (child_pid == 0) {
    string child_channel_info;
    if (!parent_channel.GetChildParams(&child_channel_info)) {
      LOG(ERROR) << "Could not get the child parameters for this parent channel";
      return false;
    }

    parent_channel.ChildCleanup();

    vector<char> name_vec(name.begin(), name.end());
    list<vector<char>> new_args(args.size());
    new_args.push_back(name_vec);

    for (const string &s : args) {
      vector<char> v(s.begin(), s.end());
      new_args.push_back(v);
    }

    vector<char> child_vec(child_channel_info.begin(), child_channel_info.end());
    new_args.push_back(child_vec);

    scoped_array<char *> argv(new char *[args.size() + 2]);
    int i = 0;
    for (vector<char> &v : new_args) {
      argv[i++] = v.data();
    }

    argv[i] = nullptr;

    int rv = execv(name.c_str(), argv.get());
    if (rv == -1) {
      LOG(ERROR) << "Could not exec " << name;
      return false;
    }
  } else {
    parent_channel.ParentCleanup();
  }

  return true;
}

string ProcessFactory::GetFactoryName() const {
  return "ProcessFactory";
}
} // namespace tao
