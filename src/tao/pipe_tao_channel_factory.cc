//  File: pipe_tao_channel_factory.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the Tao channel factory that creates a
//  pair of pipes.
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

#include <tao/pipe_tao_channel_factory.h>
#include <tao/pipe_tao_channel.h>

namespace tao {
PipeTaoChannelFactory::PipeTaoChannelFactory() {}

TaoChannel *PipeTaoChannelFactory::CreateTaoChannel() const {
  // create a pipe on which the child can communicate with the Tao
  int pipedown[2];
  int pipeup[2];

  if (pipe(pipedown) != 0) {
    LOG(ERROR) << "Could not create the downward pipe";
    return nullptr;
  }

  if (pipe(pipeup) != 0) {
    LOG(ERROR) << "Could not create the upward pipe";
    return nullptr;
  }
  int parent_fds[2];
  int child_fds[2];

  parent_fds[0] = pipeup[0];
  parent_fds[1] = pipedown[1];

  child_fds[0] = pipedown[0];
  child_fds[1] = pipeup[1];

  return new PipeTaoChannel(parent_fds, child_fds);
}
}  // nanespace tao
