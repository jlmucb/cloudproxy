//  File: pipe_factory.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A factory for creating FDMessageChannels over pipes.
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
#include "tao/pipe_factory.h"

#include <fcntl.h>
#include <unistd.h>

#include <glog/logging.h>

namespace tao {

bool PipeFactory::CreateChannelPair(
    unique_ptr<FDMessageChannel> *channel_to_parent,
    unique_ptr<FDMessageChannel> *channel_to_child) const {
  int down_pipe[2];
  if (pipe(down_pipe)) {
    LOG(ERROR) << "Could not create pipe";
    return false;
  }
  int up_pipe[2];
  if (pipe(up_pipe)) {
    close(down_pipe[0]);
    close(down_pipe[1]);
    LOG(ERROR) << "Could not create pipe";
    return false;
  }
  channel_to_parent->reset(new FDMessageChannel(down_pipe[0], up_pipe[1]));
  channel_to_child->reset(new FDMessageChannel(up_pipe[0], down_pipe[1]));
  return true;
}

}  // namespace tao
