//  File: pipe_tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of the child side of PipeTaoChannel
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
#include "tao/pipe_tao_child_channel.h"

#include <string>

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "tao/pipe_tao_channel_params.pb.h"
#include "tao/tao_child_channel_params.pb.h"

namespace tao {
PipeTaoChildChannel::PipeTaoChildChannel(const string &params)
    : UnixFdTaoChildChannel(), params_(params) {}

bool PipeTaoChildChannel::Init() {
  // Parse the params into the file descriptors for reading and writing.
  TaoChildChannelParams tccp;
  if (!tccp.ParseFromString(params_)) {
    LOG(ERROR) << "Could not parse the child params";
    return false;
  }

  PipeTaoChannelParams ptcp;
  if (!ptcp.ParseFromString(tccp.params())) {
    LOG(ERROR) << "Could not parse the pipe file descriptors from the params";
    return false;
  }

  readfd_ = ptcp.readfd();
  writefd_ = ptcp.writefd();

  return true;
}
}  // namespace tao
