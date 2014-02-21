//  File: pipe_tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of PipeTaoChannel for Tao
//  communication over file descriptors. This mostly relies
//  on the implementation in UnixFdTaoChannel.
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

#include "tao/pipe_tao_channel.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include <glog/logging.h>
#include <keyczar/base/scoped_ptr.h>

#include "tao/pipe_tao_channel_params.pb.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

using std::lock_guard;

namespace tao {
PipeTaoChannel::PipeTaoChannel(const string &socket_path,
                               const string &stop_socket_path)
    : UnixFdTaoChannel(socket_path, stop_socket_path) {}
PipeTaoChannel::~PipeTaoChannel() {}

bool PipeTaoChannel::AddChildChannel(const string &child_hash, string *params) {
  if (params == nullptr) {
    LOG(ERROR) << "Could not write the params to a null string";
    return false;
  }

  // check to make sure this hash isn't already instantiated with pipes
  {
    lock_guard<mutex> l(data_m_);
    auto hash_it = descriptors_.find(child_hash);
    if (hash_it != descriptors_.end()) {
      LOG(ERROR) << "This child has already been instantiated with a channel";
      return false;
    }
  }

  int down_pipe[2];
  if (pipe(down_pipe)) {
    LOG(ERROR) << "Could not create the down pipe for the client";
    return false;
  }

  int up_pipe[2];
  if (pipe(up_pipe)) {
    LOG(ERROR) << "Could not create the up pipe for the client";
    return false;
  }

  // the parent connect reads on the up pipe and writes on the down pipe.
  {
    lock_guard<mutex> l(data_m_);
    descriptors_[child_hash].first = up_pipe[0];
    descriptors_[child_hash].second = down_pipe[1];
  }

  VLOG(2) << "Adding program with digest " << child_hash;
  VLOG(2) << "Pipes for child: " << down_pipe[0] << ", " << up_pipe[1];
  VLOG(2) << "Pipes for parent: " << up_pipe[0] << ", " << down_pipe[1];

  // the child reads on the down pipe and writes on the up pipe
  PipeTaoChannelParams ptcp;
  ptcp.set_readfd(down_pipe[0]);
  ptcp.set_writefd(up_pipe[1]);

  TaoChildChannelParams tccp;
  tccp.set_channel_type(PipeTaoChildChannel::ChannelType());
  string *child_params = tccp.mutable_params();
  if (!ptcp.SerializeToString(child_params)) {
    LOG(ERROR) << "Could not serialize the child params to a string";
    return false;
  }

  if (!tccp.SerializeToString(params)) {
    LOG(ERROR) << "Could not serialize the params to a string";
    return false;
  }

  // Put the child fds in a data structure for later cleanup.
  {
    lock_guard<mutex> l(data_m_);
    child_descriptors_[child_hash].first = down_pipe[0];
    child_descriptors_[child_hash].second = up_pipe[1];
  }

  return true;
}

bool PipeTaoChannel::ChildCleanup(const string &child_hash) {
  {
    // Look up this hash to see if the parent has fds to clean up
    lock_guard<mutex> l(data_m_);
    // The child shouldn't have any of the open pipe descriptors from the
    // parent, including the socket
    close(*domain_socket_);
    close(*stop_socket_);
    for (pair<const string, pair<int, int>> desc : descriptors_) {
      close(desc.second.first);
      close(desc.second.second);
    }
  }

  return true;
}

bool PipeTaoChannel::ParentCleanup(const string &child_hash) {
  {
    lock_guard<mutex> l(data_m_);
    // Look up this hash to see if this child has any params to clean up.
    auto child_it = child_descriptors_.find(child_hash);
    if (child_it == child_descriptors_.end()) {
      LOG(ERROR) << "No child " << child_hash << " for parent clean up";
      return false;
    }

    VLOG(2) << "Closed " << child_it->second.first << " and "
            << child_it->second.second << " in ParentCleanup";
    close(child_it->second.first);
    close(child_it->second.second);

    child_descriptors_.erase(child_it);
  }

  return true;
}

// Pipe channels don't support this kind of update.
bool PipeTaoChannel::UpdateChildParams(const string &child_hash,
                                       const string &params) {
  return false;
}
}  // namespace tao
