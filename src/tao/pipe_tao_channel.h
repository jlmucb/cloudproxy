//  File: pipe_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: PipeTaoChannel implements Tao communication over pipes.
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

#ifndef TAO_PIPE_TAO_CHANNEL_H_
#define TAO_PIPE_TAO_CHANNEL_H_

#include <map>
#include <mutex>
#include <string>
#include <utility>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel.h"
#include "tao/unix_fd_tao_channel.h"

namespace tao {
/// A TaoChannel that communicates over file descriptors
/// set up with pipe(2) and listens to multiple connections with select.
class PipeTaoChannel : public UnixFdTaoChannel {
 public:
  /// Construct a PipeTaoChannel.
  /// @param socket_path Location to create a Unix domain socket for handling
  /// administrative requests.
  explicit PipeTaoChannel(const string &socket_path);
  virtual ~PipeTaoChannel();

  /// Serialize the child_fds into a PipeTaoChannelParams protobuf.
  virtual bool AddChildChannel(const string &child_hash, string *params);

  /// Close all the file descriptors that don't belong to the child. This is
  /// used, e.g., after a fork() in ProcessFactory.
  virtual bool ChildCleanup(const string &child_hash);

  /// Close all the file descriptors that don't belong to the parent. This is
  /// used, e.g., after a fork() in ProcessFactory.
  virtual bool ParentCleanup(const string &child_hash);

  /// This method isn't used by PipeTaoChannel, since the params for the channel
  /// are already known when the pipes are created.
  /// @return true
  virtual bool UpdateChildParams(const string &child_hash,
                                 const string &params);

 private:
  // A set of child descriptors that haven't been cleaned up yet.
  std::map<string, std::pair<int, int>> child_descriptors_;

  DISALLOW_COPY_AND_ASSIGN(PipeTaoChannel);
};
}  // namespace tao

#endif  // TAO_PIPE_TAO_CHANNEL_H_
