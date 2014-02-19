//  File: pipe_tao_child_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The hosted program interface for the PipeTaoChannel
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

#ifndef TAO_PIPE_TAO_CHILD_CHANNEL_H_
#define TAO_PIPE_TAO_CHILD_CHANNEL_H_

#include "tao/unix_fd_tao_child_channel.h"

namespace tao {
/// The channel a hosted program running as a process uses to communicate with
/// its host Tao. The params in the constructor specify a pair of pipes that are
/// connected to the host.
class PipeTaoChildChannel : public UnixFdTaoChildChannel {
 public:
  PipeTaoChildChannel(const string &params);
  virtual ~PipeTaoChildChannel() {}

  /// Parse the params from the constructor and try to open the pipes for host
  /// Tao communication.
  virtual bool Init();

  static string ChannelType() { return "PipeTaoChannel"; }

 private:

  // A Base64W-encoded representation of the two pipes.
  string params_;

  DISALLOW_COPY_AND_ASSIGN(PipeTaoChildChannel);
};
}  // namespace tao

#endif  // TAO_PIPE_TAO_CHILD_CHANNEL_H_
