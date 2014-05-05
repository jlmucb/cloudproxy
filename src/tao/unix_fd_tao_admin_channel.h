//  File: unix_fd_tao_admin_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The parent class for admin channel classes that communicate
//  over Unix file descriptors.
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

#ifndef TAO_UNIX_FD_TAO_ADMIN_CHANNEL_H_
#define TAO_UNIX_FD_TAO_ADMIN_CHANNEL_H_

#include "tao/tao_admin_channel.h"
#include "tao/util.h"

namespace tao {
/// A channel that communicates with a host Tao using a pair of file
/// descriptors: one that is used to write to the host, and one that is used to
/// read responses from the host. These can be the same file descriptor.
/// The caller is responsible for ensuring that the descriptors are closed
/// correctly: this class doesn't know if it should close both file descriptors
/// or only one.
class UnixFdTaoAdminChannel : public TaoAdminChannel {
 public:
  /// The empty constructor: used by derived classes that set readfd_ and
  /// writefd_ later.
  UnixFdTaoAdminChannel() : readfd_(-1), writefd_(-1) {}

  /// The constructor used to set readfd and writefd directly.
  /// @param readfd The file descriptor to use for reading messages to the Tao.
  /// @param writefd The file descriptor to use for writing messages to the Tao.
  UnixFdTaoAdminChannel(int readfd, int writefd)
      : readfd_(readfd), writefd_(writefd) {}
  virtual ~UnixFdTaoAdminChannel() {}

 protected:
  virtual bool SendRPC(const TaoAdminRequest &rpc) const {
    return SendMessage(writefd_, rpc);
  }
  virtual bool ReceiveRPC(TaoAdminResponse *resp, bool *eof) const {
    return ReceiveMessage(readfd_, resp, eof);
  }

  int readfd_;
  int writefd_;

 private:
  DISALLOW_COPY_AND_ASSIGN(UnixFdTaoAdminChannel);
};
}  // namespace tao

#endif  // TAO_UNIX_FD_TAO_ADMIN_CHANNEL_H_
