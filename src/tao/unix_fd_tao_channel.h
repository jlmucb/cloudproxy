//  File: unix_fd_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: UnixFdTaoChannel is a parent class that captures the common
//  operations for managing hosted programs through file descriptors.
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

#ifndef TAO_UNIX_FD_TAO_CHANNEL_H_
#define TAO_UNIX_FD_TAO_CHANNEL_H_

#include <list>
#include <map>
#include <mutex>
#include <string>
#include <utility>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel.h"
#include "tao/util.h"

namespace tao {
/// A TaoChannel that communicates over file descriptors set up with pipe(2) or
/// libvirt and listens to multiple connections with select. This
/// class does not implementation all the TaoChannel methods; it contains all
/// the file descriptor listening logic, and subclasses add methods for creating
/// and managing specific kinds of channels.
class UnixFdTaoChannel : public TaoChannel {
 public:
  /// Construct a UnixFdTaoChannel.
  /// @param socket_path Location to create a Unix domain socket for handling
  /// administrative requests.
  explicit UnixFdTaoChannel(const string &socket_path);
  virtual ~UnixFdTaoChannel();

  /// Create the sockets specified by the constructor.
  virtual bool Init();

  /// Listen on all open channels and on the Unix domain socket for RPCs from
  /// hosted or administrative programs. This method returns when
  /// either a SIGTERM signal is received or when a SHUTDOWN request is
  /// received from a child.
  /// @param tao The Tao to handle hosted-program RPCs.
  virtual bool Listen(Tao *tao);

  /// Close the sockets created in Init.
  virtual bool Destroy();

 protected:
  /// A mutex for protecting access to descriptors.
  /// TODO(kwalsh) - This is used inconsistently and should be removed.
  mutable std::mutex data_m_;

  /// A mutex for setting up and removing the sockets.
  /// TODO(kwalsh) - This is used inconsistently and should be removed.
  std::mutex socket_m_;

  /// The path to the Unix domain socket for administrative requests.
  string admin_socket_path_;

  /// The open file descriptor for the Unix domain socket that accepts
  /// connections over which administrative requests will be received.
  ScopedFd admin_socket_;

  /// A list of file descriptors accepted from admin_socket_.
  std::list<int> admin_descriptors_;

  /// A map from a child hash to a pair of file descriptors. The first file
  /// descriptor is the read descriptor, and the second descriptor is the write
  /// descriptor. These can be the same descriptor.
  std::map<string, std::pair<int, int>> descriptors_;

 private:
  DISALLOW_COPY_AND_ASSIGN(UnixFdTaoChannel);
};
}  // namespace tao

#endif  // TAO_UNIX_FD_TAO_CHANNEL_H_
