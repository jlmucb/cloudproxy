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

#include <map>
#include <mutex>
#include <string>
#include <utility>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel.h"
#include "tao/util.h"

using std::map;
using std::mutex;
using std::pair;

namespace tao {
/// A TaoChannel that communicates over file descriptors
/// set up with pipe(2) and listens to multiple connections with select. This
/// class does not implementation all the TaoChannel methods; it contains all
/// the file descriptor listening logic, and subclasses add methods for creating
/// and managing specific kinds of channels.
class UnixFdTaoChannel : public TaoChannel {
 public:
  /// Construct a UnixFdTaoChannel with a process creation socket at a given
  /// path.
  /// @param socket_path A path at which to create a Unix domain socket.
  /// @param stop_socket_path A path at which to create a Unix domain socket
  /// used to stop the channel.
  UnixFdTaoChannel(const string &socket_path, const string &stop_socket_path);
  virtual ~UnixFdTaoChannel();

  /// Listen on all open channels and the Unix domain socket for hosted-program
  /// creation requests and RPCs from hosted programs.
  /// @param tao The Tao to handle RPCs.
  virtual bool Listen(Tao *tao);

  /// Create the sockets specified by the constructor.
  virtual bool Init();

  /// Remove the sockets created in init.
  virtual bool Destroy();

 protected:
  // A mutex for protecting access to descriptors.
  mutable mutex data_m_;

  // A mutex for setting up and removing the sockets.
  mutex socket_m_;

  // The path to the Unix domain socket that manages requests to stop.
  string stop_socket_path_;

  // The open file descriptor for the Unix domain socket that receives
  // requests to stop the listen operation.
  ScopedFd stop_socket_;

  // The path to the Unix domain socket that manages program creation requests.
  string domain_socket_path_;

  // The open file descriptor for the Unix domain socket that receives
  // hosted-program creation requests.
  ScopedFd domain_socket_;

  // A map from a child hash to a pair of file descriptors. The first file
  // descriptor is the read descriptor, and the second descriptor is the write
  // descriptor. These can be the same descriptor.
  map<string, pair<int, int>> descriptors_;

  /// Receive a message by performing a read() on a file descriptor.
  /// @param[out] m The received message
  /// @param child_hash The hash of the child to receive the message from. This
  /// is used to decide which descriptor to use.
  virtual bool ReceiveMessage(google::protobuf::Message *m,
                              const string &child_hash) const;

  /// Send a message to a hosted program by performing a write() on a file
  /// descriptor.
  /// @param m The message to send.
  /// @param child_hash The hash of the child to send the message to. This is
  /// used to decide which descriptor to use.
  virtual bool SendMessage(const google::protobuf::Message &m,
                           const string &child_hash) const;

 private:
  /// Receive a datagram message on a unix socket and uses this information to
  /// create a hosted program through the Tao.
  bool HandleProgramCreation(Tao *tao, int sock, string *identifier,
                             struct sockaddr *addr, socklen_t *addr_len);

  /// Handle messages from a hosted program.
  /// @param tao The Tao implementation that will handle the message.
  /// @param child_hash The hosted program that send the message.
  bool MessageHandler(Tao *tao, const string &child_hash);

  DISALLOW_COPY_AND_ASSIGN(UnixFdTaoChannel);
};
}  // namespace tao

#endif  // TAO_UNIX_FD_TAO_CHANNEL_H_
