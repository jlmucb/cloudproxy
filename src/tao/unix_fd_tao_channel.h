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
  mutable std::mutex data_m_;

  /// A mutex for setting up and removing the sockets.
  std::mutex socket_m_;

  /// The path to the Unix domain socket for administrative requests.
  string domain_socket_path_;

  /// The open file descriptor for the Unix domain socket that accepts
  /// connections over which administrative requests will be received.
  ScopedFd domain_socket_;

  /// A list of file descriptors accepted from domain_socket_.
  std::list<int> domain_descriptors_;

  /// A map from a child hash to a pair of file descriptors. The first file
  /// descriptor is the read descriptor, and the second descriptor is the write
  /// descriptor. These can be the same descriptor.
  std::map<string, std::pair<int, int>> descriptors_;

  /// Handle incoming messages on the channel.
  /// @param tao The Tao implementation that handles the message.
  /// @param hash The hash of the hosted program that sent the message,
  /// or emptystring for the administrative channel.
  /// @param fd The file descriptor to send the reply to if hash is emptystring,
  /// ignored otherwise.
  /// @param rpc The RPC containing the received message.
  /// @param[out] request_shutdown Set to true on shutdown request.
  /// @param[out] remove_child_hash Hash of a child to be removed by caller.
  virtual bool HandleRPC(Tao &tao, const string &hash,  // NOLINT
                         int fd, const TaoChannelRPC &rpc,
                         bool *requests_shutdown);

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
  /// @param rpc The message containing program start parameters.
  /// @param tao The host tao.
  /// @param[out] identifier The identifier of the new host program.
  bool HandleProgramCreation(const TaoChannelRPC &rpc, Tao *tao,
                             string *identifier);

  /// Remove from descriptors_ any programs that have encountered errors.
  bool CleanErasedPrograms();

  /// Programs that have encountered errors and need to be cleaned up.
  std::list<string> programs_to_erase_;

  DISALLOW_COPY_AND_ASSIGN(UnixFdTaoChannel);
};
}  // namespace tao

#endif  // TAO_UNIX_FD_TAO_CHANNEL_H_
