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

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel.h"

using std::map;
using std::mutex;
using std::pair;

namespace tao {
// A TaoChannel that communicates over file descriptors
// set up with pipe(2) and listens to multiple connections with select.
class UnixFdTaoChannel : public TaoChannel {
 public:
  // Constructs a UnixFdTaoChannel with a process creation socket at a given
  // path.
  UnixFdTaoChannel(const string &socket_path);
  virtual ~UnixFdTaoChannel();

  virtual bool Listen(Tao *tao);

  // Serializes the child_fds into a UnixFdTaoChannelParams protobuf.
  virtual bool AddChildChannel(const string &child_hash, string *params) = 0;
  virtual bool ChildCleanup(const string &child_hash) = 0;
  virtual bool ParentCleanup(const string &child_hash) = 0;

  virtual bool UpdateChildParams(const string &child_hash,
                                 const string &params) = 0;

 protected:
  // A mutex for protecting access to descriptors_.
  mutable mutex data_m_;

  // The path to the Unix domain socket that manages program creation requests.
  string domain_socket_path_;

  // A map from a child hash to a pair of file descriptors. The first file
  // descriptor is the read descriptor, and the second descriptor is the write
  // descriptor. These can be the same descriptor.
  map<string, pair<int, int>> descriptors_;

  virtual bool ReceiveMessage(google::protobuf::Message *m,
                              const string &child_hash) const;
  virtual bool SendMessage(const google::protobuf::Message &m,
                           const string &child_hash) const;

 private:
  // Receives a datagram message on a unix socket and uses this information to
  // create a hosted program through the Tao.
  bool HandleProgramCreation(Tao *tao, int sock);

  // A loop that listens for messages on a given file descriptor.
  // TODO(tmroeder): Convert this into a set of threads that spin up when a new
  // Listen comes in and merge their select() operations whenever possible.
  bool MessageHandler(Tao *tao, const string &child_hash);

  DISALLOW_COPY_AND_ASSIGN(UnixFdTaoChannel);
};
}

#endif  // TAO_UNIX_FD_TAO_CHANNEL_H_
