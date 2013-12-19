//  File: pipe_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: PipeTaoChannel implements Tao communication over file
//  descriptors
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

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel.h"

using std::lock_guard;
using std::map;
using std::mutex;
using std::pair;

namespace tao {
// a TaoChannel that communicates over file descriptors
// set up with pipe(2) and listens to multiple connections with select.
class PipeTaoChannel : public TaoChannel {
 public:
  // Constructs a PipeTaoChannel with a process creation socket at a given path
  PipeTaoChannel(const string &socket_path);
  virtual ~PipeTaoChannel();

  virtual bool Listen(Tao *tao);

  // Serializes the child_fds into a PipeTaoChannelParams protobuf.
  virtual bool AddChildChannel(const string &child_hash, string *params);
  virtual bool ChildCleanup(const string &child_hash);
  virtual bool ParentCleanup(const string &child_hash);

  virtual bool UpdateChildParams(const string &child_hash,
                                 const string &params);

 protected:
  virtual bool ReceiveMessage(google::protobuf::Message *m,
                              const string &child_hash) const;
  virtual bool SendMessage(const google::protobuf::Message &m,
                           const string &child_hash) const;

 private:
  string domain_socket_path_;
  mutable mutex data_m_;
  map<string, pair<int, int>> hash_to_descriptors_;
  map<string, pair<int, int>> child_descriptors_;

  // Receives a datagram message on a unix socket and uses this information to
  // create a hosted program through the Tao.
  bool HandleProgramCreation(Tao *tao, int sock);

  // A loop that listens for messages on a given file descriptor.
  // TODO(tmroeder): Convert this into a set of threads that spin up when a new
  // Listen comes in and merge their select() operations whenever possible.
  bool MessageHandler(Tao *tao, const string &child_hash);

  DISALLOW_COPY_AND_ASSIGN(PipeTaoChannel);
};
}

#endif  // TAO_PIPE_TAO_CHANNEL_H_
