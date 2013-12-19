//  File: kvm_unix_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: KvmUnixTaoChannel implements a KVM Guest communication
//  mechanism through a serial device in the guest (/dev/ttyS0) connected to a
//  unix domain socket in the host filesystem.
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

#ifndef TAO_KVM_UNIX_TAO_CHANNEL_H_
#define TAO_KVM_UNIX_TAO_CHANNEL_H_

#include <map>
#include <mutex>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel.h"

using std::lock_guard;
using std::map;
using std::mutex;
using std::pair;

namespace tao {
// A TaoChannel that communicates over UNIX pipes with KVM guest machines.
class KvmUnixTaoChannel : public TaoChannel {
 public:
  // Constructs a KvmUnixTaoChannel with a process creation socket at a given
  // path.
  KvmUnixTaoChannel(const string &socket_path);
  virtual ~KvmUnixTaoChannel();

  virtual bool Listen(Tao *tao);

  // Creates a fresh name for another unix domain socket for a new vm
  virtual bool AddChildChannel(const string &child_hash, string *params);

  // No cleanup needed for either the client or the parent.
  virtual bool ChildCleanup(const string &child_hash) { return true; }
  virtual bool ParentCleanup(const string &child_hash) { return true; }

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
  map<string, pair<string, int>> child_hash_to_descriptor_;

  // Receives a datagram message on a unix socket and uses this information to
  // create a hosted program through the Tao.
  bool HandleProgramCreation(Tao *tao, int sock);

  // A loop that listens for messages on a given file descriptor.
  // TODO(tmroeder): Convert this into a set of threads that spin up when a new
  // Listen comes in and merge their select() operations whenever possible.
  bool MessageHandler(Tao *tao, const string &child_hash);

  DISALLOW_COPY_AND_ASSIGN(KvmUnixTaoChannel);
};
}

#endif  // TAO_KVM_UNIX_TAO_CHANNEL_H_
