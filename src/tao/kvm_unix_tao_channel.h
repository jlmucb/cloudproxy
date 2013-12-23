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
#include "tao/unix_fd_tao_channel.h"

namespace tao {
// A TaoChannel that communicates over UNIX pipes with KVM guest machines.
class KvmUnixTaoChannel : public UnixFdTaoChannel {
 public:
  // Constructs a KvmUnixTaoChannel with a process creation socket at a given
  // path.
  KvmUnixTaoChannel(const string &socket_path);
  virtual ~KvmUnixTaoChannel();

  // Creates a fresh name for another unix domain socket for a new vm
  virtual bool AddChildChannel(const string &child_hash, string *params);

  // No cleanup needed for either the client or the parent.
  virtual bool ChildCleanup(const string &child_hash) { return true; }
  virtual bool ParentCleanup(const string &child_hash) { return true; }

  virtual bool UpdateChildParams(const string &child_hash,
                                 const string &params);

 private:
  DISALLOW_COPY_AND_ASSIGN(KvmUnixTaoChannel);
};
}

#endif  // TAO_KVM_UNIX_TAO_CHANNEL_H_
