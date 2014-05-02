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
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_channel.h"
#include "tao/unix_fd_tao_channel.h"

namespace tao {
/// A TaoChannel that communicates over UNIX file descriptors with KVM guest
/// machines. It uses a channel set up by libvirt and virtio_console in the
/// guest.
class KvmUnixTaoChannel : public UnixFdTaoChannel {
 public:
  /// Construct a KvmUnixTaoChannel.
  /// @param socket_path Location to create a Unix domain socket for handling
  /// administrative requests.
  explicit KvmUnixTaoChannel(const string &socket_path);
  virtual ~KvmUnixTaoChannel();

  virtual bool AddChildChannel(const string &tentative_child_name,
                               string *params);

  // No cleanup needed for either the client or the parent.
  virtual bool ChildCleanup(const string &params, const string &subprin) {
    return true;
  }
  virtual bool ParentCleanup(const string &tentative_child_name) {
    return true;
  }

  virtual bool UpdateChildParams(const string &tentative_child_name,
                                 const string &params);

 private:
  DISALLOW_COPY_AND_ASSIGN(KvmUnixTaoChannel);
};
}  // namespace tao

#endif  // TAO_KVM_UNIX_TAO_CHANNEL_H_
