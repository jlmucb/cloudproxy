//  File: kvm_unix_tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of KvmUnixTaoChannel for communication with KVM
//  guest machines.
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

#include "tao/kvm_unix_tao_channel.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mutex>
#include <string>
#include <utility>

#include <glog/logging.h>
#include <keyczar/base/scoped_ptr.h>

#include "tao/kvm_unix_tao_channel_params.pb.h"
#include "tao/kvm_unix_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

using std::lock_guard;
using std::mutex;
using std::string;

namespace tao {
KvmUnixTaoChannel::KvmUnixTaoChannel(const string &socket_path)
    : UnixFdTaoChannel(socket_path) {}

KvmUnixTaoChannel::~KvmUnixTaoChannel() {}

bool KvmUnixTaoChannel::AddChildChannel(const string &tentative_child_name,
                                        string *params) {
  if (params == nullptr) {
    LOG(ERROR) << "Could not write the params to a null string";
    return false;
  }

  // Check to make sure this hash isn't already instantiated.
  {
    lock_guard<mutex> l(data_m_);
    auto hash_it = descriptors_.find(tentative_child_name);
    if (hash_it != descriptors_.end()) {
      LOG(ERROR) << "This child has already been instantiated with a channel";
      return false;
    }
  }

  // Add an empty string until we find out which /dev/pts was set up for this.
  {
    string empty;
    lock_guard<mutex> l(data_m_);
    descriptors_[tentative_child_name] = std::make_pair(-1, -1);
  }

  // The name of the channel will always be /dev/vport0p1 on the guest. And the
  // host will have to find out which /dev/pts entry is being used by asking
  // libvirt.
  string file("host_channel");
  KvmUnixTaoChannelParams kutcp;
  kutcp.set_guest_device(file);

  VLOG(2) << tentative_child_name << " will have guest path /dev/virtio-ports/";

  TaoChildChannelParams tccp;
  tccp.set_channel_type(KvmUnixTaoChildChannel::ChannelType());
  string *child_params = tccp.mutable_params();
  if (!kutcp.SerializeToString(child_params)) {
    LOG(ERROR) << "Could not serialize the child params to a string";
    return false;
  }

  if (!tccp.SerializeToString(params)) {
    LOG(ERROR) << "Could not serialize the params to a string";
    return false;
  }

  return true;
}

bool KvmUnixTaoChannel::UpdateChildParams(const string &tentative_child_name,
                                          const string &params) {
  // In this case, the params are just the device name rather than a serialized
  // protobuf, since this is only made as a call from KvmVmFactory directly.

  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = descriptors_.find(tentative_child_name);
    if ((child_it != descriptors_.end()) && (child_it->second.first >= 0)) {
      LOG(ERROR) << "Could not replace an existing channel for "
                 << tentative_child_name;
      return false;
    }

    // Open the file channel to the VM
    int fd = open(params.c_str(), O_RDWR | O_APPEND);
    if (fd < 0) {
      PLOG(ERROR) << "Could not open the local file '" << params << "'";
      return false;
    }

    // In this case, the same file descriptor is used for reading and writing.
    child_it->second.first = fd;
    child_it->second.second = fd;

    // This call from KvmVmFactory happens while the KvmUnixTaoChannel is
    // handling a call to create a hosted program. So, it will pick up this new
    // channel when it loops back to the select statement in Listen.
  }

  return true;
}
}  // namespace tao
