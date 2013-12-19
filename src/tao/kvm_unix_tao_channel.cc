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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/unistd.h>

#include <keyczar/base/scoped_ptr.h>

#include "tao/kvm_unix_tao_channel_params.pb.h"
#include "tao/kvm_unix_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

namespace tao {
KvmUnixTaoChannel::KvmUnixTaoChannel(const string &socket_path)
    : domain_socket_path_(socket_path) {}
KvmUnixTaoChannel::~KvmUnixTaoChannel() {}

bool KvmUnixTaoChannel::AddChildChannel(const string &child_hash,
                                        string *params) {
  if (params == nullptr) {
    LOG(ERROR) << "Could not write the params to a null string";
    return false;
  }

  // Check to make sure this hash isn't already instantiated.
  {
    lock_guard<mutex> l(data_m_);
    auto hash_it = child_hash_to_descriptor_.find(child_hash);
    if (hash_it != child_hash_to_descriptor_.end()) {
      LOG(ERROR) << "This child has already been instantiated with a channel";
      return false;
    }
  }

  // Add an empty string until we find out which /dev/pts was set up for this.
  {
    string empty;
    lock_guard<mutex> l(data_m_);
    pair<string, int> socket_pair;
    socket_pair.first = empty;
    socket_pair.second = -1;
    child_hash_to_descriptor_[child_hash] = socket_pair;
  }

  // The name of the channel will always be /dev/vport0p1 on the guest. And the
  // host will have to find out which /dev/pts entry is being used by asking
  // libvirt.
  string file("host_channel");
  KvmUnixTaoChannelParams kutcp;
  kutcp.set_guest_device(file);

  VLOG(2) << "Adding program with digest " << child_hash << " and guest path "
          << "/dev/virtio-ports/" << file;

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

bool KvmUnixTaoChannel::UpdateChildParams(const string &child_hash,
                                          const string &params) {
  // In this case, the params are just the device name rather than a serialized
  // protobuf, since this is only made as a call from KvmVmFactory directly.

  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = child_hash_to_descriptor_.find(child_hash);
    if ((child_it != child_hash_to_descriptor_.end()) &&
        (!child_it->second.first.empty())) {
      LOG(ERROR) << "Could not replace an existing channel for " << child_hash;
      return false;
    }

    // Open the file channel to the VM
    int fd = open(params.c_str(), O_RDWR | O_APPEND);
    if (fd < 0) {
      PLOG(ERROR) << "Could not open the local file '" << params << "'";
      return false;
    }

    child_it->second.first = params;
    child_it->second.second = fd;

    // This call from KvmVmFactory happens while the KvmUnixTaoChannel is
    // handling a call to create a hosted program. So, it will pick up this new
    // channel when it loops back to the select statement in Listen.
  }

  return true;
}

bool KvmUnixTaoChannel::ReceiveMessage(google::protobuf::Message *m,
                                       const string &child_hash) const {
  // try to receive an integer
  CHECK(m) << "m was null";

  int readfd = 0;
  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = child_hash_to_descriptor_.find(child_hash);
    if (child_it == child_hash_to_descriptor_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    readfd = child_it->second.second;
  }

  if (readfd < 0) {
    LOG(ERROR) << "The readfd for the child hash " << child_hash
               << " has not been set yet";
    return false;
  }

  return tao::ReceiveMessage(readfd, m);
}

bool KvmUnixTaoChannel::SendMessage(const google::protobuf::Message &m,
                                    const string &child_hash) const {
  // send the length then the serialized message
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }

  int writefd = 0;
  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = child_hash_to_descriptor_.find(child_hash);
    if (child_it == child_hash_to_descriptor_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    writefd = child_it->second.second;
  }

  if (writefd < 0) {
    LOG(ERROR) << "The writefd for child hash " << child_hash
               << " has not been set yet";
    return false;
  }

  return tao::SendMessage(writefd, m);
}

bool KvmUnixTaoChannel::Listen(Tao *tao) {
  // The unix domain socket is used to listen for CreateHostedProgram requests.
  int sock = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    LOG(ERROR) << "Could not create unix domain socket to listen for messages";
    return false;
  }

  // Make sure the socket won't block if there's no data available, or not
  // enough data available.
  int fcntl_err = fcntl(sock, F_SETFL, O_NONBLOCK);
  if (fcntl_err == -1) {
    PLOG(ERROR) << "Could not set the socket to be non-blocking";
    return false;
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (domain_socket_path_.size() + 1 > sizeof(addr.sun_path)) {
    LOG(ERROR) << "The path " << domain_socket_path_ << " was too long to use";
    return false;
  }

  strncpy(addr.sun_path, domain_socket_path_.c_str(), sizeof(addr.sun_path));
  int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
  int bind_err = bind(sock, (struct sockaddr *)&addr, len);
  if (bind_err == -1) {
    PLOG(ERROR) << "Could not bind the address " << domain_socket_path_
                << " to the socket";
  }

  LOG(INFO) << "Bound the unix socket to " << domain_socket_path_;

  while (true) {
    // set up the select operation with the current fds and the unix socket
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max = sock;
    FD_SET(sock, &read_fds);

    for (pair<const string, pair<string, int>> &descriptor :
         child_hash_to_descriptor_) {
      int d = descriptor.second.second;
      if (d >= 0) {
        FD_SET(d, &read_fds);
        if (d > max) {
          max = d;
        }
      }
    }

    int err = select(max + 1, &read_fds, NULL, NULL, NULL);
    if (err == -1) {
      PLOG(ERROR) << "Error in calling select";
      return false;
    }

    // Check for messages to handle
    if (FD_ISSET(sock, &read_fds)) {
      if (!HandleProgramCreation(tao, sock)) {
        LOG(ERROR) << "Could not handle the program creation request";
      }
    }

    list<string> programs_to_erase;
    for (pair<const string, pair<string, int>> &descriptor :
         child_hash_to_descriptor_) {
      int d = descriptor.second.second;
      const string &child_hash = descriptor.first;

      if (FD_ISSET(d, &read_fds)) {
        TaoChannelRPC rpc;
        if (!GetRPC(&rpc, child_hash)) {
          LOG(ERROR) << "Could not get an RPC for " << child_hash;
          LOG(ERROR) << "Removing hosted program " << child_hash;
          programs_to_erase.push_back(child_hash);
          continue;
        }

        if (!HandleRPC(*tao, child_hash, rpc)) {
          LOG(ERROR) << "Could not get an RPC for " << child_hash;
          LOG(ERROR) << "Removing hosted program " << child_hash;
          programs_to_erase.push_back(child_hash);
          continue;
        }
      }
    }

    auto pit = programs_to_erase.begin();
    for (; pit != programs_to_erase.end(); ++pit) {
      child_hash_to_descriptor_.erase(*pit);
    }
  }

  return true;
}

bool KvmUnixTaoChannel::HandleProgramCreation(Tao *tao, int sock) {
  TaoChannelRPC rpc;
  if (!tao::ReceiveMessage(sock, &rpc)) {
    LOG(ERROR) << "Could not receive an rpc on the channel";
    return false;
  }

  // This message must be a TaoChannelRPC message, and it must be have the type
  // START_HOSTED_PROGRAM
  if ((rpc.rpc() != START_HOSTED_PROGRAM) || !rpc.has_start()) {
    LOG(ERROR) << "This RPC was not START_HOSTED_PROGRAM";
    return false;
  }

  const StartHostedProgramArgs &shpa = rpc.start();
  list<string> args;
  for (int i = 0; i < shpa.args_size(); i++) {
    args.push_back(shpa.args(i));
  }

  if (!tao->StartHostedProgram(shpa.path(), args)) {
    LOG(ERROR) << "Could not start the program";
    return false;
  }

  return true;
}
}  // namespace tao
