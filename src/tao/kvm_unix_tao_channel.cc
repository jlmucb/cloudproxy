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
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

// TODO(tmroeder): catch SIGPIPE so that dying subprocesses don't kill us.
namespace tao {
KvmUnixTaoChannel::KvmUnixTaoChannel(const string &socket_path)
    : domain_socket_path_(socket_path) {}
KvmUnixTaoChannel::~KvmUnixTaoChannel() {}

bool KvmUnixTaoChannel::AddChildChannel(const string &child_hash, string *params) {
  if (params == nullptr) {
    LOG(ERROR) << "Could not write the params to a null string";
    return false;
  }

  // Check to make sure this hash isn't already instantiated.
  {
    lock_guard<mutex> l(data_m_);
    auto hash_it = child_hash_to_socket_.find(child_hash);
    if (hash_it != child_hash_to_socket_.end()) {
      LOG(ERROR) << "This child has already been instantiated with a channel";
      return false;
    }
  }

  // Create a random temp file name to use as the socket.
  char tempfile[] = "/tmp/kvm_unix_tao_channel_XXXXXX";
  if (mktemp(tempfile) == nullptr) {
    PLOG(ERROR) << "Could not create a temporary filename for the KVM channel";
    return false;
  }

  string file(tempfile);

  {
    lock_guard<mutex> l(data_m_);
    pair<string, int> socket_pair;
    socket_pair.first = file;
    socket_pair.second = -1;
    child_hash_to_socket_[child_hash] = socket_pair;
  }

  VLOG(2) << "Adding program with digest " << child_hash << " and path "
          << file;

  KvmUnixTaoChannelParams kutcp;
  kutcp.set_unix_socket_path(tempfile);
  kutcp.set_target_port(1);

  TaoChildChannelParams tccp;
  tccp.set_channel_type("KvmUnixTaoChannel");
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

bool KvmUnixTaoChannel::ReceiveMessage(google::protobuf::Message *m,
                                    const string &child_hash) const {
  // try to receive an integer
  CHECK(m) << "m was null";

  int readfd = 0;
  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = child_hash_to_socket_.find(child_hash);
    if (child_it == child_hash_to_socket_.end()) {
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
  
  LOG(INFO) << "Got fd " << readfd << " for child " << child_hash;
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
    auto child_it = child_hash_to_socket_.find(child_hash);
    if (child_it == child_hash_to_socket_.end()) {
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

  LOG(INFO) << "Got fd " << writefd << " for child " << child_hash;
  return tao::SendMessage(writefd, m);
}

bool KvmUnixTaoChannel::ConnectToUnixSocket(const string &path, int *s) const {
  if (s == nullptr) {
    LOG(ERROR) << "Parameter s was null";
    return false;
  }

  *s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (*s == -1) {
    PLOG(ERROR) << "Could not create a Unix domain socket for " << path;
    return false;
  }

  // TODO(tmroeder): add timeout here so that malicious clients can't cause
  // denial of service.
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    LOG(ERROR) << "The path " << path << " was too long to use";
    return false;
  }

  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
  //int len = sizeof(addr.sun_family) + strlen(addr.sun_path);
  int connect_err = connect(*s, (struct sockaddr *)&addr, sizeof(addr));
  if (connect_err == -1) {
    PLOG(ERROR) << "Could not connect to the socket " << path;
    return false;
  }

  return true;
}

bool KvmUnixTaoChannel::Listen(Tao *tao) {
  // The unix domain socket is used to listen for CreateHostedProgram requests.
  int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
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
  //int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
  int bind_err = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
  if (bind_err == -1) {
    PLOG(ERROR) << "Could not bind the address " << domain_socket_path_
                << " to the socket";
  }

  LOG(INFO) << "Bound the unix socket to " << domain_socket_path_;
  LOG(INFO) << "The file descriptor is " << sock;

  while (true) {
    // set up the select operation with the current fds and the unix socket
    LOG(INFO) << "zeroing read_fds";
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max = sock;
    FD_SET(sock, &read_fds);

    for (pair<const string, pair<string, int>> &descriptor :
         child_hash_to_socket_) {
      int d = descriptor.second.second;
      if (d >= 0) {
        FD_SET(d, &read_fds);
        if (d > max) {
          max = d;
        }
      }
    }

    LOG(INFO) << "Waiting on select with max " << (int)max;
    int err = select(max + 1, &read_fds, NULL, NULL, NULL);
    LOG(INFO) << "select returned";
    if (err == -1) {
      PLOG(ERROR) << "Error in calling select";
      return false;
    }

    // Check for messages to handle
    if (FD_ISSET(sock, &read_fds)) {
      LOG(INFO) << "Handling a program creation request";
      if (!HandleProgramCreation(tao, sock)) {
        LOG(ERROR) << "Could not handle the program creation request";
      }
    }

    list<string> programs_to_erase;
    for (pair<const string, pair<string, int>> &descriptor :
         child_hash_to_socket_) {
      int d = descriptor.second.second;
      const string &child_hash = descriptor.first;
      LOG(INFO) << "Considering descriptor " << d;

      if (FD_ISSET(d, &read_fds)) {
        TaoChannelRPC rpc;
	LOG(INFO) << "Getting RPC";
        if (!GetRPC(&rpc, child_hash)) {
          LOG(ERROR) << "Could not get an RPC. Removing child " << child_hash;
          programs_to_erase.push_back(child_hash);
          continue;
        }
	LOG(INFO) << "Got RPC, handling it";

        if (!HandleRPC(*tao, child_hash, rpc)) {
          LOG(ERROR) << "Could not handle the RPC. Removing child "
            << child_hash;
          programs_to_erase.push_back(child_hash);
          continue;
        }
	LOG(INFO) << "Finished handling RPC";
      } else {
        LOG(INFO) << "It's not set";
      }
    }

    LOG(INFO) << "Done with loop check";

    auto pit = programs_to_erase.begin();
    for (; pit != programs_to_erase.end(); ++pit) {
      LOG(INFO) << "Erasing " << *pit;
      child_hash_to_socket_.erase(*pit);
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

  for (pair<const string, pair<string, int>> &child : child_hash_to_socket_) {
    // Connect to all the sockets so far
    string path = child.second.first;
    int s = -1;
    // If we can't connect, then go on. We'll try again when another child is
    // added, if ever
    if (!ConnectToUnixSocket(path, &s)) {
      LOG(ERROR) << "Could not connect to child " << child.first
                 << " using socket " << child.second.first;
    } else {
      child.second.second = s;
    }
  }

  if (!tao->StartHostedProgram(shpa.path(), args)) {
    LOG(ERROR) << "Could not start the program";
    return false;
  }

  // attach to any channels that have been added
  for (pair<const string, pair<string, int>> &descriptor :
       child_hash_to_socket_) {
    if (descriptor.second.second == -1) {
      string path(descriptor.second.first);
      int s = -1;
      if (!ConnectToUnixSocket(path, &s)) {
	LOG(ERROR) << "Could not connect to the unix socket associated with the path " << path;
	continue;
      }

      descriptor.second.second = s;
    }
  }

  return true;
}
}  // namespace tao
