//  File: pipe_tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of PipeTaoChannel for Tao
//  communication over file descriptors
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

#include "tao/pipe_tao_channel.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/unistd.h>

#include <thread>

#include <keyczar/base/scoped_ptr.h>

#include "tao/pipe_tao_channel_params.pb.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

using std::thread;

namespace tao {
PipeTaoChannel::PipeTaoChannel(const string &socket_path)
    : domain_socket_path_(socket_path) {}
PipeTaoChannel::~PipeTaoChannel() {}

bool PipeTaoChannel::AddChildChannel(const string &child_hash, string *params) {
  if (params == nullptr) {
    LOG(ERROR) << "Could not write the params to a null string";
    return false;
  }

  // check to make sure this hash isn't already instantiated with pipes
  {
    lock_guard<mutex> l(data_m_);
    auto hash_it = hash_to_descriptors_.find(child_hash);
    if (hash_it != hash_to_descriptors_.end()) {
      LOG(ERROR) << "This child has already been instantiated with a channel";
      return false;
    }
  }

  int down_pipe[2];
  if (pipe(down_pipe)) {
    LOG(ERROR) << "Could not create the down pipe for the client";
    return false;
  }

  int up_pipe[2];
  if (pipe(up_pipe)) {
    LOG(ERROR) << "Could not create the up pipe for the client";
    return false;
  }

  // the parent connect reads on the up pipe and writes on the down pipe.
  {
    lock_guard<mutex> l(data_m_);
    hash_to_descriptors_[child_hash].first = up_pipe[0];
    hash_to_descriptors_[child_hash].second = down_pipe[1];
  }

  VLOG(2) << "Adding program with digest " << child_hash;
  VLOG(2) << "Pipes for child: " << down_pipe[0] << ", " << up_pipe[1];
  VLOG(2) << "Pipes for parent: " << up_pipe[0] << ", " << down_pipe[1];

  // the child reads on the down pipe and writes on the up pipe
  PipeTaoChannelParams ptcp;
  ptcp.set_readfd(down_pipe[0]);
  ptcp.set_writefd(up_pipe[1]);

  TaoChildChannelParams tccp;
  tccp.set_channel_type(PipeTaoChildChannel::ChannelType());
  string *child_params = tccp.mutable_params();
  if (!ptcp.SerializeToString(child_params)) {
    LOG(ERROR) << "Could not serialize the child params to a string";
    return false;
  }

  if (!tccp.SerializeToString(params)) {
    LOG(ERROR) << "Could not serialize the params to a string";
    return false;
  }

  // Put the child fds in a data structure for later cleanup.
  {
    lock_guard<mutex> l(data_m_);
    child_descriptors_[child_hash].first = down_pipe[0];
    child_descriptors_[child_hash].second = up_pipe[1];
  }

  return true;
}

bool PipeTaoChannel::ChildCleanup(const string &child_hash) {
  {
    // Look up this hash to see if the parent has fds to clean up
    lock_guard<mutex> l(data_m_);
    auto child_it = hash_to_descriptors_.find(child_hash);
    if (child_it == hash_to_descriptors_.end()) {
      LOG(ERROR) << "No parent descriptors to clean up";
      return false;
    }

    VLOG(2) << "Closed " << child_it->second.first << " and "
            << child_it->second.second << " in ChildCleanup";
    close(child_it->second.first);
    close(child_it->second.second);

    hash_to_descriptors_.erase(child_it);
  }

  return true;
}

bool PipeTaoChannel::ParentCleanup(const string &child_hash) {
  {
    lock_guard<mutex> l(data_m_);
    // Look up this hash to see if this child has any params to clean up.
    auto child_it = child_descriptors_.find(child_hash);
    if (child_it == child_descriptors_.end()) {
      LOG(ERROR) << "No child " << child_hash << " for parent clean up";
      return false;
    }

    VLOG(2) << "Closed " << child_it->second.first << " and "
            << child_it->second.second << " in ParentCleanup";
    close(child_it->second.first);
    close(child_it->second.second);

    child_descriptors_.erase(child_it);
  }

  return true;
}

// Pipe channels don't support this kind of update.
bool PipeTaoChannel::UpdateChildParams(const string &child_hash,
                                       const string &params) {
  return false;
}

bool PipeTaoChannel::ReceiveMessage(google::protobuf::Message *m,
                                    const string &child_hash) const {
  // try to receive an integer
  CHECK(m) << "m was null";

  int readfd = 0;
  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = hash_to_descriptors_.find(child_hash);
    if (child_it == hash_to_descriptors_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    readfd = child_it->second.first;
  }

  return tao::ReceiveMessage(readfd, m);
}

bool PipeTaoChannel::SendMessage(const google::protobuf::Message &m,
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
    auto child_it = hash_to_descriptors_.find(child_hash);
    if (child_it == hash_to_descriptors_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    writefd = child_it->second.second;
  }

  return tao::SendMessage(writefd, m);
}

bool PipeTaoChannel::Listen(Tao *tao) {

  // Keep SIGPIPE from killing this program when a child dies.
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  struct sigaction old_act;
  if (sigaction(SIGPIPE, &act, &old_act) < 0) {
    PLOG(ERROR) << "Could not set up the handler to block SIGPIPE";
    return false;
  }

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

    for (pair<const string, pair<int, int>> &descriptor :
         hash_to_descriptors_) {
      int d = descriptor.second.first;
      FD_SET(d, &read_fds);
      if (d > max) {
        max = d;
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
    for (pair<const string, pair<int, int>> &descriptor :
         hash_to_descriptors_) {
      int d = descriptor.second.first;
      const string &child_hash = descriptor.first;

      if (FD_ISSET(d, &read_fds)) {
        // TODO(tmroeder): if this read fails, then remove the descriptor from
        // the set
        TaoChannelRPC rpc;
        if (!GetRPC(&rpc, child_hash)) {
          LOG(ERROR) << "Could not get an RPC. Removing child " << child_hash;
          programs_to_erase.push_back(child_hash);
          continue;
        }

        if (!HandleRPC(*tao, child_hash, rpc)) {
          LOG(ERROR) << "Could not handle the RPC. Removing child "
                     << child_hash;
          programs_to_erase.push_back(child_hash);
          continue;
        }
      }
    }

    auto pit = programs_to_erase.begin();
    for (; pit != programs_to_erase.end(); ++pit) {
      if (!tao->RemoveHostedProgram(*pit)) {
	LOG(ERROR) << "Could not remove the hosted program from the list of programs";
      }

      // We still remove the program from the map so it doesn't get handled by select.
      hash_to_descriptors_.erase(*pit);
    }
  }

  // Restore the old SIGPIPE signal handler.
  if (sigaction(SIGPIPE, &old_act, NULL) < 0) {
    PLOG(ERROR) << "Could not restore the old signal handler.";
    return false;
  }

  return true;
}

bool PipeTaoChannel::HandleProgramCreation(Tao *tao, int sock) {
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

  return tao->StartHostedProgram(shpa.path(), args);
}
}  // namespace tao
