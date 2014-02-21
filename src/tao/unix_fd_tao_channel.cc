//  File: unix_fd_tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of UnixFdTaoChannel channel for Tao
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

#include "tao/unix_fd_tao_channel.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/unistd.h>

#include <list>
#include <mutex>
#include <string>
#include <thread>

#include <glog/logging.h>
#include <keyczar/base/scoped_ptr.h>

#include "tao/pipe_tao_channel_params.pb.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

using std::lock_guard;

namespace tao {
UnixFdTaoChannel::UnixFdTaoChannel(const string &socket_path,
                                   const string &stop_socket_path)
    : stop_socket_path_(stop_socket_path),
      stop_socket_(new int(-1)),
      domain_socket_path_(socket_path),
      domain_socket_(new int(-1)) {}
UnixFdTaoChannel::~UnixFdTaoChannel() {}

bool UnixFdTaoChannel::ReceiveMessage(google::protobuf::Message *m,
                                      const string &child_hash) const {
  // try to receive an integer
  CHECK(m) << "m was null";

  int readfd = 0;
  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = descriptors_.find(child_hash);
    if (child_it == descriptors_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    readfd = child_it->second.first;
  }

  return tao::ReceiveMessage(readfd, m);
}

bool UnixFdTaoChannel::SendMessage(const google::protobuf::Message &m,
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
    auto child_it = descriptors_.find(child_hash);
    if (child_it == descriptors_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    writefd = child_it->second.second;
  }

  return tao::SendMessage(writefd, m);
}

bool UnixFdTaoChannel::Listen(Tao *tao) {
  if (!domain_socket_.get() || !stop_socket_.get()) {
    LOG(ERROR) << "The UnixFdTaoChannel must be initialized with Init";
    return false;
  }

  // Keep SIGPIPE from killing this program when a child dies and is connected
  // over a pipe.
  // TODO(tmroeder): maybe this step should be generalized and put in the apps/
  // code rather than in the library.
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  struct sigaction old_act;
  if (sigaction(SIGPIPE, &act, &old_act) < 0) {
    PLOG(ERROR) << "Could not set up the handler to block SIGPIPE";
    return false;
  }

  bool ret = true;
  while (true) {
    // set up the select operation with the current fds and the unix socket
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max = 0;

    {
      lock_guard<mutex> l(socket_m_);
      if (domain_socket_.get()) {
        if (*domain_socket_ > max) {
          max = *domain_socket_;
        }
        FD_SET(*domain_socket_, &read_fds);
      }

      if (stop_socket_.get()) {
        FD_SET(*stop_socket_, &read_fds);
        if (*stop_socket_ > max) {
          max = *stop_socket_;
        }
      }
    }

    for (pair<const string, pair<int, int>> &descriptor : descriptors_) {
      int read_fd = descriptor.second.first;
      FD_SET(read_fd, &read_fds);

      if (read_fd > max) {
        max = read_fd;
      }
    }

    int err = select(max + 1, &read_fds, nullptr, nullptr, nullptr);
    if (err == -1) {
      PLOG(ERROR) << "Error in calling select";
      ret = false;
      break;
    }

    // Check for stop messages.
    if (stop_socket_.get() && FD_ISSET(*stop_socket_, &read_fds)) {
      break;
    }

    // Check for messages to handle
    if (domain_socket_.get() && FD_ISSET(*domain_socket_, &read_fds)) {
      string identifier;
      struct sockaddr_un addr;
      socklen_t addr_len = sizeof(addr);
      bool creation_result =
          HandleProgramCreation(tao, *domain_socket_, &identifier,
                                (struct sockaddr *)&addr, &addr_len);
      if (!creation_result) {
        LOG(ERROR) << "Could not handle the program creation request";
      }

      TaoChannelResponse resp;
      resp.set_rpc(START_HOSTED_PROGRAM);
      resp.set_success(creation_result);
      resp.set_data(identifier);
      if (!tao::SendMessageTo(*domain_socket_, resp, (struct sockaddr *)&addr,
                              addr_len)) {
        LOG(ERROR) << "Could not reply to the program creation request";
      }
    }

    list<string> programs_to_erase;
    for (pair<const string, pair<int, int>> &descriptor : descriptors_) {
      int read_fd = descriptor.second.first;
      const string &child_hash = descriptor.first;

      if (FD_ISSET(read_fd, &read_fds)) {
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
        LOG(ERROR)
            << "Could not remove the hosted program from the list of programs";
      }

      // We still remove the program from the map so it doesn't get handled by
      // select.
      descriptors_.erase(*pit);
    }
  }

  // Restore the old SIGPIPE signal handler.
  if (sigaction(SIGPIPE, &old_act, nullptr) < 0) {
    PLOG(ERROR) << "Could not restore the old signal handler.";
    ret = false;
  }

  return ret;
}

bool UnixFdTaoChannel::HandleProgramCreation(Tao *tao, int sock,
                                             string *identifier,
                                             struct sockaddr *addr,
                                             socklen_t *addr_len) {
  TaoChannelRPC rpc;
  if (!tao::ReceiveMessageFrom(sock, &rpc, addr, addr_len)) {
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

  return tao->StartHostedProgram(shpa.path(), args, identifier);
}

bool UnixFdTaoChannel::Init() {
  {
    lock_guard<mutex> l(socket_m_);
    if (!OpenUnixDomainSocket(domain_socket_path_, domain_socket_.get())) {
      LOG(ERROR)
          << "Could not open a domain socket to accept creation requests";
      return false;
    }

    if (!OpenUnixDomainSocket(stop_socket_path_, stop_socket_.get())) {
      LOG(ERROR) << "Could not open a socket to accept program stop requests";
      return false;
    }
  }

  return true;
}

bool UnixFdTaoChannel::Destroy() {
  {
    lock_guard<mutex> l(socket_m_);
    domain_socket_.reset(nullptr);
    stop_socket_.reset(nullptr);
  }

  return true;
}
}  // namespace tao
