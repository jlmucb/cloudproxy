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
#include <string>
#include <utility>

#include <glog/logging.h>
#include <keyczar/base/scoped_ptr.h>

#include "tao/pipe_tao_channel_params.pb.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/util.h"

using std::list;
using std::pair;

namespace tao {
UnixFdTaoChannel::UnixFdTaoChannel(const string &socket_path)
    : admin_socket_path_(socket_path), admin_socket_(new int(-1)) {}
UnixFdTaoChannel::~UnixFdTaoChannel() {}

bool UnixFdTaoChannel::Listen(Tao *tao) {
  if (*admin_socket_ == -1) {
    LOG(ERROR) << "The UnixFdTaoChannel must be initialized with Init";
    return false;
  }
  ScopedSelfPipeFd stop_fd(new int(GetSelfPipeSignalFd(SIGTERM)));
  if (*stop_fd < 0) {
    LOG(ERROR) << "Could not create self-pipe";
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

  bool graceful_shutdown = false;
  while (!graceful_shutdown) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max = 0;

    FD_SET(*stop_fd, &read_fds);
    if (*stop_fd > max) max = *stop_fd;

    FD_SET(*admin_socket_, &read_fds);
    if (*admin_socket_ > max) max = *admin_socket_;
    for (int fd : admin_descriptors_) {
      FD_SET(fd, &read_fds);
      if (fd > max) max = fd;
    }

    for (auto &it : descriptors_) {
      int read_fd = it.second.first;
      FD_SET(read_fd, &read_fds);
      if (read_fd > max) max = read_fd;
    }

    int err = select(max + 1, &read_fds, nullptr, nullptr, nullptr);
    if (err == -1 && errno == EINTR) {
      // Do nothing.
      continue;
    }
    if (err == -1) {
      PLOG(ERROR) << "Error in calling select";
      break;  // Abnormal termination.
    }

    if (FD_ISSET(*stop_fd, &read_fds)) {
      char b;
      if (read(*stop_fd, &b, 1) < 0) {
        PLOG(ERROR) << "Error reading signal number";
        break;  // Abnormal termination.
      }
      int signum = 0xff & static_cast<int>(b);
      LOG(INFO) << "UnixFdTaoChannel listener received signal " << signum;
      graceful_shutdown = true;
      continue;
    }

    // Handle a request from each ready child channel.
    std::list<pair<const string, pair<int, int>>> failed_child;
    std::list<pair<const string, const string>> child_extends;
    for (auto &it : descriptors_) {
      const string &original_child_name = it.first;
      int read_fd = it.second.first;
      int write_fd = it.second.second;
      if (FD_ISSET(read_fd, &read_fds)) {
        TaoChildRequest rpc;
        TaoChildResponse resp;
        string child_name = original_child_name;
        bool eof;
        if (!tao::ReceiveMessage(read_fd, &rpc, &eof) || eof ||
            !HandleChildRPC(tao, &child_name, rpc, &resp) ||
            !tao::SendMessage(write_fd, resp)) {
          tao->RemoveHostedProgram(child_name);
          if (!eof)
            LOG(ERROR) << "Error handling RPC for child "
                       << original_child_name;
          failed_child.push_back(it);
        } else if (child_name != original_child_name) {
          child_extends.push_back(make_pair(original_child_name, child_name));
        }
      }
    }

    // Extend child names.
    for (auto &it : child_extends) {
      descriptors_[it.second] = descriptors_[it.first];
      descriptors_.erase(it.first);
    }

    // Clean up failed child channels.
    for (auto &it : failed_child) {
      const string &child_name = it.first;
      int read_fd = it.second.first;
      int write_fd = it.second.second;
      LOG(INFO) << "Closing channel to child " << child_name;
      // TODO(kwalsh) close fds here?
      close(read_fd);
      close(write_fd);
      descriptors_.erase(child_name);
    }

    // Handle a request from each ready admin channel.
    list<int> failed_socket;
    for (int fd : admin_descriptors_) {
      if (FD_ISSET(fd, &read_fds)) {
        TaoAdminRequest rpc;
        TaoAdminResponse resp;
        bool eof;
        if (!tao::ReceiveMessage(fd, &rpc, &eof) || eof ||
            !HandleAdminRPC(tao, rpc, &resp, &graceful_shutdown) ||
            !tao::SendMessage(fd, resp)) {
          if (!eof) LOG(ERROR) << "Error handling admin RPC on channel " << fd;
          failed_socket.push_back(fd);
        }
      }
    }

    // Clean up failed admin channels.
    for (int fd : failed_socket) {
      LOG(INFO) << "Closing administrative channel " << fd;
      close(fd);
      admin_descriptors_.remove(fd);
    }

    // Check for new admin channels.
    if (FD_ISSET(*admin_socket_, &read_fds)) {
      int fd = accept(*admin_socket_, nullptr, nullptr);
      if (fd == -1) {
        if (errno != EINTR) {
          PLOG(ERROR) << "Could not accept a connection on domain socket";
        }
      } else {
        LOG(INFO) << "Accepted administrative connection " << fd;
        admin_descriptors_.push_back(fd);
      }
    }
  }

  // Restore the old SIGPIPE signal handler.
  if (sigaction(SIGPIPE, &old_act, nullptr) < 0) {
    PLOG(ERROR) << "Could not restore the old signal handler.";
    return false;
  }

  return graceful_shutdown;
}

bool UnixFdTaoChannel::Init() {
  if (!OpenUnixDomainSocket(admin_socket_path_, admin_socket_.get())) {
    LOG(ERROR) << "Could not open a socket to accept administrative requests";
    return false;
  }
  return true;
}

bool UnixFdTaoChannel::Destroy() {
  admin_socket_.reset(new int(-1));
  for (int fd : admin_descriptors_) close(fd);
  admin_descriptors_.clear();
  return true;
}
}  // namespace tao
