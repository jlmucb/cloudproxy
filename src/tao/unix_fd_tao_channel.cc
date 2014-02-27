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

using std::list;
using std::lock_guard;
using std::mutex;
using std::pair;

namespace tao {
UnixFdTaoChannel::UnixFdTaoChannel(const string &socket_path)
    : domain_socket_path_(socket_path), domain_socket_(new int(-1)) {}
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
  if (*domain_socket_ == -1) {
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
    // set up the select operation with the current fds and the unix sockets
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max = 0;

    FD_SET(*stop_fd, &read_fds);
    if (*stop_fd > max) max = *stop_fd;

    {
      lock_guard<mutex> l(socket_m_);
      FD_SET(*domain_socket_, &read_fds);
      if (*domain_socket_ > max) max = *domain_socket_;
      for (int fd : domain_descriptors_) {
        FD_SET(fd, &read_fds);
        if (fd > max) max = fd;
      }
    }

    for (pair<const string, pair<int, int>> &descriptor : descriptors_) {
      int read_fd = descriptor.second.first;
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

    // Check
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

    list<int> sockets_to_close;
    for (int fd : domain_descriptors_) {
      TaoChannelRPC rpc;
      if (!tao::ReceiveMessage(fd, &rpc)) {
        LOG(ERROR) << "Could not receive RPC on an admin channel";
        sockets_to_close.push_back(fd);
        continue;
      }
      if (!HandleRPC(*tao, "" /* no hash */, fd, rpc, &graceful_shutdown)) {
        LOG(WARNING) << "RPC failed";
        sockets_to_close.push_back(fd);
        continue;
      }
    }
    for (int fd : sockets_to_close) {
      LOG(INFO) << "Closing administrative connection " << fd;
      close(fd);
      domain_descriptors_.remove(fd);
    }

    // TODO(kwalsh) domain_socket_ is not protected by socket_m_ here.
    // The purpose of socket_m_ is unclear.
    if (FD_ISSET(*domain_socket_, &read_fds)) {
      int fd = accept(*domain_socket_, nullptr, nullptr);
      if (fd == -1) {
        if (errno != EINTR) {
          PLOG(ERROR) << "Could not accept a connection on domain socket";
        }
      } else {
        LOG(INFO) << "Accepted administrative connection " << fd;
        domain_descriptors_.push_back(fd);
      }
    }

    for (pair<const string, pair<int, int>> &descriptor : descriptors_) {
      int read_fd = descriptor.second.first;
      const string &child_hash = descriptor.first;

      if (FD_ISSET(read_fd, &read_fds)) {
        TaoChannelRPC rpc;
        if (!GetRPC(&rpc, child_hash)) {
          LOG(ERROR) << "Could not get RPC. Removing child " << child_hash;
          programs_to_erase_.push_back(child_hash);
          continue;
        }
        if (!HandleRPC(*tao, child_hash, 0 /* fd */, rpc, &graceful_shutdown)) {
          LOG(ERROR) << "Could not handle RPC from child." << child_hash;
          continue;
        }
      }
    }

    CleanErasedPrograms();
  }

  // Restore the old SIGPIPE signal handler.
  if (sigaction(SIGPIPE, &old_act, nullptr) < 0) {
    PLOG(ERROR) << "Could not restore the old signal handler.";
    return false;
  }

  return graceful_shutdown;
}

bool UnixFdTaoChannel::CleanErasedPrograms() {
  auto pit = programs_to_erase_.begin();
  for (; pit != programs_to_erase_.end(); ++pit) {
    // TODO(kwalsh) close fds here?
    descriptors_.erase(*pit);
  }
  return true;
}

bool UnixFdTaoChannel::HandleRPC(Tao &tao, const string &hash,  // NOLINT
                                 int fd, const TaoChannelRPC &rpc,
                                 bool *shutdown_request) {
  TaoChannelResponse resp;
  resp.set_rpc(rpc.rpc());
  bool success = true;
  if (rpc.rpc() == TAO_CHANNEL_RPC_SHUTDOWN) {
    *shutdown_request = true;
    success = true;
  } else if (rpc.rpc() == TAO_CHANNEL_RPC_START_HOSTED_PROGRAM) {
    string identifier;
    success = HandleProgramCreation(rpc, &tao, &identifier);
    if (success) resp.set_data(identifier);
  } else if (rpc.rpc() == TAO_CHANNEL_RPC_REMOVE_HOSTED_PROGRAM) {
    // string child_hash = rpc.to_be_determined();
    // success = tao.RemoveHostedProgram(child_hash);
    // if (success)
    //   programs_to_erase_.push_back(child_hash);
    // TODO(kwalsh) maybe this RPC should not exists?
    LOG(ERROR) << "Not yet implemented";
    success = false;
  } else if (!hash.empty()) {
    if (!TaoChannel::HandleRPC(tao, hash, rpc)) {
      LOG(ERROR) << "Could not handle RPC. Removing child " << hash;
      tao.RemoveHostedProgram(hash);
      programs_to_erase_.push_back(hash);
      return false;  // TaoChannel::HandleRPC() already send the reply, if
                     // possible.
    }
    return true;  // TaoChannel::HandleRPC() already send the reply.
  }
  // send response if not handled by TaoChannel::HandleRPC()
  resp.set_success(success);
  if (!hash.empty()) {
    if (!SendResponse(resp, hash)) {
      LOG(ERROR) << "Could not handle RPC. Removing child " << hash;
      tao.RemoveHostedProgram(hash);
      programs_to_erase_.push_back(hash);
      return false;
    }
  } else {
    if (!tao::SendMessage(fd, resp)) {
      LOG(ERROR) << "Could not reply to administrative channel";
      return false;
    }
  }
  return true;
}

bool UnixFdTaoChannel::HandleProgramCreation(const TaoChannelRPC &rpc, Tao *tao,
                                             string *identifier) {
  const StartHostedProgramArgs &shpa = rpc.start();
  list<string> args;
  for (int i = 0; i < shpa.args_size(); i++) {
    args.push_back(shpa.args(i));
  }
  if (!tao->StartHostedProgram(shpa.path(), args, identifier)) {
    LOG(ERROR) << "Could not start hosted program " << shpa.path();
    return false;
  }
  return true;
}

bool UnixFdTaoChannel::Init() {
  {
    lock_guard<mutex> l(socket_m_);
    if (!OpenUnixDomainSocket(domain_socket_path_, domain_socket_.get())) {
      LOG(ERROR) << "Could not open a socket to accept administrative requests";
      return false;
    }
  }

  return true;
}

bool UnixFdTaoChannel::Destroy() {
  {
    lock_guard<mutex> l(socket_m_);
    domain_socket_.reset(new int(-1));
    for (int fd : domain_descriptors_) close(fd);
    domain_descriptors_.clear();
  }

  return true;
}
}  // namespace tao
