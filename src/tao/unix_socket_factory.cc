//  File: unix_socket_factory.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A factory for creating FDMessageChannels over unix domain
//  sockets.
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
#include "tao/unix_socket_factory.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/fcntl.h>

#include <string>

#include <glog/logging.h>

#include "tao/util.h"

namespace tao {

/// Opens a Unix domain socket at a given path.
/// @param path The path for the new Unix domain socket.
/// @param[out] sock The file descriptor for this socket.
bool OpenUnixDomainSocket(const string &path, int *sock) {
  // The unix domain socket is used to listen for CreateHostedProgram requests.
  *sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (*sock == -1) {
    LOG(ERROR) << "Could not create unix domain socket to listen for messages";
    return false;
  }

  // Make sure the socket won't block if there's no data available, or not
  // enough data available.
  int fcntl_err = fcntl(*sock, F_SETFL, O_NONBLOCK);
  if (fcntl_err == -1) {
    PLOG(ERROR) << "Could not set the socket to be non-blocking";
    return false;
  }

  // Make sure there isn't already a file there.
  if (unlink(path.c_str()) == -1) {
    if (errno != ENOENT) {
      PLOG(ERROR) << "Could not remove the old socket at " << path;
      return false;
    }
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    LOG(ERROR) << "The path " << path << " was too long to use";
    return false;
  }

  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
  int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
  int bind_err = bind(*sock, (struct sockaddr *)&addr, len);
  if (bind_err == -1) {
    PLOG(ERROR) << "Could not bind the address " << path << " to the socket";
    return false;
  }

  int listen_err = listen(*sock, 128 /* max completed connections */);
  if (listen_err == -1) {
    PLOG(ERROR) << "Could not set the socket up for listening";
    return false;
  }

  return true;
}

/// Connect as a client to a Unix domain socket.
/// @param path The path to the existing socket.
/// @param[out] sock The connected socket.
bool ConnectToUnixDomainSocket(const string &path, int *sock) {
  if (!sock) {
    LOG(ERROR) << "Null sock parameter";
    return false;
  }

  *sock = socket(PF_UNIX, SOCK_STREAM, 0);
  if (*sock == -1) {
    PLOG(ERROR) << "Could not create a unix domain socket";
    return false;
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    LOG(ERROR) << "This socket name is too large to use";
    close(*sock);
    return false;
  }

  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
  int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
  int conn_err = connect(*sock, (struct sockaddr *)&addr, len);
  if (conn_err == -1) {
    PLOG(ERROR) << "Could not connect to the socket";
    return false;
  }

  return true;
}

bool UnixSocketFactory::Init() {
  if (!OpenUnixDomainSocket(path_, &listen_fd_)) {
    LOG(ERROR) << "Could not open unnamed client socket";
    return false;
  }
  return true;
}

bool UnixSocketFactory::Close() {
  if (listen_fd_ != -1)
    close(listen_fd_);
  listen_fd_ = -1;
  return true;
}

FDMessageChannel *UnixSocketFactory::AcceptConnection() const {
  int fd = accept(listen_fd_, nullptr, nullptr);
  if (fd == -1) {
    if (errno != EINTR)
      PLOG(ERROR) << "Could not accept a connection on domain socket";
    return nullptr;
  }
  return new FDMessageChannel(fd, fd);
}

FDMessageChannel *UnixSocketFactory::Connect(const string &path) {
  int fd;
  if (!ConnectToUnixDomainSocket(path, &fd)) {
    LOG(ERROR) << "Could not open unnamed client socket";
    return nullptr;
  }
  return new FDMessageChannel(fd, fd);
}


}  // namespace tao
