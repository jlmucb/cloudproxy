//  File: stop_service.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A program that sends a message to a stop channel (e.g., to stop
//  linux_tao_service)
//
//  Copyright (c) 2014, Google Inc.  All rights reserved.
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

#include <unistd.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/util.h"

using tao::ConnectToUnixDomainSocket;
using tao::InitializeApp;
using tao::ScopedFd;

DEFINE_string(socket, "_linux_tao_stop_socket",
              "The unix domain socket to use to stop the LinuxTaoService");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  ScopedFd sock(new int(-1));
  CHECK(ConnectToUnixDomainSocket(FLAGS_socket, sock.get()))
      << "Could not connect to the stop socket";

  // It doesn't matter what message we write to the stop socket. Any message
  // on this socket causes it to stop. It doesn't even read the message.
  int msg = 0;
  ssize_t bytes_written = write(*sock, &msg, sizeof(msg));
  if (bytes_written != sizeof(msg)) {
    PLOG(ERROR) << "Could not write a message to the stop socket";
    return 1;
  }

  return 0;
}
