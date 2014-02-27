//  File: stop_service.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A program that requests a host Tao be shut down.
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

#include "tao/unix_domain_socket_tao_child_channel.h"
#include "tao/util.h"

using tao::InitializeApp;
using tao::UnixDomainSocketTaoChildChannel;

DEFINE_string(domain_socket, "_linux_tao_socket",
              "The unix domain socket to use to contact the LinuxTaoService");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  scoped_ptr<UnixDomainSocketTaoChildChannel> chan(
      new UnixDomainSocketTaoChildChannel(FLAGS_domain_socket));
  CHECK(chan->Init()) << "Could not open a socket for communication";
  CHECK(chan->Shutdown()) << "Failed to shut down the host Tao";
  CHECK(chan->Destroy()) << "Could not destroy socket";

  return 0;
}
