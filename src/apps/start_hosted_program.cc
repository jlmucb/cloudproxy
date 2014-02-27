//  File: start_hosted_program.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A program that calls to a unix domain socket to start a hosted
//  program.
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

#include <cstdio>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/unix_domain_socket_tao_child_channel.h"
#include "tao/util.h"

using tao::InitializeApp;
using tao::UnixDomainSocketTaoChildChannel;

DEFINE_string(domain_socket, "_linux_tao_socket",
              "The unix domain socket to use to contact the LinuxTaoService");
DEFINE_string(program, "server", "The program to start");
DEFINE_bool(kvm, false, "Whether or not to start a VM for the hosted program");
DEFINE_string(vm_template, "vm.xml", "The VM template to use");
DEFINE_string(kernel, "vmlinuz", "A linux kernel to inject into KVM");
DEFINE_string(initrd, "initrd.img", "An initrd to inject into KVM");
DEFINE_string(disk, "cloudproxy-server.img",
              "A disk image to use in the KVM guest");

// Call this program with the arguments to the program after the "--":
//
// start_hosted_program --socket "/my/sock/path" --program "server" -- <args>
int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  list<string> args;

  if (FLAGS_kvm) {
    args.push_back(FLAGS_vm_template);
    args.push_back(FLAGS_kernel);
    args.push_back(FLAGS_initrd);
    args.push_back(FLAGS_disk);
  } else {
    // Pass the remaining arguments to the program that will be started.
    for (int i = 1; i < argc; i++) {
      args.push_back(string(argv[i], strlen(argv[i]) + 1));
    }
  }

  scoped_ptr<UnixDomainSocketTaoChildChannel> chan(
      new UnixDomainSocketTaoChildChannel(FLAGS_domain_socket));
  CHECK(chan->Init()) << "Could not open a socket for communication";
  string identifier;
  CHECK(chan->StartHostedProgram(FLAGS_program, args, &identifier))
      << "Failed to start the program";
  // Print identifier so callers of can later send signals to the program.
  printf("%s\n", identifier.c_str());
  CHECK(chan->Destroy()) << "Could not destroy socket";

  return 0;
}
