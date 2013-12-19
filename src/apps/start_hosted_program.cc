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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "tao/tao_channel_rpc.pb.h"
#include "tao/util.h"

using tao::InitializeOpenSSL;
using tao::StartHostedProgramArgs;
using tao::TaoChannelRPC;

DEFINE_string(socket, "/tmp/.linux_tao_socket",
              "The unix domain socket to use to contact the LinuxTaoService");
DEFINE_string(program, "server", "The program to start");
DEFINE_bool(kvm, false, "Whether or not to start a VM for the hosted program");
DEFINE_string(vm_template, "./vm.xml", "The VM template to use");
DEFINE_string(kernel, "/tmp/vmlinuz-3.7.5",
              "A linux kernel to inject into KVM");
DEFINE_string(initrd, "/tmp/initrd.img-3.7.5", "An initrd to inject into KVM");
DEFINE_string(disk, "/var/lib/libvirt/images/cloudproxy-server.img",
              "A disk image to use in the KVM guest");

// Call this program with the arguments to the program after the "--":
//
// start_hosted_program --socket "/my/sock/path" --program "server" -- <args>
int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  if (!InitializeOpenSSL()) {
    LOG(ERROR) << "Could not initialize the OpenSSL library";
    return 1;
  }

  TaoChannelRPC rpc;
  rpc.set_rpc(tao::START_HOSTED_PROGRAM);
  StartHostedProgramArgs *shpa = rpc.mutable_start();
  shpa->set_path(FLAGS_program);
  if (FLAGS_kvm) {
    string *vm_template_arg = shpa->add_args();
    vm_template_arg->assign(FLAGS_vm_template);

    string *kernel_arg = shpa->add_args();
    kernel_arg->assign(FLAGS_kernel);

    string *initrd_arg = shpa->add_args();
    initrd_arg->assign(FLAGS_initrd);

    string *disk_arg = shpa->add_args();
    disk_arg->assign(FLAGS_disk);
  } else {
    // Pass the remaining arguments to the program that will be started.
    for (int i = 1; i < argc; i++) {
      string *arg = shpa->add_args();
      arg->assign(argv[i], strlen(argv[i]) + 1);
    }
  }

  string serialized;
  if (!rpc.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the RPC to a string";
    return 1;
  }

  int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    PLOG(ERROR) << "Could not create a unix domain socket";
    return 1;
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (FLAGS_socket.size() + 1 > sizeof(addr.sun_path)) {
    LOG(ERROR) << "This socket name is too large to use";
    close(sock);
    return 1;
  }

  strncpy(addr.sun_path, FLAGS_socket.c_str(), sizeof(addr.sun_path));

  size_t len = serialized.size();
  ssize_t bytes_sent =
      sendto(sock, &len, sizeof(len), 0, (struct sockaddr *)&addr,
             sizeof(struct sockaddr_un));
  if (bytes_sent != sizeof(len)) {
    PLOG(ERROR) << "Could not send the size";
    close(sock);
    return 1;
  }

  bytes_sent = sendto(sock, serialized.c_str(), len, 0,
                      (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
  if (bytes_sent != static_cast<ssize_t>(len)) {
    PLOG(ERROR) << "Could not send the RPC itself";
    close(sock);
    return 1;
  }

  close(sock);
  return 0;
}
