//  File: linux_kvm_guest_tao_service.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Tao for Linux in a KVM guest.
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

#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "tao/kvm_unix_tao_child_channel.h"
#include "tao/linux_tao.h"
#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using keyczar::base::Base64WDecode;
using keyczar::base::ReadFileToString;

using tao::InitializeApp;
using tao::LinuxTao;
using tao::PipeTaoChannel;
using tao::ProcessFactory;
using tao::TaoChildChannel;
using tao::TaoChildChannelRegistry;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(keys_path, "linux_tao_keys", "Location of linux tao keys");
DEFINE_string(domain_socket, "_linux_tao_socket",
              "File socket for incoming administrative requests");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);
  tao::LetChildProcsDie();

  // In the guest, the params are the last element in /proc/cmdline, as
  // delimited by space.
  string cmdline;
  if (!ReadFileToString("/proc/cmdline", &cmdline)) {
    LOG(ERROR) << "Could not open /proc/cmdline to get the command line";
    return 1;
  }

  // Split on space and take the last element.
  size_t space_index = cmdline.find_last_of(' ');
  if (space_index == string::npos) {
    LOG(ERROR) << "Could not find any characters in the kernel boot params";
    return 1;
  }

  // The last character is a newline, so stop before it.
  string encoded_params(
      cmdline.substr(space_index + 1, cmdline.size() - (space_index + 1) - 1));

  string params;
  if (!Base64WDecode(encoded_params, &params)) {
    LOG(ERROR) << "Could not decode the encoded params " << encoded_params;
    return 1;
  }

  TaoChildChannelRegistry registry;
  tao::RegisterKnownChannels(&registry);

  scoped_ptr<TaoChildChannel> child_channel(registry.Create(params));

  // The Channels to use for hosted programs and the way to create hosted
  // programs.
  scoped_ptr<PipeTaoChannel> pipe_channel(
      new PipeTaoChannel(FLAGS_domain_socket));
  CHECK(pipe_channel->Init()) << "Could not init the TaoChannel";
  scoped_ptr<ProcessFactory> process_factory(new ProcessFactory());
  CHECK(process_factory->Init()) << "Could not initialize the process factory";

  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  scoped_ptr<LinuxTao> tao;
  tao.reset(new LinuxTao(FLAGS_keys_path, child_channel.release(),
                         pipe_channel.release(), process_factory.release(),
                         admin.release()));
  CHECK(tao->Init()) << "Could not initialize the LinuxTao";

  LOG(INFO) << "Linux Guest Tao Service started and waiting for requests";

  // Listen for program creation requests and for messages from hosted programs
  // that have been created.
  CHECK(tao->Listen());

  return 0;
}
