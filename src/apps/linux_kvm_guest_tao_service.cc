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

#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <glog/logging.h>
#include <gflags/gflags.h>
#include <keyczar/base/base64w.h>
#include <keyczar/keyczar.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "tao/linux_tao.h"
#include "tao/kvm_unix_tao_child_channel.h"
#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using std::ifstream;
using std::shared_ptr;
using std::string;
using std::stringstream;
using std::vector;

using keyczar::base::Base64WDecode;

using tao::LinuxTao;
using tao::KvmUnixTaoChildChannel;
using tao::PipeTaoChannel;
using tao::ProcessFactory;
using tao::TaoChildChannel;
using tao::TaoChildChannelRegistry;
using tao::WhitelistAuth;

DEFINE_string(secret_path, "linux_tao_service_secret",
              "The path to the TPM-sealed key for this binary");
DEFINE_string(key_path, "linux_tao_service_files/key",
              "An encrypted keyczar directory for an encryption key");
DEFINE_string(pk_key_path, "linux_tao_service_files/public_key",
              "An encrypted keyczar directory for a signing key");
DEFINE_string(whitelist, "signed_whitelist", "A signed whitelist file");
DEFINE_string(policy_pk_path, "./policy_public_key",
              "The path to the public policy key");
DEFINE_string(program_socket, "/tmp/.linux_tao_socket",
              "The name of a file to use as the socket for incoming program "
              "creation requests");
DEFINE_string(ca_host, "", "The hostname of the TCCA server, if any");
DEFINE_string(ca_port, "", "The port for the TCCA server, if any");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  tao::InitializeOpenSSL();

  // In the guest, the params are the last element in /proc/cmdline, as
  // delimited by space.
  ifstream proc_cmd("/proc/cmdline");
  if (!proc_cmd) {
    LOG(ERROR) << "Could not open /proc/cmdline to get the command line";
    return 1;
  }

  stringstream proc_stream;
  proc_stream << proc_cmd.rdbuf();

  // Split on space and take the last element.
  string cmdline(proc_stream.str());
  size_t space_index = cmdline.find_last_of(' ');
  if (space_index == string::npos) {
    LOG(ERROR) << "Could not find any characters in the kernel boot params";
    return 1;
  }

  // The last character is a newline, so stop before it.
  LOG(INFO) << "cmdline.size() == " << (int)cmdline.size();
  LOG(INFO) << "space_index == " << (int)space_index;
  string encoded_params(cmdline.substr(space_index + 1,
                        	       cmdline.size() - (space_index + 1) - 1));

  LOG(INFO) << "The length of the encoded string is " << encoded_params.size();
  string params;
  if (!Base64WDecode(encoded_params, &params)) {
    LOG(ERROR) << "Could not decode the encoded params " << encoded_params;
    return 1;
  }

  TaoChildChannelRegistry registry;
  tao::RegisterKnownChannels(&registry);

  LOG(INFO) << "Getting registered channel for these params";
  scoped_ptr<TaoChildChannel> child_channel(registry.Create(params));

  scoped_ptr<WhitelistAuth> whitelist_auth(
      new WhitelistAuth(FLAGS_whitelist, FLAGS_policy_pk_path));
  CHECK(whitelist_auth->Init())
      << "Could not initialize the authorization manager";
  LOG(INFO) << "Initialized the authorization manager";

  // The Channels to use for hosted programs and the way to create hosted
  // programs.
  scoped_ptr<PipeTaoChannel> pipe_channel(
      new PipeTaoChannel(FLAGS_program_socket));
  scoped_ptr<ProcessFactory> process_factory(new ProcessFactory());
  CHECK(process_factory->Init()) << "Could not initialize the process factory";

  LOG(INFO) << "Set up the channels and factories for local hosted programs";
  scoped_ptr<LinuxTao> tao(
      new LinuxTao(FLAGS_secret_path, FLAGS_key_path, FLAGS_pk_key_path,
                   FLAGS_policy_pk_path, child_channel.release(),
                   pipe_channel.release(), process_factory.release(),
                   whitelist_auth.release(), FLAGS_ca_host, FLAGS_ca_port));
  LOG(INFO) << "Created the LinuxTao; about to initialize";
  CHECK(tao->Init()) << "Could not initialize the LinuxTao";

  LOG(INFO) << "Linux Tao Service started and waiting for requests";

  // Listen for program creation requests and for messages from hosted programs
  // that have been created.
  CHECK(tao->Listen());

  return 0;
}
