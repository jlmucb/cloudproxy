//  File: bootstrap.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A simple client that initializes the Tao then gets a signed
//  list and path to a binary as input. It checks the signature on the list,
//  checks the binary against its hash on the list, and starts the requested
//  application.
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

#include <glog/logging.h>
#include <gflags/gflags.h>
#include "legacy_tao/legacy_tao.h"
#include "logging.h"

DEFINE_string(secret_path, "bootstrap_sealed_secret",
              "The path to the TPM-sealed key for this binary");
DEFINE_string(directory, "/home/jlm/jlmcrypt",
              "The directory to use for Tao initialization");
DEFINE_string(
    subdirectory, "bootstrap_files",
    "The subdirectory to write the files into for the bootstrap application");
DEFINE_string(key_path, "bootstrap_files/bootstrap_key",
              "An encrypted keyczar directory for an encryption key");
DEFINE_string(pk_key_path, "bootstrap_files/bootstrap_pk_key",
              "An encrypted keyczar directory for a signing key");
DEFINE_string(whitelist, "signed_whitelist", "A signed whitelist file");
DEFINE_string(policy_pk_path, "./policy_public_key",
              "The path to the public policy key");
DEFINE_string(tao_provider, "/dev/tcioDD0",
              "The path to the device that the LegacyTao will use");
DEFINE_string(program, "server", "The program to run");

int main(int argc, char **argv) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  initLog(NULL);

  // call this program like this:
  // ./bootstrap <bootstrap flags> -- <flags for the bootstrapped application>
  FLAGS_log_dir = "b_meas";
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  initLog("bootstrap.log");

  LOG(INFO) << "Measured program starting";
  scoped_ptr<tao::Tao> tao(new legacy_tao::LegacyTao(
      FLAGS_secret_path, FLAGS_directory, FLAGS_subdirectory, FLAGS_key_path,
      FLAGS_pk_key_path, FLAGS_whitelist, FLAGS_policy_pk_path,
      FLAGS_tao_provider));

  CHECK(tao->Init()) << "Could not initialize the Legacy Tao";
  LOG(INFO) << "Finished initializing the Legacy Tao";

  // now start the server and start listening for requests from it
  size_t plen = FLAGS_program.size();
  scoped_array<char> pname(new char[plen + 1]);
  strncpy(pname.get(), FLAGS_program.data(), plen + 1);
  char *program_name = pname.get();
  char *new_argv[] = {program_name};
  CHECK(tao->StartHostedProgram(FLAGS_program.c_str(), 1, new_argv))
      << "Could not start the server under LegacyTao";
  return 0;
}
