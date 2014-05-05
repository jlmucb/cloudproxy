//  File: linux_tao_service.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Tao for Linux, implemented over a TPM and creating child
//  processes.
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
#include <keyczar/base/file_util.h>

#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/linux_tao.h"
#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"
#include "tao/tao_domain.h"
#include "tao/tpm_tao_child_channel.h"

using keyczar::base::ReadFileToString;

using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::InitializeApp;
using tao::LinuxTao;
using tao::PipeTaoChannel;
using tao::ProcessFactory;
using tao::TPMTaoChildChannel;
using tao::TaoChildChannel;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(keys_path, "linux_tao_keys", "Location of linux tao keys");
DEFINE_string(domain_socket, "_linux_tao_socket",
              "File socket for incoming administrative requests");

DEFINE_string(aik_blob, "tpm/aikblob", "The AIK blob from the TPM");
DEFINE_string(aik_attestation, "tpm/aik.attest",
              "The attestation to the AIK by the policy key");

// Flags that can be used to switch into a testing mode that doesn't need
// hardware support.
DEFINE_bool(use_tpm, true, "Whether or not to use the TPM Tao");
DEFINE_string(linux_hash, "FAKE_PCRS",
              "The hash of the Linux OS for the DirectTaoChildChannel");
DEFINE_string(fake_keys, "./fake_tpm",
              "Directory containing signing_key and "
              "sealing_key to use with the fake tao");
DEFINE_bool(ignore_seal_hashes, false,
            "Whether or not to ignore hashes during unseal operations");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);
  tao::LetChildProcsDie();

  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  scoped_ptr<TaoChildChannel> child_channel;
  if (FLAGS_use_tpm) {
    string blob;
    if (!ReadFileToString(FLAGS_aik_blob, &blob)) {
      LOG(ERROR) << "Could not open the file " << FLAGS_aik_blob;
      return 1;
    }

    string attestation;
    if (!ReadFileToString(FLAGS_aik_attestation, &attestation)) {
      LOG(ERROR) << "Could not open the file " << FLAGS_aik_attestation;
      return 1;
    }

    // The TPM to use for the parent Tao
    child_channel.reset(
        new TPMTaoChildChannel(blob, attestation, list<UINT32>{17, 18}));
  } else {
    // The FakeTao to use for the parent Tao
    scoped_ptr<FakeTao> tao(new FakeTao());
    CHECK(tao->InitPseudoTPM(FLAGS_fake_keys, *admin))
        << "Could not initialize the FakeTao";
    child_channel.reset(
        new DirectTaoChildChannel(tao.release(), FLAGS_linux_hash));
  }

  CHECK(child_channel->Init()) << "Could not init the TPM";

  // Create channels for hosted programs and administrative requests.
  scoped_ptr<PipeTaoChannel> pipe_channel(
      new PipeTaoChannel(FLAGS_domain_socket));
  CHECK(pipe_channel->Init()) << "Could not initialize the pipe channel";
  scoped_ptr<ProcessFactory> process_factory(new ProcessFactory());
  CHECK(process_factory->Init()) << "Could not initialize the process factory";

  scoped_ptr<LinuxTao> tao(new LinuxTao(
      FLAGS_keys_path, child_channel.release(), pipe_channel.release(),
      process_factory.release(), admin.release()));
  CHECK(tao->Init()) << "Could not initialize the LinuxTao";

  if (!FLAGS_use_tpm && FLAGS_ignore_seal_hashes)
    tao->SetIgnoreUnsealPolicyForTesting(true);

  string tao_name;
  tao->GetTaoFullName(&tao_name);
  LOG(INFO) << "Tao Service: " << tao_name;
  LOG(INFO) << "Linux Tao Service started and waiting for requests";

  // Listen for program creation requests and for messages from hosted programs
  // that have been created.
  CHECK(tao->Listen());

  return 0;
}
