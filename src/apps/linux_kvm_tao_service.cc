//  File: linux_kvm_tao_service.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Tao for Linux, implemented over a TPM and creating guest
//  virtual machines.
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
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "tao/kvm_unix_tao_channel.h"
#include "tao/kvm_vm_factory.h"
#include "tao/linux_tao.h"
#include "tao/tao_domain.h"
#include "tao/tpm_tao_child_channel.h"
#include "tao/util.h"

using keyczar::base::ReadFileToString;

using tao::InitializeApp;
using tao::KvmUnixTaoChannel;
using tao::KvmVmFactory;
using tao::LinuxTao;
using tao::TPMTaoChildChannel;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(keys_path, "linux_tao_keys", "Location of linux tao keys");
DEFINE_string(program_socket, "_linux_tao_socket",
              "File socket for incoming program creation requests");
DEFINE_string(stop_socket, "_linux_tao_stop_socket",
              "File socket for stopping the server");
DEFINE_string(aik_blob, "tpm/aikblob", "The AIK blob from the TPM");
DEFINE_string(aik_attestation, "tpm/aik.attest",
              "The attestation to the AIK by the policy key");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

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
  scoped_ptr<TPMTaoChildChannel> tpm(
      new TPMTaoChildChannel(blob, attestation, list<UINT32>{17, 18}));
  CHECK(tpm->Init()) << "Could not init the TPM";

  // The Channels to use for hosted programs and the way to create hosted
  // programs.
  scoped_ptr<KvmUnixTaoChannel> kvm_channel(
      new KvmUnixTaoChannel(FLAGS_program_socket, FLAGS_stop_socket));
  CHECK(kvm_channel->Init()) << "Could not init the TaoChannel";
  scoped_ptr<KvmVmFactory> vm_factory(new KvmVmFactory());
  CHECK(vm_factory->Init()) << "Could not initialize the VM factory";

  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  scoped_ptr<LinuxTao> tao;
  tao.reset(new LinuxTao(FLAGS_keys_path, tpm.release(), kvm_channel.release(),
                         vm_factory.release(), admin.release()));
  CHECK(tao->Init()) << "Could not initialize the LinuxTao";

  LOG(INFO) << "Linux Tao Service started and waiting for requests";

  // Listen for program creation requests and for messages from hosted programs
  // that have been created.
  CHECK(tao->Listen());

  return 0;
}
