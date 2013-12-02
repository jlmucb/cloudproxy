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

#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <glog/logging.h>
#include <gflags/gflags.h>
#include <keyczar/keyczar.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "tao/linux_tao.h"
#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"
#include "tao/tpm_tao_child_channel.h"
#include "tao/whitelist_auth.h"

using std::ifstream;
using std::shared_ptr;
using std::string;
using std::stringstream;
using std::vector;

using tao::LinuxTao;
using tao::PipeTaoChannel;
using tao::ProcessFactory;
using tao::TPMTaoChildChannel;
using tao::WhitelistAuth;


DEFINE_string(secret_path, "linux_tao_service_secret",
              "The path to the TPM-sealed key for this binary");
DEFINE_string(aik_blob, "HW/aikblob", "The AIK blob from the TPM");
DEFINE_string(aik_attestation, "HW/aik.attest",
              "The attestation to the AIK by the policy key");
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

vector<shared_ptr<mutex> > locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  // set up locking in OpenSSL
  int lock_count = CRYPTO_num_locks();
  locks.resize(lock_count);
  for (int i = 0; i < lock_count; i++) {
    locks[i].reset(new mutex());
  }
  CRYPTO_set_locking_callback(locking_function);

  ifstream aik_blob_file(FLAGS_aik_blob.c_str(), ifstream::in);
  if (!aik_blob_file) {
    LOG(ERROR) << "Could not open the file " << FLAGS_aik_blob;
    return 1;
  }

  stringstream aik_blob_stream;
  aik_blob_stream << aik_blob_file.rdbuf();

  ifstream aik_attest_file(FLAGS_aik_attestation.c_str(), ifstream::in);
  if (!aik_attest_file) {
    LOG(ERROR) << "Could not open the file " << FLAGS_aik_attestation;
    return 1;
  }

  stringstream aik_attest_stream;
  aik_attest_stream << aik_attest_file.rdbuf();

  // The TPM to use for the parent Tao
  // TODO(tmroeder): add a proper AIK attestation from the public key
  scoped_ptr<TPMTaoChildChannel> tpm(new TPMTaoChildChannel(
      aik_blob_stream.str(), aik_attest_stream.str(), list<UINT32>{17, 18}));
  CHECK(tpm->Init()) << "Could not init the TPM";

  scoped_ptr<WhitelistAuth> whitelist_auth(
      new WhitelistAuth(FLAGS_whitelist, FLAGS_policy_pk_path));
  CHECK(whitelist_auth->Init())
      << "Could not initialize the authorization manager";

  // The Channels to use for hosted programs and the way to create hosted
  // programs.
  scoped_ptr<PipeTaoChannel> pipe_channel(
      new PipeTaoChannel(FLAGS_program_socket));
  scoped_ptr<ProcessFactory> process_factory(new ProcessFactory());

  scoped_ptr<LinuxTao> tao(
      new LinuxTao(FLAGS_secret_path, FLAGS_key_path, FLAGS_pk_key_path,
                   FLAGS_policy_pk_path, tpm.release(), pipe_channel.release(),
                   process_factory.release(), whitelist_auth.release(),
		   FLAGS_ca_host, FLAGS_ca_port));
  CHECK(tao->Init()) << "Could not initialize the LinuxTao";

  LOG(INFO) << "Linux Tao Service started and waiting for requests";

  // Listen for program creation requests and for messages from hosted programs
  // that have been created.
  CHECK(tao->Listen());

  return 0;
}
