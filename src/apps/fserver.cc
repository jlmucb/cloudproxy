//  File: fserver.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An example file server application using FileServer
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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include "cloudproxy/file_server.h"
#include "tao/attestation_verifier.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/whitelist_auth.h"

#include <mutex>
#include <string>
#include <vector>

using std::mutex;
using std::string;
using std::vector;

using tao::AttestationVerifier;
using tao::PipeTaoChildChannel;
using tao::TaoChildChannel;
using tao::WhitelistAuth;

DEFINE_string(file_path, "file_server_files",
              "The path used by the file server to store files");
DEFINE_string(meta_path, "file_server_meta",
              "The path used by the file server to store metadata");
DEFINE_string(server_cert, "./openssl_keys/server/server.crt",
              "The PEM certificate for the server to use for TLS");
DEFINE_string(server_key, "./openssl_keys/server/server.key",
              "The private key file for the server for TLS");
DEFINE_string(server_password, "cpserver", "The password for the server key");
DEFINE_string(policy_key, "./policy_public_key", "The keyczar public"
                                                 " policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.crt",
              "The PEM public policy cert");
DEFINE_string(acls, "./acls_sig",
              "A file containing a SignedACL signed by"
              " the public policy key (e.g., using sign_acls)");
DEFINE_string(server_enc_key, "./server_key", "A keyczar crypter"
                                              " directory");
DEFINE_string(whitelist_path, "./signed_whitelist",
              "The path to the signed whitelist");
DEFINE_string(address, "localhost", "The address to listen on");
DEFINE_int32(port, 11235, "The port to listen on");

DEFINE_string(aik_cert, "./HW/aik.crt",
              "A certificate for the AIK, signed by the public policy key");

vector<shared_ptr<mutex> > locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

int main(int argc, char **argv) {
  // make sure protocol buffers is using the right version
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  // the last argument should be the parameters for channel establishment
  if (argc < 2) {
    LOG(ERROR) << "Too few arguments to server";
    return 1;
  }

  string params(argv[argc - 1]);

  // TODO(tmroeder): generalize this to arbitrary channel strings
  scoped_ptr<TaoChildChannel> channel(new PipeTaoChildChannel(params));
  CHECK(channel->Init()) << "Could not initialize the child channel";

  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  scoped_ptr<keyczar::Keyczar> policy_key(
      keyczar::Verifier::Read(FLAGS_policy_key.c_str()));
  policy_key->set_encoding(keyczar::Keyczar::NO_ENCODING);

  scoped_ptr<WhitelistAuth> whitelist_auth(new WhitelistAuth());
  whitelist_auth->Init(FLAGS_whitelist_path, *policy_key);

  scoped_ptr<AttestationVerifier> verifier(new AttestationVerifier(
      FLAGS_aik_cert, FLAGS_policy_key, whitelist_auth.release()));

  // set up locking in OpenSSL
  int lock_count = CRYPTO_num_locks();
  locks.resize(lock_count);
  for (int i = 0; i < lock_count; i++) {
    locks[i].reset(new mutex());
  }
  CRYPTO_set_locking_callback(locking_function);

  cloudproxy::FileServer fs(
      FLAGS_file_path, FLAGS_meta_path, FLAGS_server_cert, FLAGS_server_key,
      FLAGS_server_password, FLAGS_policy_key, FLAGS_pem_policy_key, FLAGS_acls,
      FLAGS_whitelist_path, FLAGS_server_enc_key, FLAGS_address, FLAGS_port);

  CHECK(fs.Listen(*channel, *verifier))
      << "Could not listen for client connections";
  return 0;
}
