//  File: server.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An example server application using CloudServer
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
#include <openssl/err.h>
#include "cloudproxy/cloud_server.h"
#include "cloudproxy/util.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/util.h"

#include <mutex>
#include <string>
#include <vector>

using std::mutex;
using std::string;
using std::vector;

using cloudproxy::CloudServer;
using tao::SealOrUnsealSecret;

using keyczar::base::ScopedSafeString;

using tao::PipeTaoChildChannel;
using tao::TaoAuth;
using tao::TaoChildChannel;
using tao::WhitelistAuth;

DEFINE_string(server_cert, "./openssl_keys/server/server.crt",
              "The PEM certificate for the server to use for TLS");
DEFINE_string(server_key, "./openssl_keys/server/server.key",
              "The private key file for the server for TLS");
DEFINE_string(sealed_secret, "server_secret", "A Tao-sealed secret");
DEFINE_string(policy_key, "./policy_public_key", "The keyczar public"
                                                 " policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.crt",
              "The PEM public policy cert");
DEFINE_string(acls, "./acls_sig",
              "A file containing a SignedACL signed by"
              " the public policy key (e.g., using sign_acls)");
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

  LOG(INFO) << "Successfully established communication with the Tao";

  // get a secret from the Tao
  ScopedSafeString secret(new string());
  CHECK(SealOrUnsealSecret(*channel, FLAGS_sealed_secret, secret.get()))
      << "Could not get the secret";

  LOG(INFO) << "Got a secret from the Tao";
  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  scoped_ptr<keyczar::Keyczar> policy_key(
      keyczar::Verifier::Read(FLAGS_policy_key.c_str()));
  policy_key->set_encoding(keyczar::Keyczar::NO_ENCODING);

  scoped_ptr<WhitelistAuth> whitelist_auth(new WhitelistAuth(FLAGS_whitelist_path, FLAGS_policy_key));
  CHECK(whitelist_auth->Init()) << "Could not initialize the whitelist auth";

  // set up locking in OpenSSL
  int lock_count = CRYPTO_num_locks();
  locks.resize(lock_count);
  for (int i = 0; i < lock_count; i++) {
    locks[i].reset(new mutex());
  }
  CRYPTO_set_locking_callback(locking_function);

  LOG(INFO) << "Starting CloudServer";

  CloudServer cs(FLAGS_server_cert, FLAGS_server_key, *secret, FLAGS_policy_key,
                 FLAGS_pem_policy_key, FLAGS_acls,
                 FLAGS_address, FLAGS_port, whitelist_auth.release());
  LOG(INFO) << "Started CloudServer. About to listen";
  CHECK(cs.Listen(*channel))
      << "Could not listen for client connections";
  return 0;
}
