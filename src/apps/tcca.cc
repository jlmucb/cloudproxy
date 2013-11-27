//  File: tcca.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Trusted Computing Certificate Authority
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
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "tao/attestation.pb.h"
#include "tao/whitelist_auth.h"

#include <memory>
#include <mutex>
#include <vector>

using keyczar::Keyczar;

using std::mutex;
using std::shared_ptr;
using std::vector;

using tao::Attestation;
using tao::Statement;
using tao::WhitelistAuth;

DEFINE_int32(port, 11235, "The listening port for tcca");
DEFINE_string(policy_key_path, "policy_key", "The path to the policy key");
DEFINE_string(policy_key_pass, "cppolicy", "The password for the policy key");
DEFINE_string(policy_pk_path, "policy_public_key",
              "The path to the policy public key");
DEFINE_string(whitelist, "signed_whitelist",
              "The whitelist of hashes to accept");

vector<shared_ptr<mutex> > locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

bool receive_message(int sock, Attestation *a);
bool send_message(int sock, const Attestation &a);

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

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    PLOG(ERROR) << "Could not create a socket for tcca to listen on";
    return 1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((short)FLAGS_port);

  int bind_err =
      bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
  if (bind_err == -1) {
    PLOG(ERROR) << "Could not bind the socket";
    return 1;
  }

  int listen_err = listen(sock, 128 /* max completed connections */);
  if (listen_err == -1) {
    PLOG(ERROR) << "Could not set the socket up for listening";
    return 1;
  }

  scoped_ptr<WhitelistAuth> whitelist_auth(
      new WhitelistAuth(FLAGS_whitelist, FLAGS_policy_pk_path));
  CHECK(whitelist_auth->Init())
      << "Could not initialize the whitelist authorization mechanism";

  // decrypt the private policy key so we can construct a signer
  keyczar::base::ScopedSafeString password(new string(FLAGS_policy_key_pass));
  scoped_ptr<keyczar::rw::KeysetReader> reader(
      new keyczar::rw::KeysetPBEJSONFileReader(FLAGS_policy_key_path.c_str(),
                                               *password));

  // sign this serialized data with the keyset in FLAGS_key_loc
  scoped_ptr<keyczar::Keyczar> policy_key(keyczar::Signer::Read(*reader));
  CHECK(policy_key.get()) << "Could not initialize the signer from "
                          << FLAGS_policy_key_path;
  policy_key->set_encoding(keyczar::Keyczar::NO_ENCODING);

  while (true) {
    int accept_sock = accept(sock, NULL, NULL);
    if (accept_sock == -1) {
      PLOG(ERROR) << "Could not accept a connection on the socket";
      return 1;
    }

    Attestation a;
    if (!receive_message(accept_sock, &a)) {
      LOG(ERROR) << "Could not receive a message from the socket";
      continue;
    }

    string serialized_attest;
    if (!a.SerializeToString(&serialized_attest)) {
      LOG(ERROR) << "Could not serialize the attestation";
      continue;
    }

    string data;
    if (!whitelist_auth->VerifyAttestation(serialized_attest, &data)) {
      LOG(ERROR) << "The provided attestation did not pass verification";
      continue;
    }

    Statement orig_statement;
    if (!orig_statement.ParseFromString(a.serialized_statement())) {
      LOG(ERROR)
          << "Could not parse the original statment from the attestation";
      continue;
    }

    // Create a new attestation using the policy key
    Statement policy_statement;
    policy_statement.CopyFrom(orig_statement);

    Attestation policy_attest;
    string *serialized_policy_statement =
        policy_attest.mutable_serialized_statement();
    if (!policy_statement.SerializeToString(serialized_policy_statement)) {
      LOG(ERROR) << "Could not serialize the policy statement";
      continue;
    }

    string *sig = policy_attest.mutable_signature();
    if (!policy_key->Sign(*serialized_policy_statement, sig)) {
      LOG(ERROR) << "Could not sign the policy statement";
      continue;
    }

    if (!send_message(accept_sock, policy_attest)) {
      LOG(ERROR) << "Could not send the newly signed attestation in reply";
      continue;
    }
  }
  return 0;
}

bool receive_message(int sock, Attestation *a) {
  size_t len;
  ssize_t bytes_read = read(sock, &len, sizeof(size_t));
  if (bytes_read != sizeof(size_t)) {
    LOG(ERROR) << "Could not receive a size on the channel";
    return false;
  }

  // then read this many bytes as the message
  scoped_array<char> bytes(new char[len]);
  bytes_read = read(sock, bytes.get(), len);

  // TODO(tmroeder): add safe integer library
  if (bytes_read != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not read the right number of bytes from the fd";
    return false;
  }

  string serialized(bytes.get(), len);
  return a->ParseFromString(serialized);
}

bool send_message(int sock, const Attestation &a) {
  // send the length then the serialized message
  string serialized;
  if (!a.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }

  size_t len = serialized.size();
  ssize_t bytes_written = write(sock, &len, sizeof(size_t));
  if (bytes_written != sizeof(size_t)) {
    LOG(ERROR) << "Could not write the length to the fd " << sock;
    return false;
  }

  bytes_written = write(sock, serialized.data(), len);
  if (bytes_written != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not wire the serialized message to the fd";
    return false;
  }

  return true;
}
