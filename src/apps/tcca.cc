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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

#include "tao/attestation.pb.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using keyczar::Keyczar;

using tao::Attestation;
using tao::InitializeOpenSSL;
using tao::OpenTCPSocket;
using tao::ReceiveMessage;
using tao::SendMessage;
using tao::Statement;
using tao::WhitelistAuth;

DEFINE_int32(port, 11238, "The listening port for tcca");
DEFINE_string(policy_key_path, "policy_key", "The path to the policy key");
DEFINE_string(policy_key_pass, "cppolicy", "The password for the policy key");
DEFINE_string(policy_pk_path, "policy_public_key",
              "The path to the policy public key");
DEFINE_string(whitelist, "signed_whitelist",
              "The whitelist of hashes to accept");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  if (!InitializeOpenSSL()) {
    LOG(ERROR) << "Could not initialize the OpenSSL library";
    return 1;
  }

  int sock = 0;
  if (!OpenTCPSocket(static_cast<short>(FLAGS_port), &sock)) {
    LOG(ERROR) << "Could not open a TCP socket for listening on port "
               << FLAGS_port;
    return 1;
  }

  scoped_ptr<WhitelistAuth> whitelist_auth(
      new WhitelistAuth(FLAGS_whitelist, FLAGS_policy_pk_path));
  CHECK(whitelist_auth->Init())
      << "Could not initialize the whitelist authorization mechanism";

  // Set up the policy key for signing.
  keyczar::base::ScopedSafeString password(new string(FLAGS_policy_key_pass));
  scoped_ptr<keyczar::rw::KeysetReader> reader(
      new keyczar::rw::KeysetPBEJSONFileReader(FLAGS_policy_key_path.c_str(),
                                               *password));
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
    if (!ReceiveMessage(accept_sock, &a)) {
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

    // Create a new attestation to the same statement, but using the policy key
    Statement policy_statement;
    policy_statement.CopyFrom(orig_statement);

    Attestation policy_attest;
    policy_attest.set_type(tao::ROOT);
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

    if (!SendMessage(accept_sock, policy_attest)) {
      LOG(ERROR) << "Could not send the newly signed attestation in reply";
      continue;
    }
  }

  return 0;
}
