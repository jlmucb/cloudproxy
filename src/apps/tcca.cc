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
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/attestation.pb.h"
#include "tao/tao.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using tao::Attestation;
using tao::InitializeOpenSSL;
using tao::OpenTCPSocket;
using tao::ReceiveMessage;
using tao::ScopedFd;
using tao::SendMessage;
using tao::Statement;
using tao::Tao;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "cppolicy", "A password for the policy private key");

static bool StopFlag = false;
void term_handler(int sig) {
  StopFlag = true;
  LOG(INFO) << "Received SIGTERM. Shutting down...";
}

int main(int argc, char **argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  google::InstallFailureSignalHandler();

  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = term_handler;
  if (sigaction(SIGTERM, &act, nullptr) < 0) {
    PLOG(ERROR) << "Could not set up a handler to catch SIGERM";
    return 1;
  }

  if (!InitializeOpenSSL()) {
    LOG(ERROR) << "Could not initialize the OpenSSL library";
    return 1;
  }

  scoped_ptr<TaoDomain> admin(
      TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  string host = admin->GetTaoCAHost();
  string port = admin->GetTaoCAPort();
  int sock = 0;
  if (!OpenTCPSocket(host, port, &sock)) {
    LOG(ERROR) << "Could not open a TCP socket for listening on " << host << ":"
               << port;
    return 1;
  }

  LOG(INFO) << "TCCA Listening for connections on " << host << ":" << port;

  while (!StopFlag) {
    ScopedFd accept_sock(new int(accept(sock, nullptr, nullptr)));
    if (*accept_sock == -1) {
      if (errno != EINTR) {
        PLOG(ERROR) << "Could not accept a connection on the socket";
        return 1;
      }

      continue;
    }

    Attestation a;
    if (!ReceiveMessage(*accept_sock, &a)) {
      LOG(ERROR) << "Could not receive a message from the socket";
      continue;
    }

    string serialized_attest;
    if (!a.SerializeToString(&serialized_attest)) {
      LOG(ERROR) << "Could not serialize the attestation";
      continue;
    }

    string data;
    if (!admin->VerifyAttestation(serialized_attest, &data)) {
      LOG(ERROR) << "The provided attestation did not pass verification";
      continue;
    }

    Statement orig_statement;
    if (!orig_statement.ParseFromString(a.serialized_statement())) {
      LOG(ERROR)
          << "Could not parse the original statement from the attestation";
      continue;
    }

    // Create a new attestation to the same statement, but using the policy key
    Statement root_statement;
    root_statement.CopyFrom(orig_statement);

    Attestation root_attestation;
    if (!admin->AttestByRoot(&root_statement, &root_attestation)) {
      LOG(ERROR) << "Could not sign a new root attestation";
      continue;
    }

    if (!SendMessage(*accept_sock, root_attestation)) {
      LOG(ERROR) << "Could not send the newly signed attestation in reply";
      continue;
    }
  }

  VLOG(1) << "Shutting down tcca";
  return 0;
}
