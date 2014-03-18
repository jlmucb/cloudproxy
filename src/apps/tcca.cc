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
#include <keyczar/keyczar.h>

#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/tao.h"
#include "tao/tao_ca.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using keyczar::Verifier;

using tao::DeserializePublicKey;
using tao::InitializeApp;
using tao::OpenTCPSocket;
using tao::ReceiveMessage;
using tao::ScopedFd;
using tao::SendMessage;
using tao::Statement;
using tao::TaoCARequest;
using tao::TaoCAResponse;
using tao::TaoDomain;
using tao::X509Details;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "cppolicy", "A password for the policy private key");

static bool StopFlag = false;
void term_handler(int sig) {
  StopFlag = true;
  LOG(INFO) << "Received SIGTERM. Shutting down...";
}

// FIXME(kwalsh) The TCCA protocol is built into LinuxTao so should be moved
// into tao/tao_ca.{cc,h} or similar.

bool HandleRequestAttestation(const TaoDomain *admin, const TaoCARequest &req,
                              TaoCAResponse *resp, string *key_data) {
  if (!req.has_attestation()) {
    LOG(ERROR) << "Request is missing attestation";
    return false;
  }

  string serialized_attest;
  if (!req.attestation().SerializeToString(&serialized_attest)) {
    LOG(ERROR) << "Could not serialize the attestation";
    return false;
  }

  if (!admin->VerifyAttestation(serialized_attest, key_data)) {
    LOG(ERROR) << "The provided attestation did not pass verification";
    return false;
  }

  Statement orig_statement;
  if (!orig_statement.ParseFromString(
          req.attestation().serialized_statement())) {
    LOG(ERROR) << "Could not parse the original statement from the attestation";
    return false;
  }

  // Create a new attestation to same key as orig_statement, signed with policy
  // key
  Statement root_statement;
  // root_statement.CopyFrom(orig_statement);
  root_statement.set_time(orig_statement.time());
  root_statement.set_expiration(orig_statement.expiration());
  root_statement.set_data(orig_statement.data());

  if (!admin->AttestByRoot(&root_statement, resp->mutable_attestation())) {
    LOG(ERROR) << "Could not sign a new root attestation";
    return false;
  }

  return true;
}

bool HandleRequestX509Chain(TaoDomain *admin, const TaoCARequest &req,
                            const string &key_data, TaoCAResponse *resp) {
  if (!req.has_x509details()) {
    LOG(ERROR) << "Request is missing x509 certificate";
    return false;
  }
  if (!req.has_attestation() || !resp->has_attestation()) {
    LOG(ERROR) << "Request is missing valid attestation";
    return false;
  }
  // extract public key from the verified attestation

  const X509Details &subject_details = req.x509details();

  // TODO(kwalsh): This code assumes that all verified attestations
  // sent to tcca are of serialized public keys.
  scoped_ptr<Verifier> subject_key;
  if (!DeserializePublicKey(key_data, &subject_key)) {
    LOG(ERROR) << "Could not deserialize the public key";
    return false;
  }

  // Get a version number
  int cert_serial = admin->GetFreshX509CertificateSerialNumber();
  if (cert_serial == -1) {
    LOG(ERROR) << "Could not get fresh x509 serial number";
    return false;
  }

  if (!admin->GetPolicyKeys()->CreateCASignedX509(cert_serial, *subject_key,
                                                  subject_details,
                                                  resp->mutable_x509chain())) {
    LOG(ERROR) << "Could not generate x509 chain";
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = term_handler;
  if (sigaction(SIGTERM, &act, nullptr) < 0) {
    PLOG(ERROR) << "Could not set up a handler to catch SIGERM";
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

    TaoCARequest req;
    if (!ReceiveMessage(*accept_sock, &req)) {
      LOG(ERROR) << "Could not receive a TaoCA request from the socket";
      continue;
    }

    TaoCAResponse resp;
    string key_data;
    bool ok = true;
    switch (req.type()) {
      case tao::TAO_CA_REQUEST_ATTESTATION:
        if (!HandleRequestAttestation(admin.get(), req, &resp, &key_data)) {
          resp.set_reason("Attestation failed");
          ok = false;
        }
        if (ok && req.has_x509details()) {
          if (!HandleRequestX509Chain(admin.get(), req, key_data, &resp)) {
            resp.set_reason("Certificate chain generation failed");
            ok = false;
          }
        }
        break;
      default:
        LOG(ERROR) << "Unknown TaoCA request type";
        resp.set_reason("Unknown TaoCA request type");
        ok = false;
        break;
    }
    resp.set_type(ok ? tao::TAO_CA_RESPONSE_SUCCESS
                     : tao::TAO_CA_RESPONSE_FAILURE);

    if (!SendMessage(*accept_sock, resp)) {
      LOG(ERROR) << "Could not send a Tao CA response";
      continue;
    }
  }

  VLOG(1) << "Shutting down tcca";
  return 0;
}
