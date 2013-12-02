//  File: root_auth.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of root-only authentication.
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

#include "tao/root_auth.h"

#include <fstream>

#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/util.h"

using keyczar::Keyczar;
using keyczar::Keyset;
using keyczar::Verifier;

using std::ifstream;

namespace tao {
bool RootAuth::Init() {
  // Load the public policy key
  policy_key_.reset(keyczar::Verifier::Read(policy_public_key_.c_str()));
  policy_key_->set_encoding(keyczar::Keyczar::NO_ENCODING);

  return true;
}

bool RootAuth::VerifyAttestation(const string &attestation,
                                 string *data) const {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not deserialize an Attestation";
    return false;
  }

  if (a.type() != ROOT) {
    LOG(ERROR) << "Only root attestations are supported";
    return false;
  }

  if (!CheckRootSignature(a)) {
    LOG(ERROR) << "The root signature fails verification";
    return false;
  }

  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the statement";
    return false;
  }

  // check the time to make sure it's still valid
  time_t cur_time;
  time(&cur_time);
  if (s.expiration() < cur_time) {
    LOG(ERROR) << "Signature is no longer valid";
    return false;
  }

  data->assign(s.data().data(), s.data().size());

  VLOG(1) << "The attestation passed verification";

  return true;
}

bool RootAuth::CheckRootSignature(const Attestation &a) const {
  VLOG(2) << "About to verify the signature against the policy key";
  VLOG(2) << "a.serialized_statement().size = "
          << (int)a.serialized_statement().size();
  VLOG(2) << "a.signature().size = " << (int)a.signature().size();

  // Verify against the policy key.
  if (!policy_key_->Verify(a.serialized_statement(), a.signature())) {
    LOG(ERROR) << "Verification failed with the policy key";
    return false;
  }

  return true;
}
}  // namespace tao
