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

#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/tao.h"
#include "tao/util.h"

namespace tao {

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
  time_t cur_time;
  time(&cur_time);
  // TODO(kwalsh) check notbefore as well
  // if (cur_time < s.time()) {
  //  LOG(ERROR) << "Signature is not yet valid";
  //  return false;
  //}
  if (cur_time > s.expiration()) {
    LOG(ERROR) << "Signature is no longer valid";
    return false;
  }
  data->assign(s.data().data(), s.data().size());

  // TODO(kwalsh) - make a pretty printer for attestation chains
  // VLOG(5) << "RootAuth verified attestation\n" << AttestationDebugString(a);

  return true;
}

}  // namespace tao
