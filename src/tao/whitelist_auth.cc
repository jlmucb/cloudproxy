//  File: whitelist_auth.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the whitelist manager that handles
//  whitelist files signed with the policy public key.
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



#include "tao/whitelist_auth.h"
#include "tao/hosted_programs.pb.h"

#include <fstream>

using keyczar::Keyczar;
using std::ifstream;

namespace tao {

bool WhitelistAuth::Init(const string &whitelist_path,
                                         const Keyczar &public_policy_key) {
  // load the whitelist file and check its signature
  ifstream whitelist(whitelist_path);

  SignedWhitelist sw;
  sw.ParseFromIstream(&whitelist);
  if (!public_policy_key.Verify(sw.serialized_whitelist(), sw.signature())) {
    LOG(ERROR) << "The signature did not verify on the signed whitelist";
    return false;
  }

  Whitelist w;
  const string &serialized_w = sw.serialized_whitelist();

  if (!w.ParseFromString(serialized_w)) {
    LOG(ERROR) << "Could not parse the serialized whitelist";
    return false;
  }

  for (int i = 0; i < w.programs_size(); i++) {
    const HostedProgram &hp = w.programs(i);
    if (whitelist_.find(hp.name()) != whitelist_.end()) {
      LOG(ERROR) << "Can't add " << hp.name() << " to the whitelist twice";
      return false;
    }

    whitelist_[hp.name()] = hp.hash();
    hash_whitelist_.insert(hp.hash());
  }

  return true;
}

bool WhitelistAuth::IsAuthorized(
    const string &program_hash) const {
  return hash_whitelist_.find(program_hash) != hash_whitelist_.end();
}

bool WhitelistAuth::IsAuthorized(
    const string &program_name, const string &program_hash) const {
  auto it = whitelist_.find(program_name);
  if (it == whitelist_.end()) {
    return false;
  }

  return (it->second.compare(program_hash) == 0);
}

}  // namespace tao
