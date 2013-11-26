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

typedef unsigned int UINT32;
typedef unsigned short UINT16;

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

bool WhitelistAuth::IsAuthorized(const string &program_hash) const {
  return hash_whitelist_.find(program_hash) != hash_whitelist_.end();
}

bool WhitelistAuth::IsAuthorized(const string &program_name,
                                 const string &program_hash) const {
  auto it = whitelist_.find(program_name);
  if (it == whitelist_.end()) {
    return false;
  }

  return (it->second.compare(program_hash) == 0);
}

bool WhitelistAuth::IsAuthorized(const Attestation &attestation) const {
  Statement s;
  if (!s.ParseFromString(attestation.serialized_statement())) {
    LOG(ERROR) << "Could not parse the statement from an attestation";
    return false;
  }

  if (s.hash_alg().compare("SHA256")) {
    // This is a normal program-like hash, so check the whitelist directly
    return IsAuthorized(s.hash());
  }

  if (attestation.has_quote()) {
    // Extract the PCRs as a single string and look for them in the whitelist.
    string quote(attestation.quote());
    size_t quote_len = quote.size();
    if (quote_len < sizeof(UINT16)) {
      LOG(ERROR) << "The quote was not long enough to contain a mask length";
      return false;
    }

    const char *quote_bytes = quote.c_str();
    UINT32 index = 0;
    UINT16 mask_len = *(UINT16 *)(quote_bytes + index);
    index += sizeof(UINT16);

    // skip the mask bytes
    if ((quote_len < index) || (quote_len - index < mask_len)) {
      LOG(ERROR) << "The quote was not long enough to contain the mask";
      return false;
    }

    index += mask_len;

    if ((quote_len < index) || (quote_len - index < sizeof(UINT32))) {
      LOG(ERROR) << "The quote was not long enough to contain the pcr length";
      return false;
    }

    UINT32 pcr_len = *(UINT32 *)(quote_bytes + index);
    index += sizeof(UINT32);

    if ((quote_len < index) || (quote_len - index < pcr_len)) {
      LOG(ERROR) << "The quote was not long enough to contain the PCRs";
      return false;
    }

    string pcrs(quote_bytes + index, pcr_len);
    return IsAuthorized(pcrs);
  }

  return false;
}
}  // namespace tao
