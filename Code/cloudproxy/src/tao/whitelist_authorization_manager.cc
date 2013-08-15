//  File: whitelist_authorization_manager.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the whitelist manager that handles
//  whitelist files signed with the policy public key.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#include "tao/whitelist_authorization_manager.h"
#include "tao/hosted_programs.pb.h"

#include <fstream>

using keyczar::Keyczar;
using std::ifstream;

namespace tao {

bool WhitelistAuthorizationManager::Init(const string &whitelist_path, const Keyczar &public_policy_key) {
  LOG(INFO) << "Loading the whitelist from " << whitelist_path;
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

  LOG(INFO) << "The number of program hashes is " << w.programs_size();
  for (int i = 0; i < w.programs_size(); i++) {
    const HostedProgram &hp = w.programs(i);
    if (whitelist_.find(hp.name()) != whitelist_.end()) {
      LOG(ERROR) << "Can't add " << hp.name() << " to the whitelist twice";
      return false;
    }
    
    LOG(INFO) << "Adding " << hp.name() << " to the whitelist";
    whitelist_[hp.name()] = hp.hash();
    hash_whitelist_.insert(hp.hash());
  }
  LOG(INFO) << "Done populating the whitelist";
  
  return true;
}

bool WhitelistAuthorizationManager::IsAuthorized(const string &program_hash) const {
  return hash_whitelist_.find(program_hash) != hash_whitelist_.end();
}

bool WhitelistAuthorizationManager::IsAuthorized(const string &program_name, const string &program_hash) const {
  auto it = whitelist_.find(program_name);
  if (it == whitelist_.end()) {
    return false;
  }

  return (it->second.compare(program_hash) == 0);
}

} // namespace tao
