//  File: acl_guard.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization guard based on ACLs.
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
#include "tao/acl_guard.h"

#include <list>
#include <sstream>
#include <string>

#include <glog/logging.h>

#include "tao/acl_guard.pb.h"
#include "tao/util.h"

namespace tao {
bool ACLGuard::AddRule(const string &rule) {
  aclset_.add_entries(rule);
  return SaveConfig();
}

bool ACLGuard::RetractRule(const string &rule) {
  bool found = false;
  for (int i = aclset_.entries_size() - 1; i >= 0; i--) {
    if (aclset_.entries(i) == rule) {
      found = true;
      aclset_.mutable_entries()->DeleteSubrange(i, 1);
    }
  }
  if (!found) {
    LOG(WARNING) << "Rule to be revoked was not found";
    return false;
  }
  return SaveConfig();
}

bool ACLGuard::Clear() {
  aclset_.clear_entries();
  return SaveConfig();
}

bool ACLGuard::Query(const string &query) {
  for (auto &entry : aclset_.entries()) {
    if (entry == query) {
      return true;
    }
  }
  return false;
}

int ACLGuard::RuleCount() const { return aclset_.entries_size(); }

string ACLGuard::GetRule(int i) const { return aclset_.entries(i); }

bool ACLGuard::ParseConfig() {
  // Load basic configuration.
  if (!TaoDomain::ParseConfig()) {
    LOG(ERROR) << "Can't load basic configuration";
    return false;
  }
  // Load the signed ACL set file.
  string path = GetConfigPath(JSONSignedACLsPath);
  string serialized;
  if (!ReadFileToString(path, &serialized)) {
    LOG(ERROR) << "Can't load signed ACL set from " << path;
    return false;
  }
  // Parse the signed ACL set.
  SignedACLSet sacls;
  if (!sacls.ParseFromString(serialized)) {
    LOG(ERROR) << "Can't parse signed ACL set from " << path;
    return false;
  }
  // Verify its signature.
  if (!GetPolicyKeys()->Verify(sacls.serialized_aclset(), ACLSigningContext,
                               sacls.signature())) {
    LOG(ERROR) << "Signature did not verify on signed ACL set from " << path;
    return false;
  }
  // Parse the ACL set.
  if (!aclset_.ParseFromString(sacls.serialized_aclset())) {
    LOG(ERROR) << "Can't parse serialized ACL set from " << path;
    return false;
  }
  return true;
}

bool ACLGuard::SaveConfig() const {
  if (GetPolicySigner() == nullptr) {
    LOG(ERROR) << "Can't sign ACL set, admin is currently locked.";
    return false;
  }
  // Save basic configuration.
  if (!TaoDomain::SaveConfig()) {
    LOG(ERROR) << "Can't save basic configuration";
    return false;
  }
  // Serialize ACL set.
  string serialized_aclset;
  if (!aclset_.SerializeToString(&serialized_aclset)) {
    LOG(ERROR) << "Could not serialize the ACL set";
    return false;
  }
  // Sign ACL set.
  string aclset_signature;
  if (!GetPolicyKeys()->Sign(serialized_aclset, ACLSigningContext,
                             &aclset_signature)) {
    LOG(ERROR) << "Can't sign ACL set";
    return false;
  }
  SignedACLSet sacls;
  sacls.set_serialized_aclset(serialized_aclset);
  sacls.set_signature(aclset_signature);
  string serialized;
  if (!sacls.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the signed ACL set";
    return false;
  }
  // Save signed ACL set.
  string path = GetConfigPath(JSONSignedACLsPath);
  if (!WriteStringToFile(path, serialized)) {
    LOG(ERROR) << "Can't write signed ACL set to " << path;
    return false;
  }
  return true;
}

}  // namespace tao
