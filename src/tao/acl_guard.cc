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

bool ACLGuard::GetSubprincipalName(string *subprin) const {
  // Use policy key as part of name
  string key_prin;
  if (!GetPolicyKeys()->GetPrincipalName(&key_prin)) {
    LOG(ERROR) << "Could not get policy key principal name";
    return false;
  }
  subprin->assign("ACLGuard(" + key_prin + ")");
  return true;
}

// TODO(kwalsh) Add wildcard feature for name, op, and args.

bool ACLGuard::IsMatchingEntry(const ACLEntry &entry, const string &name,
                               const string &op,
                               const list<string> &args) const {
  if (entry.name() != name) return false;
  if (entry.op() != op) return false;
  if (entry.args_size() != int(args.size())) return false;
  int i = 0;
  for (auto &arg : args)
    if (entry.args(i++) != arg) return false;
  return true;
}

bool ACLGuard::IsAuthorized(const string &name, const string &op,
                            const list<string> &args) const {
  for (auto &entry : aclset_.entries()) {
    if (IsMatchingEntry(entry, name, op, args)) {
      LOG(INFO) << "Principal " << elideString(name)
                << " is authorized to perform " << op << "(...)";
      return true;
    }
  }
  LOG(INFO) << "Principal " << elideString(name)
            << " is not authorized to perform " << op << "(...)";
  LOG(INFO) << DebugString();
  return false;
}

bool ACLGuard::Authorize(const string &name, const string &op,
                         const list<string> &args) {
  ACLEntry *entry = aclset_.add_entries();
  entry->set_name(name);
  entry->set_op(op);
  for (auto &arg : args) entry->add_args(arg);
  return SaveConfig();
}

bool ACLGuard::Revoke(const string &name, const string &op,
                      const list<string> &args) {
  bool found = false;
  for (int i = aclset_.entries_size() - 1; i >= 0; i--) {
    if (IsMatchingEntry(aclset_.entries(i), name, op, args)) {
      found = true;
      aclset_.mutable_entries()->DeleteSubrange(i, 1);
    }
  }
  if (!found)
    LOG(WARNING) << "Principal " << name << " was not authorized to perform "
                 << op << "(...)";
  return found;
}

string ACLGuard::DebugString() const {
  std::stringstream out;
  out << "Set of " << aclset_.entries_size() << " authorizations:";
  int i = 0;
  for (auto &entry : aclset_.entries())
    out << "\n  " << (i++) << ". " << DebugString(entry);
  return out.str();
}

int ACLGuard::ACLEntryCount() const { return aclset_.entries_size(); }

bool ACLGuard::GetACLEntry(int i, string *name, string *op,
                           list<string> *args) const {
  if (i < 0 || i > aclset_.entries_size()) {
    LOG(ERROR) << "Invalid ACL entry index";
    return false;
  }
  const ACLEntry &entry = aclset_.entries(i);
  name->assign(entry.name());
  op->assign(entry.op());
  args->clear();
  for (auto &arg : entry.args()) args->push_back(arg);
  return true;
}

bool ACLGuard::GetACLEntry(int i, string *desc) const {
  if (i < 0 || i > aclset_.entries_size()) {
    LOG(ERROR) << "Invalid ACL entry index";
    return false;
  }
  const ACLEntry &entry = aclset_.entries(i);
  desc->assign(DebugString(entry));
  return true;
}

string ACLGuard::DebugString(const ACLEntry &entry) const {
  std::stringstream out;
  out << elideString(entry.name()) << " : " << entry.op() << "(";
  string delim = "";
  for (auto &arg : entry.args()) {
    out << delim << elideString(arg);
    delim = ", ";
  }
  out << ")";
  return out.str();
}

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
  string aclset_signature;
  if (!GetPolicyKeys()->Sign(serialized_aclset, ACLSigningContext,
                             &aclset_signature)) {
    LOG(ERROR) << "Can't sign ACL set";
    return false;
  }
  // Sign ACL set.
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
