//  File: acl_guard.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization guard based on ACLs.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#ifndef TAO_ACL_GUARD_H_
#define TAO_ACL_GUARD_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/values.h>

#include "tao/acl_guard.pb.h"
#include "tao/tao_domain.h"

using std::list;
using std::string;

namespace tao {

/// An authorization guard that uses ACLs stored in a single file, signed by the
/// policy key.
class ACLGuard : public TaoDomain {
 public:
  /// Name strings for name:value pairs in JSON config.
  constexpr static auto JSONSignedACLsPath = "signed_acls_path";

  ACLGuard(const string &path, DictionaryValue *value)
      : TaoDomain(path, value) {}
  virtual ~ACLGuard() {}

  /// These methods have the same semantics as in TaoGuard.
  /// @{
  virtual bool IsAuthorized(const string &name, const string &op,
                            const list<string> &args) const;
  virtual bool Authorize(const string &name, const string &op,
                         const list<string> &args);
  virtual bool Forbid(const string &name, const string &op,
                      const list<string> &args);
  virtual string DebugString() const;
  /// @}

  /// Get a count of how many ACL entries there are.
  int ACLEntryCount() const;

  /// Get information about the i^th ACL entry.
  bool GetACLEntry(int i, string *name, string *op, list<string> *args) const;
  bool GetACLEntry(int i, string *desc) const;

  // TODO(kwalsh) Maybe also map a name to pair<op, args>?

  constexpr static auto ACLSigningContext = "tao::SignedACLs Version 1";

  constexpr static auto GuardType = "ACLs";

 protected:
  /// Parse all configuration parameters from the configuration file and load
  /// keys and other state. This loads and checks the signature on the
  /// ACLs, then imports it into a local data store.
  virtual bool ParseConfig();

  /// Save all configuration parameters to the configuration file and save all
  /// other state. This signs and saves the ACLs. This fails if the
  /// TaoDomain is locked.
  virtual bool SaveConfig() const;

  /// Check whether an acl entry matches a given name, op, args tuple.
  virtual bool IsMatchingEntry(const ACLEntry &entry, const string &name,
                               const string &op,
                               const list<string> &args) const;

  string DebugString(const ACLEntry &entry) const;

 private:
  // The set of ACL entries.
  ACLSet aclset_;

  DISALLOW_COPY_AND_ASSIGN(ACLGuard);
};
}  // namespace tao

#endif  // TAO_ACL_GUARD_H_
