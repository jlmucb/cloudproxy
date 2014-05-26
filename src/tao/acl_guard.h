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

#include <keyczar/base/values.h>

#include "tao/acl_guard.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

namespace tao {

/// An authorization guard that uses ACLs stored in a single file, signed by the
/// policy key.
class ACLGuard : public TaoDomain {
 public:
  /// Name strings for name:value pairs in JSON config.
  constexpr static auto JSONSignedACLsPath = "signed_acls_path";

  /// Example json strings useful for constructing domains for testing.
  constexpr static auto ExampleGuardDomain =
      "{\n"
      "   \"name\": \"Tao example ACL-based domain\",\n"
      "\n"
      "   \"policy_keys_path\":     \"policy_keys\",\n"
      "   \"policy_x509_details\":  \"country: \\\"US\\\" state: "
      "\\\"Washington\\\" organization: \\\"Google\\\" commonname: \\\"tao "
      "example domain\\\"\",\n"
      "   \"policy_x509_last_serial\": 0,\n"
      "\n"
      "   \"guard_type\": \"ACLs\",\n"
      "   \"signed_acls_path\": \"domain_acls\",\n"
      "\n"
      "   \"tao_ca_host\": \"localhost\",\n"
      "   \"tao_ca_port\": \"11238\"\n"
      "}";

  ACLGuard(const string &path, DictionaryValue *value)
      : TaoDomain(path, value) {}

  virtual string GuardTypeName() const { return "ACLGuard"; }

  /// These methods have the same semantics as in TaoGuard. ACLGuard supports
  /// the basic syntax for rules and queries, i.e. 
  ///   Authorized(P, op, args...).
  /// ACLGuard does not interpret the rules and queries in any way, so
  /// additional rules and queries could be used if desired. There is little use
  /// for this feature, however, as op and args already encode arbitrary,
  /// uninterpreted strings.
  /// @{
  virtual bool AddRule(const string &rule);
  virtual bool RetractRule(const string &rule);
  virtual bool Clear();
  virtual bool Query(const string &query);
  virtual int RuleCount() const;
  virtual string GetRule(int i) const;
  /// @}

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

  /// Reload ACLs from disk if they were changed recently.
  bool ReloadACLsIfModified();

 private:
  // The set of ACL entries.
  ACLSet aclset_;

  // The path to the signed ACL file.
  string acl_path_;

  // Modification time of signed ACL file when it was read.
  time_t acl_mod_time_;

  // Minimum time in seconds before re-checking modification time of ACL file.
  constexpr static int ACLFileRefreshTimeout = 10;

  DISALLOW_COPY_AND_ASSIGN(ACLGuard);
};
}  // namespace tao

#endif  // TAO_ACL_GUARD_H_
