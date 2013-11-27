//  File: whitelist_auth.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The whitelist manager handles whitelist files signed
//  with the policy public key.
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

#ifndef TAO_WHITELIST_AUTH_H_
#define TAO_WHITELIST_AUTH_H_

#include "tao/tao_auth.h"

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include <map>
#include <set>

using std::map;
using std::set;

namespace tao {
class WhitelistAuth : public TaoAuth {
 public:
  WhitelistAuth(const string &whitelist_path, const string &policy_public_key) : whitelist_path_(whitelist_path), policy_public_key_(policy_public_key), policy_key_(NULL), whitelist_(), hash_whitelist_() {}
  virtual ~WhitelistAuth() {}
  virtual bool Init();
  virtual bool IsAuthorized(const string &program_hash) const;
  virtual bool IsAuthorized(const string &program_name,
                            const string &program_hash) const;
  virtual bool IsAuthorized(const Attestation &attestation) const;
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 private:
  string whitelist_path_;
  string policy_public_key_;
  scoped_ptr<keyczar::Keyczar> policy_key_;
  map<string, string> whitelist_;
  set<string> hash_whitelist_;

  // Checks a signature made by the public policy key
  bool CheckRootSignature(const Attestation &a) const;

  // Checks a signature made by an intermediate Tao
  bool CheckIntermediateSignature(const Attestation &a) const;

  // Checks a signature in the TPM 1.2 Quote format
  bool CheckTPM12Quote(const Attestation &a) const;

  DISALLOW_COPY_AND_ASSIGN(WhitelistAuth);
};
}  // namespace tao

#endif  // TAO_WHITELIST_AUTH_H_
