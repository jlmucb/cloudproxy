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

#include <map>
#include <set>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/scoped_ptr.h>

#include "tao/attestation.pb.h"
#include "tao/tao_auth.h"

using std::map;
using std::set;

namespace keyczar {

class Keyczar;

}  // namespace keyczar

namespace tao {
/// An authorization verifier that uses a signed whitelist to map hosted program
/// names to hashes. The whitelist is signed by the policy key. This allows
/// hosted programs to communicate without talking to tcca. This is also used by
/// tcca itself to decide whether to sign a request or not.
class WhitelistAuth : public TaoAuth {
 public:
  /// Store information about the whitelist and the public key, but don't
  /// evaluate it yet.
  /// @param whitelist_path The path to the whitelist to use.
  /// @param policy_public_key The path to the policy public key.
  WhitelistAuth(const string &whitelist_path, const string &policy_public_key)
      : whitelist_path_(whitelist_path),
        policy_public_key_(policy_public_key),
        policy_key_(NULL),
        whitelist_(),
        hash_whitelist_() {}
  virtual ~WhitelistAuth() {}

  /// Evaluate the information provided in the constructor: load the public
  /// policy key, check the signature on the whitelist, and import it into a
  /// local data store.
  virtual bool Init();

  // The following methods have the same semantics as in TaoAuth.
  virtual bool IsAuthorized(const string &program_hash) const;
  virtual bool IsAuthorized(const string &program_name,
                            const string &program_hash) const;
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 private:
  string whitelist_path_;

  // The path to the public policy key.
  string policy_public_key_;

  // The in-memory representation of the public policy key.
  scoped_ptr<keyczar::Keyczar> policy_key_;

  // A representation of the whitelist: it maps program names to hashes.
  map<string, string> whitelist_;

  // All the hashes that are values in the whitelist.
  set<string> hash_whitelist_;

  /// Checks to see if the attestation has expired. If it's not a ROOT
  /// attestation, then it checks to see if the hash is in the whitelist.
  /// @param attestation The attestation to verify.
  bool CheckAuthorization(const Attestation &attestation) const;

  /// Checks a signature made by the public policy key
  bool CheckRootSignature(const Attestation &a) const;

  /// Checks a signature made by an intermediate Tao
  bool CheckIntermediateSignature(const Attestation &a) const;

  /// Checks a signature in the TPM 1.2 Quote format
  bool CheckTPM12Quote(const Attestation &a) const;

  DISALLOW_COPY_AND_ASSIGN(WhitelistAuth);
};
}  // namespace tao

#endif  // TAO_WHITELIST_AUTH_H_
