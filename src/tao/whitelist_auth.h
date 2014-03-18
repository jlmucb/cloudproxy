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

#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/values.h>

#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/tao_domain.h"

using std::string;

namespace tao {
/// An authorization verifier that uses a signed whitelist to map hosted program
/// names to hashes. The whitelist is signed by the policy key. This allows
/// hosted programs to communicate without talking to tcca. This is also used by
/// tcca itself to decide whether to sign a request or not.
class WhitelistAuth : public TaoDomain {
 public:
  /// Name strings for name:value pairs in JSON config.
  constexpr static auto JSONSignedWhitelistPath = "signed_whitelist_path";

  WhitelistAuth(const string &path, DictionaryValue *value)
      : TaoDomain(path, value) {}
  virtual ~WhitelistAuth() {}

  // The following methods have the same semantics as in TaoAuth.
  virtual bool IsAuthorized(const string &hash, const string &alg,
                            const string &name) const;
  virtual bool IsAuthorized(const string &hash, const string &alg,
                            string *name) const;
  virtual bool VerifyAttestation(const string &attestation, string *data) const;
  virtual bool Authorize(const string &hash, const string &alg,
                         const string &name);
  virtual bool Forbid(const string &name);
  virtual string DebugString() const;

  /// Get a count of how many whitelist entries there are.
  int WhitelistCount() const;

  /// Get information about the i^th whitelist entry.
  bool WhitelistEntry(int i, string *hash, string *alg, string *name) const;

  constexpr static auto WhitelistSigningContext =
      "tao::SignedWhitelist Version 1";

  constexpr static auto AuthType = "whitelist";

 protected:
  /// Parse all configuration parameters from the configuration file and load
  /// keys and other state. This loads and checks the signature on the
  /// whitelist, then imports it into a local data store.
  virtual bool ParseConfig();

  /// Save all configuration parameters to the configuration file and save all
  /// other state. This signs and saves the whitelist. This fails if the
  /// TaoDomain is locked.
  virtual bool SaveConfig() const;

 private:
  // The policy whitelist, to be verified against the policy public key
  Whitelist whitelist_;

  /// Checks to see if the attestation has expired. If it's not a ROOT
  /// attestation, then it checks to see if the hash is in the whitelist.
  /// @param attestation The attestation to verify.
  bool CheckAuthorization(const Attestation &attestation) const;

  /// Checks a signature made by an intermediate Tao
  bool CheckIntermediateSignature(const Attestation &a) const;

  /// Checks a signature in the TPM 1.2 Quote format
  bool CheckTPM12Quote(const Attestation &a) const;

  DISALLOW_COPY_AND_ASSIGN(WhitelistAuth);
};
}  // namespace tao

#endif  // TAO_WHITELIST_AUTH_H_
