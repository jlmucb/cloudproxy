//  File: root_auth.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An auth manager that only accepts applications and attestations
//  if they are directly signed by the policy key.
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
#ifndef TAO_ROOT_AUTH_H_
#define TAO_ROOT_AUTH_H_

#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/values.h>

#include "tao/attestation.pb.h"
#include "tao/tao_domain.h"

using std::string;

namespace tao {
/// An authorization component that only accepts signatures from the public
/// policy key.
class RootAuth : public TaoDomain {
 public:
  RootAuth(const string &path, DictionaryValue *value)
      : TaoDomain(path, value) {}
  virtual ~RootAuth() {}

  /// Only root attestations are allowed, so IsAuthorized() is always false.
  virtual bool IsAuthorized(const string &hash, const string &alg,
                            const string &name) const {
    return false;
  }
  /// Only root attestations are allowed, so IsAuthorized() is always false.
  virtual bool IsAuthorized(const string &hash, const string &alg,
                            string *name) const {
    return false;
  }

  /// Checks if an attestation is from root and is well formed.
  /// @param attestation A serialized Attestation
  /// @param[out] data The extracted data from the Statement in the Attestation
  /// @return true if the attestation passes verification
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

  /// Only root attestations are allowed, so disallow Authorize().
  virtual bool Authorize(const string &hash, const string &alg,
                         const string &name) {
    return false;
  }

  /// Only root attestations are allowed, so disallow Forbid().
  virtual bool Forbid(const string &name) { return false; }

  /// Nothing to show user since we don't hold the attestations.
  virtual string DebugString() {
    return "Policy-Root signed authorizations only";
  }

  constexpr static auto AuthType = "root";

 private:
  DISALLOW_COPY_AND_ASSIGN(RootAuth);
};
}  // namespace tao

#endif  // TAO_ROOT_AUTH_H_
