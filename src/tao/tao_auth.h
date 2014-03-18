//  File: tao_auth.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An interface for hosted-program authorization mechanisms
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

#ifndef TAO_TAO_AUTH_H_
#define TAO_TAO_AUTH_H_

#include <string>

using std::string;

namespace tao {
/// An interface that is used to answer authorization questions for hosts and
/// hosted programs under the Tao.
class TaoAuth {
 public:
  /// Typical hash algorithm for programs.
  constexpr static auto Sha256 = "SHA256";
  /// Typical hash algorithm for TPM pcrs.
  constexpr static auto PcrSha1 = "PCR_SHA1";
  /// Typical hash algorithm for testing when no actual hash is available.
  constexpr static auto FakeHash = "FAKE_HASH";

  virtual ~TaoAuth() {}

  /// Check that a given hash is authorized to execute under and speak for
  /// the given name.
  /// @param hash The hash to check
  /// @param alg The algorithm used to compute the hash
  /// @param name The name to check
  virtual bool IsAuthorized(const string &hash, const string &alg,
                            const string &name) const = 0;

  /// Check that a given hash (e.g. of a program or of some pcrs) is authorized
  /// to execute in this administrative domain under some name.
  /// @param hash The hash to check
  /// @param alg The algorithm used to compute the hash
  /// @param name[out] If not null, some name under which the hash was
  /// authorized to execute
  /// TODO(kwalsh) rename to avoid similarity with other function
  virtual bool IsAuthorized(const string &hash, const string &alg,
                            string *name) const = 0;

  /// Check an attestation produced by the Tao method Attest for a given data
  /// string.
  /// @param attestation A serialized Attestation
  /// @param[out] data The extracted data from the Statement in the Attestation
  /// @return true if the attestation passes verification
  virtual bool VerifyAttestation(const string &attestation,
                                 string *data) const = 0;

  /// Authorize a hash to execute under and speak for the given name.
  /// @param alg The algorithm used to compute the hash
  /// @param hash The hash for the binding
  /// @param name The name that will be bound to this hash
  virtual bool Authorize(const string &hash, const string &alg,
                         const string &name) = 0;

  /// Attempt to revoke all authorizations for any hashes to execute under or
  /// speak for a given name.
  /// @param name The name that will be revoked
  virtual bool Forbid(const string &name) = 0;

  /// Get a string suitable for showing users authorization info.
  virtual string DebugString() const = 0;
};
}  // namespace tao

#endif  // TAO_TAO_AUTH_H_
