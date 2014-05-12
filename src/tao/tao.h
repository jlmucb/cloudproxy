//  File: tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Interface used by hosted programs to access Tao services.
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
#ifndef TAO_TAO_H_
#define TAO_TAO_H_

#include <string>

#include "tao/attestation.pb.h"

namespace tao {
using std::string;

/// Tao is the fundamental Trustworthy Computing interface provided by a host to
/// its hosted programs. Each level of a system can act as a host by exporting
/// the Tao interface and providing Tao services to higher-level hosted
/// programs.
///
/// In most cases, a hosted program will use a stub Tao that performs RPC over a
/// channel to its host. The details of such RPC depend on the specific
/// implementation of the host: some hosted programs may use pipes to
/// communicate with their host, others may use sockets, etc.
class Tao {
 public:
  Tao() {}
  virtual bool Destroy() { return true; }
  virtual ~Tao() {
    if (host_tao_ == this) host_tao_ = nullptr;
  }

  /// Get the interface to the host Tao for this hosted program.
  /// Every hosted program is provided with one such interface.
  /// Ownership is of the returned pointer retained by this (static) class.
  static Tao *GetHostTao() { return host_tao_; }

  /// Set the interface to the host tao for this hosted program. The caller
  /// takes ownership of the previous Tao interface pointer, which is returned.
  /// @param tao The new Tao interface. Ownership is taken.
  virtual Tao *SetHostTao(Tao * tao) {
    Tao *prev_tao = host_tao_;
    host_tao_ = tao;
    return prev_tao;
  }

  /// Get the Tao principal name assigned to this hosted program. The name
  /// encodes the full path from the root Tao, through all intermediary Tao
  /// hosts, to this hosted program. The name will be globally unique: different
  /// hosted program (for some definition of "different") will be given
  /// different Tao names.
  /// @param[out] name The full, globally-unique name of this hosted program.
  virtual bool GetTaoName(string *name) const = 0;

  /// Irreversibly extend the Tao principal name of this hosted program. In
  /// effect, the hosted program can drop privileges by taking on the identity
  /// of its subprincipal.
  /// @param subprin The subprincipal to append to the principal name.
  virtual bool ExtendTaoName(const string &subprin) const = 0;

  /// Get random bytes.
  /// @param size The number of bytes to get.
  /// @param[out] bytes The random bytes.
  virtual bool GetRandomBytes(size_t size, string *bytes) const = 0;

  /// Request the Tao host sign a Statement on behalf of this hosted program.
  /// @param stmt A Statement to be signed. The issuer, time, and expiration
  /// fields will be filled in with appropriate defaults if they are left empty.
  /// @param[out] attestation The resulting signed attestation.
  virtual bool Attest(const Statement &stmt, string *attestation) const = 0;

  /// Encrypt data so only certain hosted programs can unseal it.
  /// @param data The data to seal.
  /// @param policy A policy controlling which hosted programs can seal or
  /// unseal the
  /// data. The semantics of this value are host-specific, except: all Tao hosts
  /// support at least the policies defined below; and the policy must be
  /// satisfied both during Seal() and during Unseal().
  /// @param[out] sealed The encrypted data.
  /// TODO(kwalsh) Add expiration.
  virtual bool Seal(const string &data, const string &policy,
                    string *sealed) const = 0;

  /// Decrypt data that has been sealed by the Seal() operation, but only
  /// if the policy specified during the Seal() operation is satisfied.
  /// @param sealed The sealed data to decrypt.
  /// @param[out] data The decrypted data, if the policy was satisfied.
  /// @param[out] policy The sealing policy, if it was satisfied.
  /// Note: The returned policy can be used as a limited integrity check, since
  /// only a hosted program that itself satisfies the policy could have
  /// performed the Seal() operation.
  virtual bool Unseal(const string &sealed, string *data,
                      string *policy) const = 0;

  /// Policy for sealing and unsealing. Hosts may implement additional policies.
  /// @{

  /// The default sealing policy, which corresponds roughly to "a past or future
  /// instance of a hosted program having a similar identity as the caller". The
  /// definition of "similar" is host-specific. For example, for a TPM, it may
  /// mean "has identical PCR values, for some subset of the PCRs". And for a
  /// Linux OS, it may mean "has the same program binary".
  constexpr static auto SealPolicyDefault = "self";

  /// The most conservative (but non-trivial) sealing policy supported by the
  /// host. For example, a Linux OS may interpret this to mean "the same hosted
  /// program instance, including process ID, program hash and argument hash".
  constexpr static auto SealPolicyConservative = "few";

  /// The most liberal (but non-trivial) sealing policy supported by the host.
  /// For example, a TPM may interpret this to mean "any hosted program on the
  /// same platform".
  constexpr static auto SealPolicyLiberal = "any";

  /// @}

  /// A context string for signed attestations.
  constexpr static auto AttestationSigningContext =
      "tao::Attestation Version 1";

  /// Default timeout for Attestation (= 1 year in seconds).
  static const int DefaultAttestationTimeout = 31556926;

 private:
  static Tao *host_tao_;
};
}  // namespace tao

#endif  // TAO_TAO_H_
