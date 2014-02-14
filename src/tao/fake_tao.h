//  File: fake_tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A fake implementation of the Tao interface that isn't
//  backed by any trusted hardware.
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
#ifndef TAO_FAKE_TAO_H_
#define TAO_FAKE_TAO_H_

#include <list>
#include <string>

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "tao/tao.h"
#include "tao/tao_domain.h"

using std::list;
using std::string;

namespace tao {
class TaoDomain;
/// A fake Tao implementation that performs crypto operations using
/// in-memory keys, including a fake policy key.
class FakeTao : public Tao {
 public:
  /// A bogus password used to encrypt FakeTao keys.
  static constexpr auto FakePassword = "fakepass";

  FakeTao() {}
  virtual ~FakeTao() {}
  
  /// Use temporary keys for signing and sealing. This version stands in for a
  /// hardware TPM, but no attestation will be generated.
  virtual bool InitTemporaryTPM();

  /// Use temporary keys for signing and sealing. This version stands in for a
  /// hardware TPM, including an attestation from the policy key.
  /// @param admin The configuration for this administrative domain. 
  virtual bool InitTemporaryTPM(const TaoDomain &admin);

  /// Use fake signing and sealing keys. This version stands in for hardware
  /// like a TPM, including an attestation from the policy key.
  /// @param keys_path A directory to store signing and sealing keys and a
  /// signed attestation from the policy key. The directory should contain
  /// sealing and sealing keys, both encrypted with FakePassword, and an
  /// attestation. If any of these are missing, they will be created.
  /// @param admin The configuration for this administrative domain. Ownership
  /// is not taken.
  virtual bool InitPseudoTPM(const string &keys_path, const TaoDomain &admin);

  /// Make a (deep) copy of this object.
  virtual FakeTao *DeepCopy() const;

  /// The FakeTao pretends to start hosted programs but does nothing.
  virtual bool StartHostedProgram(const string &path, const list<string> &args,
                                  string *identifier);

  /// The FakeTao doesn't remove hosted programs, but it accepts the call.
  virtual bool RemoveHostedProgram(const string &child_hash) { return true; }

  /// FakeTao follows the normal semantics of the Tao for these methods.
  /// @{
  virtual bool Destroy() { return true; }
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &child_hash, const string &data,
                    string *sealed) const;
  virtual bool Unseal(const string &child_hash, const string &sealed,
                      string *data) const;
  virtual bool Attest(const string &child_hash, const string &data,
                      string *attestation) const;
  /// @}

 private:
  /// An attestation for our signing public key, or emptystring.
  string attestation_;

  /// Crypting and signing keys for sealing and signing.
  scoped_ptr<tao::Keys> keys_;

  /// Generate a new attestation for our signing key.
  /// @param admin The configuration for this administrative domain.
  bool MakePolicyAttestation(const TaoDomain &admin);

  DISALLOW_COPY_AND_ASSIGN(FakeTao);
};
}  // namespace tao

#endif  // TAO_FAKE_TAO_H_
