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

  /// Use temporary keys for signing and sealing. This version stands in for a
  /// hardware TPM, but it will not have an attestation since there is no policy
  /// key.
  FakeTao() {}

  /// Use fake signing and sealing keys. This version stands in for hardware
  /// like a TPM.
  /// @param keys_path A directory to store signing and sealing keys and a
  /// signed attestation from the policy key. The directory should contain
  /// sealing and sealing keys, both encrypted with FakePassword, and an
  /// attestation. If any of these are missing, they will be created.
  /// @param admin The configuration for this administrative domain.
  FakeTao(const string &keys_path, TaoDomain *admin)
      : admin_(admin), keys_path_(keys_path) {}

  /// Use an existing private key for signing. A temporary key will be
  /// generated for sealing. This version does not stand in for a hardware TPM,
  /// since the same key is used for the FakeTao and some other purpose (e.g.
  /// the policy private signing key). This version is used in some unit tests.
  /// @param path Path to private signing key.
  /// @param password Password to unlock the private signing key.
  FakeTao(const string &signing_key_path, const string &password)
      : signing_key_path_(signing_key_path), signing_key_password_(password) {}
  virtual ~FakeTao() {}

  /// Init initializes the keys and sets everything up.
  virtual bool Init();

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
  /// Configuration for this administrative domain.
  scoped_ptr<TaoDomain> admin_;

  /// Directory to store keys for this FakeTao, or emptystring if using only a
  /// signing key supplied in the constructor.
  string keys_path_;

  /// Path to signing and password key from the constructor, or emptystring.
  /// @{
  string signing_key_path_;
  string signing_key_password_;
  /// @}

  /// An attestation for our signing public key, or emptystring.
  string attestation_;

  /// A crypting key for sealing, protected by a sealed secret.
  scoped_ptr<keyczar::Crypter> crypter_;

  /// A signing key for signing, protected by crypter_.
  scoped_ptr<keyczar::Signer> signer_;

  DISALLOW_COPY_AND_ASSIGN(FakeTao);
};
}  // namespace tao

#endif  // TAO_FAKE_TAO_H_
