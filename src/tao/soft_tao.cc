//  File: soft_tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A Tao interface based entirely in software not backed by a TPM.
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
#include "tao/soft_tao.h"

#include <string>

#include <glog/logging.h>
#include <keyczar/crypto_factory.h>

#include "tao/attestation.h"
#include "tao/keys.h"
#include "tao/util.h"

using keyczar::CryptoFactory;

namespace tao {
bool SoftTao::InitWithTemporaryKeys() {
  keys_.reset(new Keys("soft_tpm", Keys::Signing | Keys::Crypting));
  return keys_->InitTemporary();
}

bool SoftTao::Init(Keys *keys) {
  if (keys->Signer() == nullptr || keys->Crypter() == nullptr) {
    LOG(ERROR) << "SoftTao is missing a required key";
    return false;
  }
  keys_.reset(keys);
  return true;
}

SoftTao *SoftTao::DeepCopy() const {
  scoped_ptr<SoftTao> other(new SoftTao());
  other->keys_.reset(keys_->DeepCopy());
  return other.release();
}

bool SoftTao::GetTaoName(string *name) const {
  return keys_->GetPrincipalName(name);
}

bool SoftTao::ExtendTaoName(const string &subprin) const {
  return true;
}

bool SoftTao::GetRandomBytes(size_t size, string *bytes) const {
  return CryptoFactory::Rand()->RandBytes(size, bytes);
}

bool SoftTao::Attest(const Statement &stmt, string *attestation) const {
  // Set up a (copy) of statement and fill in defaults.
  Statement s;
  s.MergeFrom(stmt);
  if (!s.has_time()) s.set_time(CurrentTime());
  if (!s.has_expiration())
    s.set_expiration(s.time() + Tao::DefaultAttestationTimeout);
  if (!s.has_issuer()) {
    string issuer;
    if (!GetTaoName(&issuer)) {
      LOG(ERROR) << "Could not get issuer name";
      return false;
    }
    s.set_issuer(issuer);
  }
  return GenerateAttestation(*keys_, "" /* delegation */, s, attestation);
}

bool SoftTao::Seal(const string &data, const string &policy,
                   string *sealed) const {
  if (policy != Tao::SealPolicyDefault) {
    LOG(ERROR) << "SoftTao-specific policies not yet implemented: " << policy;
    return false;
  }
  return keys_->Encrypt(data, sealed);
}

bool SoftTao::Unseal(const string &sealed, string *data, string *policy) const {
  if (!keys_->Decrypt(sealed, data)) {
    LOG(ERROR) << "Could not decrypt the sealed data";
    return false;
  }
  policy->assign(Tao::SealPolicyDefault);
  return true;
}
}  // namespace tao
