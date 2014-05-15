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
  if (!keys_->InitTemporary()) {
    LOG(ERROR) << "Could not generate temporary keys";
    return false;
  }
  return Init(keys_.release());
}

bool SoftTao::Init(Keys *keys) {
  keys_.reset(keys);
  if (keys_->Signer() == nullptr || keys_->Crypter() == nullptr) {
    LOG(ERROR) << "SoftTao is missing a required key";
    return false;
  }
  if (!keys_->GetPrincipalName(&key_name_)) {
    LOG(ERROR) << "Could not get key principal name";
    return false;
  }
  return true;
}

SoftTao *SoftTao::DeepCopy() const {
  scoped_ptr<SoftTao> other(new SoftTao());
  other->keys_.reset(keys_->DeepCopy());
  other->key_name_ = key_name_;
  other->name_extension_ = name_extension_;
  return other.release();
}

bool SoftTao::GetTaoName(string *name) const {
  name->assign(key_name_ + name_extension_);
  return true;
}

bool SoftTao::ExtendTaoName(const string &subprin) {
  if (subprin == "") {
    LOG(ERROR) << "Invalid subprincipal name";
    return false;
  }
  name_extension_ += "::" + subprin;
  return true;
}

bool SoftTao::GetRandomBytes(size_t size, string *bytes) const {
  return CryptoFactory::Rand()->RandBytes(size, bytes);
}

bool SoftTao::Attest(const Statement &stmt, string *attestation) const {
  // Set up a (copy) of statement and fill in defaults.
  Statement s;
  s.MergeFrom(stmt);
  string name = key_name_ + name_extension_;
  if (!s.has_issuer()) {
    s.set_issuer(name);
  } else if (!IsSubprincipalOrIdentical(s.issuer(), name)) {
    LOG(ERROR) << "Invalid issuer in statement";
    return false;
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
