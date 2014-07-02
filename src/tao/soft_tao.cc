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
bool SoftTao::Init() {
  if (keys_.get() == nullptr) {
    keys_.reset(new Keys(Keys::Signing | Keys::Crypting | Keys::Deriving));
    if (!keys_->InitTemporary()) {
      LOG(ERROR) << "Could not generate temporary keys";
      return false;
    }
  }
  if (keys_->Signer() == nullptr || keys_->Crypter() == nullptr) {
    LOG(ERROR) << "SoftTao is missing a required key";
    return false;
  }
  key_name_ = keys_->Verifier()->ToPrincipalName();
  if (key_name_ == "") {
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

bool SoftTao::GetTaoName(string *name) {
  name->assign(key_name_ + name_extension_);
  return true;
}

bool SoftTao::ExtendTaoName(const string &subprin) {
  if (subprin == "") {
    failure_msg_ = "Invalid subprincipal name";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  name_extension_ += "::" + subprin;
  return true;
}

bool SoftTao::GetRandomBytes(size_t size, string *bytes) {
  return CryptoFactory::Rand()->RandBytes(size, bytes);
}

bool SoftTao::GetSharedSecret(size_t size, const string &policy,
                              string *bytes) {
  if (keys_ == nullptr || keys_->Deriver() == nullptr) {
    failure_msg_ = "SoftTao does not implement shared secrets";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  if (policy != Tao::SharedSecretPolicyDefault) {
    failure_msg_ = "SoftTao policies not yet implemented";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  if (!keys_->Deriver()->Derive(size, "derive shared secret", bytes)) {
    failure_msg_ = "Could not derive shared secret";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  return true;
}

bool SoftTao::Attest(const Statement &stmt, string *attestation) {
  // Set up a (copy) of statement and fill in defaults.
  Statement s;
  s.MergeFrom(stmt);
  string name = key_name_ + name_extension_;
  if (!s.has_issuer()) {
    s.set_issuer(name);
  } else if (!IsSubprincipalOrIdentical(s.issuer(), name)) {
    failure_msg_ = "Invalid issuer in statement";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  return GenerateAttestation(*keys_->Signer(), "" /* delegation */, s,
                             attestation);
}

bool SoftTao::Seal(const string &data, const string &policy, string *sealed) {
  if (policy != Tao::SealPolicyDefault) {
    failure_msg_ = "SoftTao policies not yet implemented";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  return keys_->Crypter()->Encrypt(data, sealed);
}

bool SoftTao::Unseal(const string &sealed, string *data, string *policy) {
  if (!keys_->Crypter()->Decrypt(sealed, data)) {
    failure_msg_ = "Could not decrypt the sealed data";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  policy->assign(Tao::SealPolicyDefault);
  return true;
}

bool SoftTao::SerializeToStringWithDirectory(const string &path,
                                             const string &pass,
                                             string *params) const {
  stringstream out;
  out << "tao::SoftTao(";
  out << quotedString(path);
  out << ", ";
  out << quotedString(pass);
  out << ")";
  params->assign(out.str());
  return true;
}

SoftTao *SoftTao::DeserializeFromString(const string &params) {
  stringstream in(params);
  skip(in, "tao::SoftTao(");
  if (!in) return nullptr;  // not for us
  string path, pass;
  getQuotedString(in, &path);
  skip(in, ", ");
  getQuotedString(in, &pass);
  skip(in, ")");
  if (!in || (in.get() && !in.eof())) {
    LOG(ERROR) << "Could not deserialize SoftTao";
    return nullptr;
  }
  scoped_ptr<Keys> keys(
      new Keys(path, Keys::Signing | Keys::Crypting | Keys::Deriving));
  if (!keys->InitWithPassword(pass)) {
    LOG(ERROR) << "Could not load keys for SoftTao";
    return nullptr;
  }
  scoped_ptr<SoftTao> tao(new SoftTao(keys.release()));
  if (!tao->Init()) {
    LOG(ERROR) << "Could not initialize SoftTao";
    return nullptr;
  }
  return tao.release();
}

}  // namespace tao
