//  File: tao_root_host.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Tao host implemented using a set of keys.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#include "tao/tao_root_host.h"

#include <glog/logging.h>
#include <keyczar/crypto_factory.h>

#include "tao/attestation.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/tao.h"

using keyczar::CryptoFactory;

namespace tao {

bool TaoRootHost::Init() {
  if (keys_.get() == nullptr) {
    keys_.reset(new Keys(Keys::Signing | Keys::Crypting));
    if (!keys_->InitTemporary()) {
      LOG(ERROR) << "Could not generate temporary keys";
      return false;
    }
  }
  if (keys_->Signer() == nullptr || keys_->Crypter() == nullptr) {
    LOG(ERROR) << "TaoRootHost is missing a required key";
    return false;
  }
  // Get our name early and cache it.
  tao_host_name_ = keys_->Verifier()->ToPrincipalName();
  if (tao_host_name_ == "") {
    LOG(ERROR) << "Could not get key principal name";
    return false;
  }
  VLOG(1) << "TaoRootHost: Initialization finished successfully";
  VLOG(1) << "TaoRootHost: " << elideString(tao_host_name_);
  return true;
}

bool TaoRootHost::GetRandomBytes(const string &child_subprin, size_t size,
                                 string *bytes) const {
  return CryptoFactory::Rand()->RandBytes(size, bytes);
}

bool TaoRootHost::GetSharedSecret(const string &tag, size_t size,
                                  string *bytes) const {
  if (keys_ == nullptr || keys_->Deriver() == nullptr) {
    LOG(ERROR) << "This host does not implement shared secrets";
    return false;
  }
  if (!keys_->Deriver()->Derive(size, tag, bytes)) {
    LOG(ERROR) << "Could not derive shared secret";
    return false;
  }
  return true;
}

bool TaoRootHost::Attest(const string &child_subprin, Statement *stmt,
                         string *attestation) const {
  // Make sure issuer is identical to (or a subprincipal of) the hosted
  // program's principal name.
  if (!stmt->has_issuer()) {
    stmt->set_issuer(tao_host_name_ + "::" + child_subprin);
  } else if (!IsSubprincipalOrIdentical(
                 stmt->issuer(), tao_host_name_ + "::" + child_subprin)) {
    LOG(ERROR) << "Invalid issuer in statement";
    return false;
  }
  // Sign it.
  return GenerateAttestation(*keys_->Signer(), "" /* delegation */, *stmt,
                             attestation);
}

bool TaoRootHost::Encrypt(const google::protobuf::Message &data,
                          string *encrypted) const {
  string serialized_data;
  if (!data.SerializeToString(&serialized_data)) {
    LOG(ERROR) << "Could not serialize data to be sealed";
    return false;
  }
  return keys_->Crypter()->Encrypt(serialized_data, encrypted);
}

bool TaoRootHost::Decrypt(const string &encrypted,
                          google::protobuf::Message *data) const {
  string serialized_data;
  if (!keys_->Crypter()->Decrypt(encrypted, &serialized_data)) {
    LOG(ERROR) << "Could not decrypt sealed data";
    return false;
  }
  if (!data->ParseFromString(serialized_data)) {
    LOG(ERROR) << "Could not deserialize sealed data";
    return false;
  }
  return true;
}

}  // namespace tao
