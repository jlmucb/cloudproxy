//  File: tao_host.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tao host implementation.
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
#include "tao/tao_host.h"

#include <glog/logging.h>

#include "tao/attestation.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/tao.h"

namespace tao {

bool TaoHost::Init() {
  // Get our name early and cache it.
  if (!host_tao_->GetTaoName(&tao_host_name_)) {
    LOG(ERROR) << "Could not obtain Tao host name";
    return false;
  }
  // When using a signing key, we require a delegation to accompany it.
  if (keys_ != nullptr && keys_->Signer() != nullptr &&
      !keys_->GetHostDelegation(&host_delegation_)) {
    LOG(ERROR) << "Could not load delegation for attestation key";
    return false;
  }

  VLOG(1) << "TaoHost: Initialization finished successfully";
  VLOG(1) << "TaoHost: " << tao_host_name_;
  return true;
}

// bool TaoHost::GetTaoName(const string &child_subprin, string *name) const {
//   name->assign(tao_host_name_ + "::" + child_subprin);
//   return true;
// }

// bool TaoHost::ExtendTaoName(const string &child_subprin, const string &subprin) const {
//   // Nothing to do.
//   return true;
// }

bool TaoHost::GetRandomBytes(const string &child_subprin, size_t size,
                              string *bytes) const {
  return host_tao_->GetRandomBytes(size, bytes);
}

bool TaoHost::Attest(const string &child_subprin, Statement *stmt,
                      string *attestation) const {
  // Make sure issuer is identical to (or a subprincipal of) the hosted
  // program's principal name.
  if (!stmt->has_issuer()) {
    stmt->set_issuer(tao_host_name_ + "::" + child_subprin);
  } else if (!IsSubprincipalOrIdentical(stmt->issuer(),
        tao_host_name_ + "::" + child_subprin)) {
    LOG(ERROR) << "Invalid issuer in statement";
    return false;
  }
  // Sign it.
  if (keys_ == nullptr || keys_->Signer() == nullptr) {
    return host_tao_->Attest(*stmt, attestation);
  } else {
    return GenerateAttestation(*keys_, host_delegation_, *stmt, attestation);
  }
}

bool TaoHost::SealToHost(const string &data, const string &policy,
                         string *sealed) const {
  return host_tao_->Seal(data, policy, sealed);
}

// Unseal data by invoking the host Tao. See Tao::Unseal() for semantics.
bool TaoHost::UnsealFromHost(const string &sealed, string *data,
                             string *policy) const {
  return host_tao_->Unseal(sealed, data, policy);
}

bool TaoHost::Encrypt(const google::protobuf::Message &data,
                      string *encrypted) const {
  if (keys_ == nullptr || keys_->Crypter() == nullptr) {
    LOG(ERROR) << "TaoHost can not encrypt without a crypting key.";
    return false;
  }
  string serialized_data;
  if (!data.SerializeToString(&serialized_data)) {
    LOG(ERROR) << "Could not serialize data to be sealed";
    return false;
  }
  return keys_->Encrypt(serialized_data, encrypted);
}

bool TaoHost::Decrypt(const string &encrypted,
                      google::protobuf::Message *data) const {
  if (keys_ == nullptr || keys_->Crypter() == nullptr) {
    LOG(ERROR) << "TaoHost can not decrypt without a crypting key.";
    return false;
  }
  string serialized_data;
  if (!keys_->Decrypt(encrypted, &serialized_data)) {
    LOG(ERROR) << "Could not decrypt sealed data";
    return false;
  }
  if (!data->ParseFromString(serialized_data)) {
    LOG(ERROR) << "Could not deserialize sealed data";
    return false;
  }
  return true;
}

bool TaoHost::GetAttestationName(string *name) const {
  if (keys_ == nullptr || keys_->Signer() == nullptr) {
    LOG(ERROR) << "Tao host is not configured with an attestation key";
    return false;
  }
  return keys_->GetPrincipalName(name);
}

}  // namespace tao
