//  File: direct_tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A TaoChildChannel that calls directly to another Tao object
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

#include "tao/direct_tao_child_channel.h"

namespace tao {
  DirectTaoChildChannel::DirectTaoChildChannel(Tao *tao,
					       const string &child_hash)
    : tao_(tao),
      child_hash_(child_hash) {
  // no other initialization needed
}

bool DirectTaoChildChannel::StartHostedProgram(const string &path,
                                          const list<string> &args) {
  return tao_->StartHostedProgram(path, args);
}

bool DirectTaoChildChannel::GetRandomBytes(size_t size, string *bytes) const {
  return tao_->GetRandomBytes(size, bytes);
}

bool DirectTaoChildChannel::Seal(const string &data, string *sealed) const {
  return tao_->Seal(child_hash_, data, sealed);
}

bool DirectTaoChildChannel::Unseal(const string &sealed, string *data) const {
  return tao_->Unseal(child_hash_, sealed, data);
}

bool DirectTaoChildChannel::Attest(const string &data, string *attestation) const {
  return tao_->Attest(child_hash_, data, attestation);
}

bool DirectTaoChildChannel::VerifyAttestation(const string &attestation,
                                         string *data) const {
  return tao_->VerifyAttestation(attestation, data);
}
}  // namespace tao
