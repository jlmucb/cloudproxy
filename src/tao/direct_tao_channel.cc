//  File: direct_tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A TaoChannel that calls directly to another Tao object
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

#include "tao/direct_tao_channel.h"

namespace tao {
DirectTaoChannel::DirectTaoChannel(Tao *tao) : tao_(tao) {
  // no other initialization needed
}

bool DirectTaoChannel::StartHostedProgram(const string &path,
                                          const list<string> &args) {
  return tao_->StartHostedProgram(path, args);
}

bool DirectTaoChannel::GetRandomBytes(size_t size, string *bytes) const {
  return tao_->GetRandomBytes(size, bytes);
}

bool DirectTaoChannel::Seal(const string &data, string *sealed) const {
  return tao_->Seal(data, sealed);
}

bool DirectTaoChannel::Unseal(const string &sealed, string *data) const {
  return tao_->Unseal(sealed, data);
}

bool DirectTaoChannel::Attest(const string &data, string *attestation) const {
  return tao_->Attest(data, attestation);
}

bool DirectTaoChannel::VerifyAttestation(const string &attestation,
                                         string *data) const {
  return tao_->VerifyAttestation(attestation, data);
}
}  // namespace tao
