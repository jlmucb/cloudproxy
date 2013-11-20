//  File: tpm_tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the TPM Tao child channel.
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

#include "tao/tpm_tao_child_channel.h"

namespace tao {
TPMTaoChildChannel::TPMTaoChildChannel() {
  // nothing to do yet. But this should be get the information needed for Init
  // to connect to the TPM
}

bool TPMTaoChildChannel::Init() {
  return false;
}


bool TPMTaoChildChannel::Destroy() {
  return false;
}


bool TPMTaoChildChannel::GetRandomBytes(size_t size, string *bytes) const {
  return false;
}


bool TPMTaoChildChannel::Seal(const string &data, string *sealed) const {
  return false;
}


bool TPMTaoChildChannel::Unseal(const string &sealed, string *data) const {
  return false;
}


bool TPMTaoChildChannel::Attest(const string &data, string *attestation) const {
  return false;
}


bool TPMTaoChildChannel::VerifyAttestation(const string &attestation,
                                           string *data) const {
  return false;
}

} // namespace tao
