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

#include <list>
#include <string>

#include "tao/tao.h"

using std::string;

namespace tao {

bool DirectTaoChildChannel::GetRandomBytes(size_t size, string *bytes) const {
  return tao_->GetRandomBytes(child_name_, size, bytes);
}

bool DirectTaoChildChannel::Seal(const string &data, int policy,
                                 string *sealed) const {
  return tao_->Seal(child_name_, data, policy, sealed);
}

bool DirectTaoChildChannel::Unseal(const string &sealed, string *data,
                                   int *policy) const {
  return tao_->Unseal(child_name_, sealed, data, policy);
}

bool DirectTaoChildChannel::Attest(const string &key_prin,
                                   string *attestation) const {
  return tao_->Attest(child_name_, key_prin, attestation);
}

bool DirectTaoChildChannel::GetHostedProgramFullName(string *full_name) const {
  return tao_->GetHostedProgramFullName(child_name_, full_name);
}
}  // namespace tao
