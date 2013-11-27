//  File: root_auth.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An auth manager that only accepts applications and attestations
//  if they are directly signed by the policy key.
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

#ifndef TAO_ROOT_AUTH_H_
#define TAO_ROOT_AUTH_H_

#include "tao/tao_auth.h"

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include <map>
#include <set>

using std::map;
using std::set;

namespace tao {
class RootAuth : public TaoAuth {
 public:
  RootAuth(const string &policy_public_key) : policy_public_key_(policy_public_key), policy_key_(NULL) {}
  virtual ~RootAuth() {}
  virtual bool Init();
  virtual bool IsAuthorized(const string &program_hash) const { return false; }
  virtual bool IsAuthorized(const string &program_name,
                            const string &program_hash) const { return false; }
  virtual bool IsAuthorized(const Attestation &attestation) const;
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 private:
  string policy_public_key_;
  scoped_ptr<keyczar::Keyczar> policy_key_;

  // Checks a signature made by the public policy key
  bool CheckRootSignature(const Attestation &a) const;

  DISALLOW_COPY_AND_ASSIGN(RootAuth);
};
}  // namespace tao

#endif  // TAO_ROOT_AUTH_H_
