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

#include <map>
#include <set>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/scoped_ptr.h>

#include "tao/attestation.pb.h"
#include "tao/tao_auth.h"

using std::map;
using std::set;

namespace keyczar {

class Keyczar;

}  // namespace keyczar

namespace tao {
/// An authorization component that only accepts signatures from the public
/// policy key.
class RootAuth : public TaoAuth {
 public:
  /// Stores the location of the public policy but doesn't try to parse it.
  RootAuth(const string &policy_public_key)
      : policy_public_key_(policy_public_key), policy_key_(NULL) {}
  virtual ~RootAuth() {}

  /// Load the public policy key from the location specified in the
  /// constructor.
  virtual bool Init();

  /// Check to see if a program hash is on the whitelist.
  /// @return false because the only thing that matters is the policy key
  /// signature. There is no whitelist.
  virtual bool IsAuthorized(const string &program_hash) const { return false; }

  /// Check to see if a program name/hash pair is on the whitelist.
  /// @return false because the only thing that matters is the policy key
  /// signature. There is no whitelist.
  virtual bool IsAuthorized(const string &program_name,
                            const string &program_hash) const {
    return false;
  }

  /// Verify an attestation and return the data it attests to
  /// @param attestation The attestation to verify.
  /// @param[out] data The data in the attestation.
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 private:
  // The location of the public policy key.
  string policy_public_key_;

  // The public policy key
  scoped_ptr<keyczar::Keyczar> policy_key_;

  /// Check a signature made by the policy key.
  bool CheckRootSignature(const Attestation &a) const;

  DISALLOW_COPY_AND_ASSIGN(RootAuth);
};
}  // namespace tao

#endif  // TAO_ROOT_AUTH_H_
