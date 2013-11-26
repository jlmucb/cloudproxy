//  File: attestation_verifier.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A class that verifies all kinds of attestations
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

#ifndef TAO_ATTESTATION_VERIFIER_H_
#define TAO_ATTESTATION_VERIFIER_H_

#include "tao/attestation.pb.h"
#include "tao/tao_auth.h"
#include "tao/util.h"

#include <string>

using std::string;

namespace tao {
class AttestationVerifier {
 public:
  AttestationVerifier(const string &aik_cert_file,
                      const string &public_policy_key_file,
                      TaoAuth *auth_manager);
  virtual ~AttestationVerifier() {}
  virtual bool Init();
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 private:
  // The public AIK as an OpenSSL RSA key.
  ScopedRsa aik_rsa_;

  // The public policy key as a Keyczar key.
  scoped_ptr<keyczar::Keyczar> policy_key_;

  // An authorization manager that decides whether or not a given program is
  // authorized.
  scoped_ptr<TaoAuth> auth_manager_;

  bool CheckRootSignature(const Attestation &a) const;
  bool CheckIntermediateSignature(const Attestation &a) const;
  bool CheckTPM12Quote(const Attestation &a) const;
};
}  // namespace tao

#endif  // TAO_ATTESTATION_VERIFIER_H_
