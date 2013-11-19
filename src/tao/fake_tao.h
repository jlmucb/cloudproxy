//  File: fake_tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A fake implementation of the Tao interface that isn't
//  backed by any trusted hardware.
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

#ifndef TAO_FAKE_TAO_H_
#define TAO_FAKE_TAO_H_

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include "tao/tao.h"

namespace tao {

// A fake Tao implementation that performs crypto operations using
// in-memory keys, including a fake policy key.
class FakeTao : public Tao {
 public:
  FakeTao();
  virtual ~FakeTao() {}
  virtual bool Init();
  virtual bool Destroy() { return true; }
  virtual bool StartHostedProgram(const string &path, const list<string> &args);
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &child_hash, const string &data,
                    string *sealed) const;
  virtual bool Unseal(const string &child_hash, const string &sealed,
                      string *data) const;
  virtual bool Attest(const string &child_hash, const string &data,
                      string *attestation) const;
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 private:
  // An in-memory, temporary symmetric key
  scoped_ptr<keyczar::Keyczar> crypter_;

  // An in-memory, temporary asymmetric key pair
  scoped_ptr<keyczar::Keyczar> signer_;

  // A fake public policy key
  scoped_ptr<keyczar::Keyczar> policy_verifier_;

  DISALLOW_COPY_AND_ASSIGN(FakeTao);
};
}  // namespace tao

#endif  // TAO_FAKE_TAO_H_
