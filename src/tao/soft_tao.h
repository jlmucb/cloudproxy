//  File: soft_tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A Tao interface based entirely in software not backed by a TPM.
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
#ifndef TAO_SOFT_TAO_H_
#define TAO_SOFT_TAO_H_

#include <list>
#include <string>

#include "tao/keys.h"
#include "tao/tao.h"
#include "tao/util.h"


namespace tao {
/// A Tao interface implemented entirely in software and not backed by any
/// hardware TPM or any host Tao.
class SoftTao : public Tao {
 public:

  SoftTao() {}
  virtual ~SoftTao() {}

  /// Use temporary keys for signing and sealing. This is useful for unit tests.
  virtual bool InitWithTemporaryKeys();

  /// Use the provided keys for signing and sealing.
  /// @param keys A set of signing and crypting keys. Ownership is taken.
  virtual bool Init(Keys *keys);

  /// Make a (deep) copy of this object.
  virtual SoftTao *DeepCopy() const;
  
  /// These methods have the same semantics as Tao.
  /// @{
  virtual bool GetTaoName(string *name) const;
  virtual bool ExtendTaoName(const string &subprin) const;
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Attest(const Statement &stmt, string *attestation) const;
  virtual bool Seal(const string &data, const string &policy,
                    string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data, string *policy) const;
  /// @}

 private:
  /// Crypting and signing keys for sealing and signing.
  scoped_ptr<tao::Keys> keys_;

  DISALLOW_COPY_AND_ASSIGN(SoftTao);
};
}  // namespace tao

#endif  // TAO_SOFT_TAO_H_
