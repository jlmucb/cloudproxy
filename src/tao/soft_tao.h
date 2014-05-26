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
  /// Use temporary keys for signing and sealing. This is useful for unit tests.
  SoftTao() {}

  /// Use the provided keys for signing and sealing.
  /// @param keys A set of signing and crypting keys. Ownership is taken.
  explicit SoftTao(Keys *keys) : keys_(keys) {}

  virtual bool Init();

  // Serializing all the keys in one large blob is inconvenient...
  // virtual bool SerializeToString(string *params) const;
  virtual bool SerializeToStringWithDirectory(const string &path,
                                              const string &pass,
                                              string *params) const;

  // Deserialize a string of the form "tao::SoftTao(path, passwd)".
  static SoftTao *DeserializeFromString(const string &params);

  /// Make a (deep) copy of this object.
  virtual SoftTao *DeepCopy() const;

  /// These methods have the same semantics as Tao.
  /// @{
  virtual bool GetTaoName(string *name);
  virtual bool ExtendTaoName(const string &subprin);
  virtual bool GetRandomBytes(size_t size, string *bytes);
  virtual bool Attest(const Statement &stmt, string *attestation);
  virtual bool Seal(const string &data, const string &policy, string *sealed);
  virtual bool Unseal(const string &sealed, string *data, string *policy);
  virtual string GetRecentErrorMessage() const { return failure_msg_; }
  virtual string ResetRecentErrorMessage() {
    string msg = failure_msg_;
    failure_msg_ = "";
    return msg;
  }
  /// @}

 private:
  /// Crypting and signing keys for sealing and signing.
  scoped_ptr<tao::Keys> keys_;

  /// Base name of this SoftTao, encoded as a principal.
  string key_name_;

  /// Subprincipal names extended to this SoftTao's principal name.
  string name_extension_;

  /// Most recent failure message, if any.
  string failure_msg_;

  DISALLOW_COPY_AND_ASSIGN(SoftTao);
};
}  // namespace tao

#endif  // TAO_SOFT_TAO_H_
