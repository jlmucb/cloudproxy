//  File: tao_root_host.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Tao host implemented using a set of keys.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#ifndef TAO_TAO_ROOT_HOST_H_
#define TAO_TAO_ROOT_HOST_H_

#include <string>

#include "tao/keys.h"
#include "tao/tao.h"
#include "tao/tao_host.h"
#include "tao/util.h"

namespace tao {

/// TaoRootHost provides an implementation of TaoHost by making use of a set of
/// keys and without the services of any underlying host Tao.
class TaoRootHost : public TaoHost {
 public:
  /// Use temporary keys for signing, sealing, and key deriving. This is useful
  /// for
  /// unit tests.
  TaoRootHost() {}

  /// Use the provided keys for signing, sealing, and key deriving.
  /// @param keys A set of signing, crypting, and key-deriving keys. Ownership
  /// is taken.
  explicit TaoRootHost(Keys *keys) : keys_(keys) {}

  virtual bool Init();
  virtual ~TaoRootHost() {}

  /// TaoRootHost follows the semantics of TaoHost for these methods.
  /// @{
  virtual bool GetRandomBytes(const string &child_subprin, size_t size,
                              string *bytes) const;
  virtual bool GetSharedSecret(const string &tag, size_t size,
                               string *bytes) const;
  virtual bool Attest(const string &child_subprin, Statement *stmt,
                      string *attestation) const;
  virtual bool Encrypt(const google::protobuf::Message &data,
                       string *encrypted) const;
  virtual bool Decrypt(const string &encrypted,
                       google::protobuf::Message *data) const;
  virtual string TaoHostName() const { return tao_host_name_; }
  /// @}

 private:
  /// Keys for attestation and sealing.
  scoped_ptr<Keys> keys_;

  /// Our own principal name, as derived from the signing key.
  string tao_host_name_;

  DISALLOW_COPY_AND_ASSIGN(TaoRootHost);
};
}  // namespace tao

#endif  // TAO_TAO_ROOT_HOST_H_
