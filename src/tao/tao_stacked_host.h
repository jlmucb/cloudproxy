//  File: tao_stacked_host.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Tao host implemented on top of a host Tao.
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
#ifndef TAO_TAO_STACKED_HOST_H_
#define TAO_TAO_STACKED_HOST_H_

#include <string>

#include "tao/keys.h"
#include "tao/tao.h"
#include "tao/tao_host.h"
#include "tao/util.h"

namespace tao {

/// TaoStackedHost provides an implementation of TaoHost by making use of the
/// services of an underlying host Tao (e.g. the TPM or some host Tao accessed
/// via RPC).
class TaoStackedHost : public TaoHost {
 public:
  /// Construct and configure a TaoStackedHost. Ownership is taken for all
  /// relevant
  /// parameters.
  /// @param keys A set of keys, or nullptr. If the set contains a signing key
  /// and accompanying delegation attestation, they will be used for signing
  /// attestations on behalf of hosted programs, otherwise attestation will
  /// invoke host_tao. If the set contains a crypting key, it will be used for
  /// sealing and unsealing data, otherwise sealing and unsealing will invoke
  /// host_tao using Tao::SealPolicyDefault. If the set contains a key-deriving
  /// key, it will be used for generating shared secrets, otherwise generating
  /// shared secrets will invoke host_tao using Tao::SharedSecretPolicyDefault.
  /// @param host_tao The host tao on top of which this hosted Tao executes.
  TaoStackedHost(Keys *keys, Tao *host_tao)
      : keys_(keys), host_tao_(host_tao) {}

  virtual bool Init();
  virtual ~TaoStackedHost() {}

  /// TaoStackedHost follows the semantics of TaoHost for these methods.
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
  /// Keys for attestations and/or sealing, or nullptr.
  unique_ptr<Keys> keys_;

  /// A delegation for our signing key (if any) from the host Tao.
  string host_delegation_;

  /// The channel to use for host communication.
  unique_ptr<Tao> host_tao_;

  /// Our own principal name, as obtained from the host Tao.
  string tao_host_name_;

  DISALLOW_COPY_AND_ASSIGN(TaoStackedHost);
};
}  // namespace tao

#endif  // TAO_TAO_STACKED_HOST_H_
