//  File: tao_host.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tao host interface.
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

#ifndef TAO_TAO_HOST_H_
#define TAO_TAO_HOST_H_

#include <set>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/scoped_ptr.h>

namespace tao {
using std::set;
using std::string;

class Keys;
class Tao;

/// TaoHost provides a generic implementation of a Tao host that can be
/// configured for, and driven by, a variety of host environments. Generally,
/// the host environment is responsible for enforcing and managing policy,
/// managing hosted programs (e.g. naming, measuring, starting, stopping),
/// communication with hosted programs (e.g. channel creation, RPC reception),
/// and other host-specific details. Elsewhere are classes, implemented using a
/// variety of approaches, that implement some of these tasks and make the
/// appropriate calls into TaoHost.
class TaoHost {
 public:
  /// Construct and configure a TaoHost. Ownership is taken for all relevant
  /// parameters.
  /// @param keys A set of keys, or nullptr. If the set contains a signing key
  /// and accompanying delegation attestation, they will be used for signing
  /// attestations on behalf of hosted programs, otherwise attestation will
  /// invoke host_tao. If the set contains a crypting key, it will be used for
  /// sealing and unsealing data, otherwise sealing and unsealing wil invoke
  /// host_tao.
  /// @param host_tao The host tao on top of which this hosted Tao executes.
  TaoHost(Keys *keys, Tao *host_tao) : keys_(keys), host_tao_(host_tao) {}

  virtual bool Init();
  virtual bool Destroy() { return true; }
  virtual ~TaoHost() {}

  /// TaoHost mostly follows the semantics of the Tao interface for these
  /// methods. An extra child_name parameter is added to each call to specify
  /// the identity of the hosted program that requested to invoke the method. In
  /// all cases, the child_name parameter specifies the subprincipal that
  /// appears after this Tao host's own full name.
  /// @{
  virtual bool GetTaoName(const string &child_name, string *name) const;
  virtual bool ExtendTaoName(const string &child_name,
                             const string &subprin) const;
  virtual bool GetRandomBytes(const string &child_name, size_t size,
                              string *bytes) const;
  virtual bool Attest(const string &child_name, const string &stmt,
                      string *attestation) const;
  /// @}
  
  /// TaoHost does not itself enforce policy for seal and unseal operations.
  /// These methods invoke the host tao, which is assumed to enforce the policy.
  /// @{

  /// Seal data by invoking the host Tao. See Tao::Seal() for semantics.
  virtual bool SealToHost(const string &data, const string &policy,
                          string *sealed) const {
    return host_tao_->Seal(data, policy, sealed);
  }

  // Unseal data by invoking the host Tao. See Tao::Unseal() for semantics.
  virtual bool UnsealFromHost(const string &sealed, string *data,
                              string *policy) const {
    return host_tao_->Uneal(sealed, data, policy);
  }

  /// @}
  
  /// TaoHost does not itself enforce policy for seal and unseal operations.
  /// These methods encrypt and decrypt data using the crypting key, if so
  /// configured, without enforcing any policy. If the host environment enforces
  /// policy, these can be used to provide Seal() and Unseal() services to
  /// hosted programs.
  /// @{

  /// Encrypt data using the crypting key.
  /// @param data The data to be encrypted.
  /// @param[out] encrypted The encrypted data.
  virtual bool Encrypt(const string &data, string *encrypted) const;

  /// Decrypt data using the crypting key.
  /// @param encrypted The encrypted data.
  /// @param[out] ddata The decrypted data.
  virtual bool Decrypt(const string &encrypted, string *data) const;
  
  /// @}

  /// These methods are called by the host environment on certain events.
  /// @{

  /// Notify this TaoHost that a new hosted program has been created.
  /// @param child_name The subprincipal for the new hosted program.
  virtual bool AddHostedProgram(const string &child_name) {}
  
  /// Notify this TaoHost that a hosted program has been killed.
  /// @param child_name The subprincipal for the dead hosted program.
  virtual bool RemoveHostedProgram(const string &child_name) {}
 
  /// Get the Tao principal name assigned to this hosted Tao host. The name
  /// encodes the full path from the root Tao, through all intermediary Tao
  /// hosts, to this hosted Tao host. 
  /// @param[out] name The full, globally-unique name of this hosted Tao host.
  virtual bool GetTaoHostName(string *name) const { return tao_host_name_; }

  /// Get the principal name associated with this Tao's attestation signing key.
  /// @param[out] name The globally-unique name of the signing key.
  virtual bool GetAttestationName(string *name) const;

 private:
  /// Keys for attestations and/or sealing, or nullptr.
  scoped_ptr<Keys> keys_;

  /// A delegation for our signing key from the host Tao.
  string parent_delegation_;

  /// The channel to use for host communication.
  scoped_ptr<Tao> host_tao_;

  /// Our own principal name, as obtained from the host Tao.
  string tao_host_name_;

  DISALLOW_COPY_AND_ASSIGN(TaoHost);
};
}  // namespace tao

#endif  // TAO_TAO_HOST_H_
