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

#include <string>

#include "tao/attestation.pb.h"

namespace tao {
using std::string;

/// TaoHost provides a generic interface  for a Tao host that can be configured
/// and driven by a variety of host environments. Generally, the host
/// environment is responsible for enforcing and managing policy, managing
/// hosted programs (e.g. measuring, naming, starting, stopping), communication
/// with hosted programs (e.g. channel creation, RPC reception), and other
/// host-specific details. Elsewhere are various classes that implement a
/// variety of approaches to these tasks and make the appropriate calls into
/// TaoHost.
///
/// Because the environment calls TaoHost in response to requests from hosted
/// processes invoking the Tao interface, several TaoHost methods resemble
/// methods in Tao. Semantics and method signatures differ slightly, however,
/// since the environment can add context (e.g. the subprincipal name of the
/// requesting child) or do part of the implenentation (e.g. manage policy on
/// seal/unseal).
class TaoHost {
 public:
  virtual bool Init() { return true; }
  virtual ~TaoHost() {}

  /// Get random bytes. A TaoHost is expected to be a good source of randomness.
  /// @param child_subprin. The principal name extension identifying the hosted
  /// program requesting the random bytes. (This parameter is currently unused.)
  /// @param size The number of bytes requested.
  /// @param bytes[out] The random bytes.
  virtual bool GetRandomBytes(const string &child_subprin, size_t size,
                              string *bytes) const = 0;

  /// Attest to a statement after modifying it to fill in missing fields.
  /// @param child_subprin. The principal name extension identifying the hosted
  /// program requesting the attestation. This is used for filling in the issuer
  /// field of the statement or checking that the issuer field is reasonable.
  /// @param stmt The partially-completed statement to be attested.
  /// @param attestation[out] The signed attestation.
  virtual bool Attest(const string &child_subprin, Statement *stmt,
                      string *attestation) const = 0;

  /// TaoHost does not itself enforce policy for seal and unseal operations. The
  /// following methods encrypt and decrypt data using the crypting key, if so
  /// configured, without enforcing any policy. It is assumed that the crypting
  /// key is accessible only to this host. If so, and if the host environment
  /// enforces policy, then the following methods can be used as part of the
  /// implementation for Seal() and Unseal() services provided to hosted
  /// programs.
  /// @{

  /// Encrypt data so that only this host can access it.
  /// @param data The data to be encrypted.
  /// @param[out] encrypted The encrypted data.
  virtual bool Encrypt(const google::protobuf::Message &data,
                       string *encrypted) const = 0;

  /// Decrypt data that only this host can access.
  /// @param encrypted The encrypted data.
  /// @param[out] ddata The decrypted data.
  virtual bool Decrypt(const string &encrypted,
                       google::protobuf::Message *data) const = 0;

  /// @}

  /// These methods are called by the host environment on certain events.
  /// @{

  /// Notify this TaoHost that a new hosted program has been created.
  /// @param child_subprin The subprincipal for the new hosted program.
  virtual bool AddedHostedProgram(const string &child_subprin) { return true; }

  /// Notify this TaoHost that a hosted program has been killed.
  /// @param child_subprin The subprincipal for the dead hosted program.
  virtual bool RemovedHostedProgram(const string &child_subprin) {
    return true;
  }

  /// @}

  /// Get the Tao principal name assigned to this hosted Tao host. The name
  /// encodes the full path from the root Tao, through all intermediary Tao
  /// hosts, to this hosted Tao host.
  virtual string TaoHostName() const = 0;
};
}  // namespace tao

#endif  // TAO_TAO_HOST_H_
