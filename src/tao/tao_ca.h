//  File : tao_ca.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A Tao Certificate Authority client.
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
#ifndef TAO_TAO_CA_H_
#define TAO_TAO_CA_H_

#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/scoped_ptr.h>

#include "tao/util.h"

using std::string;

namespace keyczar {
class Verifier;
}  // namespace keyczar

namespace tao {
class TaoDomain;
class TaoCARequest;
class TaoCAResponse;
class X509Details;

/// A TaoCA connects to a network port to receive attestations and x509
/// certificate chains rooted in the policy signing key.
class TaoCA {
 public:
  /// Construct a new TaoCA to make requests for attestations to be signed by
  /// the policy key.
  /// @param admin The administrative domain holding the policy key. The pointer
  /// is retained but ownership is not taken.
  explicit TaoCA(TaoDomain *admin);

  virtual ~TaoCA();

  /// Request shut down of the remote TaoCAServer.
  virtual bool Shutdown();

  /// Request a root attestation from the remote TaoCA to replace an
  /// intermediate
  /// attestation. This method verifies the resulting root attestation before
  /// returning it.
  /// @param intermediate_attestation An intermediate attestation, e.g. from
  /// LinuxTao, FakeTao, or a TPM.
  /// @param[out] root_attestation An attestation from the policy signing key.
  virtual bool GetAttestation(const string &intermediate_attestation,
                              string *root_attestation);

  /// Request an X509 certificate chain along with a root attestation from a
  /// remote TaoCA to replace an intermediate attestation. This method verifies
  /// the resulting root attestation before returning it.
  /// @param intermediate_attestation An intermediate attestation, e.g. from
  /// LinuxTao, FakeTao, or a TPM.
  /// @param details_text Details of requested X509 in text format.
  /// @param[out] root_attestation An attestation from the policy signing key.
  /// @param[out] pem_cert An x509 certificate chain in PEM format rooted in the
  /// policy signing key.
  virtual bool GetX509Chain(const string &intermediate_attestation,
                            const string &details_text,
                            string *root_attestation, string *pem_cert);

 protected:
  /// Send a request to a remote TaoCA.
  /// @param req The request to send to the remote TaoCA.
  /// @param[out] resp The response from the remote TaoCA.
  bool SendRequest(const TaoCARequest &req, TaoCAResponse *resp);

 private:
  /// The administrative domain.
  TaoDomain *admin_;

  DISALLOW_COPY_AND_ASSIGN(TaoCA);
};
}  // namespace tao

#endif  // TAO_TAO_CA_H_
