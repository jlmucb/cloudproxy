//  File : tao_ca.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A Tao Certificate Authority server.
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
#ifndef TAO_TAO_CA_SERVER_H_
#define TAO_TAO_CA_SERVER_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/scoped_ptr.h>

#include "tao/util.h"

using std::list;
using std::string;

namespace keyczar {
class Verifier;
}  // namespace keyczar

namespace tao {
class TaoDomain;
class TaoCARequest;
class TaoCAResponse;

/// A TaoCAServer listens on a network port for requests and, in response,
/// provides
/// attestations and x509 certificate chains rooted in the policy signing key.
class TaoCAServer {
 public:
  /// Construct a new server to handle requests for attestations.
  /// @param admin The unlocked administrative domain holding the policy key.
  explicit TaoCAServer(TaoDomain *admin);

  virtual ~TaoCAServer();

  virtual bool Init();

  /// Listen for RPCs. This method returns when either a SIGTERM signal is
  /// received or when a SHUTDOWN request is received from a child.
  /// @param tao The Tao to handle hosted-program RPCs.
  virtual bool Listen();

  /// Close the sockets created in Init.
  virtual bool Destroy();

 protected:
  /// Process a request.
  /// @param fd The descriptor for this connection.
  /// @param req The request.
  /// @param[out] request_shutdown Set to true on shutdown request.
  virtual bool HandleRequest(int fd, const TaoCARequest &req,
                             bool *requests_shutdown);

  /// Process an attestation request.
  /// @param req The request.
  /// @param[out] key The subject key extracted from the request.
  /// @param[out] resp The response.
  virtual bool HandleRequestAttestation(
      const TaoCARequest &req, scoped_ptr<keyczar::Verifier> *subject_key,
      TaoCAResponse *resp);

  /// Process an x509 chain request.
  /// @param req The request.
  /// @param subject_key The subject key for the new x509 certificate.
  /// @param[in,out] resp The response.
  virtual bool HandleRequestX509Chain(const TaoCARequest &req,
                                      const keyczar::Verifier &subject_key,
                                      TaoCAResponse *resp);

 private:
  /// The administrative domain.
  scoped_ptr<TaoDomain> admin_;

  /// The socket fd.
  ScopedFd sock_;

  /// File descriptors for open connections.
  list<int> descriptors_;

  /// The host on which to listen.
  string host_;

  /// The port on which to listen.
  string port_;

  DISALLOW_COPY_AND_ASSIGN(TaoCAServer);
};
}  // namespace tao

#endif  // TAO_TAO_CA_SERVER_H_
