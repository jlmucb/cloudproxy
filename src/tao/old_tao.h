//  File: tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Tao interface for Trusted Computing
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

#ifndef TAO_TAO_H_
#define TAO_TAO_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

using std::list;
using std::string;

namespace tao {

/// The Tao is the fundamental interface for Trustworthy Computing in
/// CloudProxy. Each level of a system can implement a Tao interface and provide
/// Tao services to higher-level hosted programs.
///
/// Naming within a stack of Tao instances can be... interesting. The root Tao,
/// typically a TPM or a FakeTao, has a signing key which is its primary
/// identity (where "identity" implies a globally unique name for this specific
/// instance). A root Tao may also have an attestation from one (or more?) other
/// principal (or multiple other principals?), allowing it to speak for some
/// other name (or names?). These other names are not necessarily globally
/// unique. For instance each of several TPMs, with key K_tpm1, K_tpm2, etc.,
/// may have attestations allowing them each to speak for
/// K_policy::TrustedPlatform.
///
/// To summarize, a root Tao has:
///  - One unique identity that encodes its signing key.
///  - Zero or more additional names that it can speak for.
///
/// A hosted Tao has a signing key, which can serve as an identity. But it also
/// has one or more identities that are constructed as subprincipals from the
/// identity or identities of its host Tao. For example, a LinuxTao instance
/// running on top of a TPM with key K_tpm will have, in addition to its own
/// key, an identity of the form K_tpm::PCRs(...).

class Tao {
 public:
  Tao() {}
  virtual ~Tao() {}

  /// Initialize and acquire resources.
  virtual bool Init() = 0;

  /// Clean up an resources that were allocated in Init().
  virtual bool Destroy() = 0;

  /// Administrative interfaces for managing the Tao.
  /// @{

  /// Start a hosted program with a given set of arguments. These arguments
  /// might not always be the arguments passed directly to a process. For
  /// example, they might be kernel, initrd, and disk for starting a virtual
  /// machine.
  /// @param name The name of the hosted program. This can sometimes be a path
  /// to a process, but it is not always.
  /// @param args A list of arguments for starting the hosted program.
  /// @param[out] child_name A locally-unique name for the started program.
  /// @TODO(kwalsh) The child_name given by the Tao can just be a counter or an
  ///               opaque unique id or hash. Or it could be something
  ///               descriptive, including the program hash, argument hash,
  ///               PID, start time, etc., so long as the result is locally
  ///               unique. The linux tao takes the latter approach for ease of
  ///               administration, and so that the caller can use the PID for
  ///               other things, e.g. sending signals to the process.
  virtual bool StartHostedProgram(const string &name, const list<string> &args,
                                  string *child_name) = 0;

  /// Remove the hosted program from the running programs. Note that this does
  /// not necessarily stop the hosted program itself.
  /// @param child_name The locally-unique name of the hosted program to remove.
  virtual bool RemoveHostedProgram(const string &child_name) = 0;

  /// Shut down the Tao.
  /// Note: This is never called: it is implemented entirely by TaoChannel.
  bool Shutdown() { return false; }

  /// Get the full name of this Tao, i.e. as a descendent of the root Tao.
  /// @param[out] tao_name The full, globally-unique name of the Tao.
  virtual bool GetTaoFullName(string *tao_name) const = 0;

  /// Get the local name of this Tao, i.e. as identified by its own signing key.
  /// @param[out] local_name The public signing key, encoded as a principal
  /// name.
  virtual bool GetLocalName(string *local_name) const = 0;

  /// Get the policy name of this Tao, i.e. as shown in the policy attestation.
  /// @param[out] policy_name The name encoded in the policy attestation.
  virtual bool GetPolicyName(string *policy_name) const = 0;

  /// Install a new policy attestation for this Tao.
  virtual bool InstallPolicyAttestation(const string &attestation) = 0;

  // @}

  /// Hosted-program interfaces for using the Tao.
  /// These methods have a child_name parameter that identifies the requesting
  /// hosted program.
  /// @{

  bool GetHostedProgramFullName(const string &child_name,
                                string *full_name) const {
    string tao_name;
    bool success = GetTaoFullName(&tao_name);
    if (success) full_name->assign(tao_name + "::" + child_name);
    return success;
  }

  virtual bool GetRandomBytes(const string &child_name, size_t size,
                              string *bytes) const = 0;

  // TODO(kwalsh) This is a temporary hack, we need a policy to enforce.
  static const int PolicyAny = 0;
  static const int PolicySameID = 1;
  static const int PolicySameProgHash = 2;
  static const int PolicySameArgHash = 4;
  static const int PolicySamePID = 8;
  static const int PolicySameSubprin = 16;

  /// Encrypt data so only certain hosted programs can unseal it.
  /// @param child_name The local name of the hosted program making the request.
  /// @param data The data to seal.
  /// @param policy A policy controlling which hosted programs can unseal.
  /// @param[out] sealed The encrypted data
  /// @TODO(kwalsh) policy is a hack for now -- replace with goal formula?
  ///               the linux tao will use a bitwise mask of:
  ///               1 for "exact program id",
  ///               2 for "exact program hash",
  ///               4 for "exact argument hash",
  ///               8 for "same PID", (not implemented)
  ///               16 for "same start time", etc. (not implemented)

  /// @}

 private:
  DISALLOW_COPY_AND_ASSIGN(Tao);
};
}  // namespace tao

#endif  // TAO_TAO_H_
