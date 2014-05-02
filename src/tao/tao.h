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
/// For example, a Linux system installed on hardware with a TPM might work as
/// follows: TPMTaoChildChannel <-> LinuxTao <-> PipeTaoChannel. The
/// TPMTaoChildChannel implements a shim for the TPM hardware to convert Tao
/// operations into TPM commands. LinuxTao implements the Tao for Linux, and it
/// holds a PipeTaoChannel that it uses to communicate with hosted programs
/// running as processes. A hosted program called CloudServer would have the
/// following interactions: PipeTaoChildChannel <-> CloudServer. The
/// PipeTaoChildChannel and the PipeTaoChannel communicate over Unix pipes to
/// send Tao messages between LinuxTao and CloudServer. See the apps/ folder for
/// applications that implement exactly this setup: apps/linux_tao_service.cc
/// implements the LinuxTao, and apps/server.cc implements CloudServer.
///
/// Similarly, the LinuxTao could start KVM Guests as hosted programs
/// (using the KvmVmFactory instead of the ProcessFactory). In this case, the
/// interaction would be: TPMTaoChildChannel <-> LinuxTao <-> KvmUnixTaoChannel.
///
/// And the guest OS would have another instance of the LinuxTao that would have
/// the following interactions:
/// KvmUnixTaoChildChannel <-> LinuxTao <-> PipeTaoChannel. This version of
/// the LinuxTao in the Guest OS would use the ProcessFactory to start hosted
/// programs as processes in the guest.
///
/// In summary: each level of the Tao can have a TaoChildChannel to communicate
/// with its host Tao and has a TaoChannel to communicated with hosted programs.
/// Hosts use implementations of HostedProgramFactory to instantiate hosted
/// programs.
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

  /// Get the full name of this Tao, starting at the root Tao.
  /// @param[out] tao_name The full, globally-unique name of the Tao.
  virtual bool GetTaoFullName(string *tao_name) = 0;

  // @}

  /// Hosted-program interfaces for using the Tao.
  /// These methods have a child_name parameter that identifies the requesting
  /// hosted program.
  /// @{

  /// Get the full name of the requesting hosted program.
  /// @param child_name The local name of the hosted program making the request.
  /// @param[out] full_name The full, globally-unique name of the child.
  /// Note: This is never called: it is implemented entirely by TaoChannel.
  bool GetHostedProgramFullName(const string &child_name, string *full_name) {
    string tao_name;
    bool success = GetTaoFullName(&tao_name);
    if (success) full_name->assign(tao_name + "::" + child_name);
    return success;
  }

  /// Get a random string of a given size.
  /// @param child_name The local name of the hosted program making the request.
  /// @param size The size of string to get, in bytes.
  /// @param[out] bytes The random bytes generated by this call.
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
  virtual bool Seal(const string &child_name, const string &data, int policy,
                    string *sealed) const = 0;

  /// Decrypt data that has been sealed by the Seal() operation, but only
  /// if the requesting hosted program satisfies the policy specified at
  /// in the Seal() operation.
  /// @param child_name The local name of the hosted program making the request.
  /// @param sealed The sealed data to decrypt.
  /// @param[out] data The decrypted data, if the policy was satisfied.
  /// @param[out] policy The sealing policy, if it was satisfied.
  /// Note: The unseal policy can be used as a limited integrity check, since
  /// (currently) only a hosted program that itself satisfies the policy could
  /// have performed the Seal() operation. This is only true, however, because
  /// of the limited policies supported in Seal().
  virtual bool Unseal(const string &child_name, const string &sealed,
                      string *data, int *policy) const = 0;

  /// Produce a signed statement that asserts that a given program produced a
  /// given data string.
  /// @param child_name The local name of the hosted program making the request.
  /// @param data The data produced by the hosted program.
  /// @param[out] attestation The resulting signed message. For verification see
  /// TaoAuth and its implementations.
  /// TODO(kwalsh) Make the opaque data string into a statement in some logic?
  virtual bool Attest(const string &child_name, const string &data,
                      string *attestation) const = 0;

  /// Extend a childs name with a new subprincipal name.
  /// @param[in,out] child_name The local name of the hosted program making the
  /// request. If successful, this is extended with the subprin name.
  /// @param subprin The subprincipal to use for extending child_name.
  virtual bool ExtendName(string *child_name, const string &subprin) = 0;

  /// @}

  constexpr static auto AttestationSigningContext =
      "tao::Attestation Version 1";

  /// The timeout for an Attestation (= 1 year in seconds).
  static const int DefaultAttestationTimeout = 31556926;

  /// Default size of secret for protecting crypting and signing keys.
  static const int DefaultRandomSecretSize = 128;

 private:
  DISALLOW_COPY_AND_ASSIGN(Tao);
};
}  // namespace tao

#endif  // TAO_TAO_H_
