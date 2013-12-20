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
  virtual bool Init() = 0;
  virtual bool Destroy() = 0;
  virtual bool StartHostedProgram(const string &path,
                                  const list<string> &args) = 0;
  virtual bool RemoveHostedProgram(const string &child_hash) = 0;
  virtual bool GetRandomBytes(size_t size, string *bytes) const = 0;
  virtual bool Seal(const string &child_hash, const string &data,
                    string *sealed) const = 0;
  virtual bool Unseal(const string &child_hash, const string &sealed,
                      string *data) const = 0;
  virtual bool Attest(const string &child_hash, const string &data,
                      string *attestation) const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(Tao);
};
}

#endif  // TAO_TAO_H_
