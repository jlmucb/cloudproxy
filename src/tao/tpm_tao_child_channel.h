//  File: tpm_tao_child_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A channel that communicates with tpmd in the Linux kernel to
//  implement the Tao over TPM hardware.
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

#ifndef TAO_TPM_TAO_CHILD_CHANNEL_H_
#define TAO_TPM_TAO_CHILD_CHANNEL_H_

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include "tao/tao_child_channel.h"

namespace tao {
class TPMTaoChildChannel : public TaoChildChannel {
 public:
  TPMTaoChildChannel();
  virtual ~TPMTaoChildChannel() {}

  // Tao interface methods without the child hash parameter
  virtual bool Init();
  virtual bool Destroy();
  virtual bool StartHostedProgram(const string &path,
                                  const list<string> &args) {
    // In the case of the TPM, this would mean to start an OS, and that is
    // accomplished by other means.
    return false;
  }
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &data, string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data) const;
  virtual bool Attest(const string &data, string *attestation) const;
  virtual bool VerifyAttestation(const string &attestation, string *data) const;

 protected:
  // subclasses implement these methods for the underlying transport.
  virtual bool ReceiveMessage(google::protobuf::Message *m) const {
    return false;
  }

  virtual bool SendMessage(const google::protobuf::Message &m) const {
    return false;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(TPMTaoChildChannel);
};
}  // namespace tao

#endif  // TAO_TPM_TAO_CHILD_CHANNEL_H_
