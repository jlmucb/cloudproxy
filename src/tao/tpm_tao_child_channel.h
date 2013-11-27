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
#include "tao/util.h"

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

namespace tao {
class TPMTaoChildChannel : public TaoChildChannel {
 public:
  // Initializes the TPMTaoChildChannel with the public key of the AIK as a blob
  // in the form of a TSS TPM_KEY.
  TPMTaoChildChannel(const string &aik_blob, const string &aik_attestation,
                     const list<UINT32> &pcrs_to_seal);
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

 protected:
  virtual bool ReceiveMessage(google::protobuf::Message *m) const {
    return false;
  }

  virtual bool SendMessage(const google::protobuf::Message &m) const {
    return false;
  }

 private:
  static const int PcrLen = 20;

  // the timeout for an Attestation (= 1 year in seconds)
  static const int AttestationTimeout = 31556926;

  // The public Attestation Identity Key associated with the TPM.
  string aik_blob_;

  // An OpenSSL RSA public-key version of the AIK.
  ScopedRsa aik_rsa_;

  // An attestation to aik_blob_ using the policy key.
  string aik_attestation_;

  // The list of PCRs to use for Seal and Quote.
  list<UINT32> pcrs_to_seal_;

  // The context for TSS operations (e.g., handles memory management).
  TSS_HCONTEXT tss_ctx_;

  // A handle for a connection to the TPM.
  TSS_HTPM tpm_;

  // A handle to the Storage Root Key for the TPM.
  TSS_HKEY srk_;

  // A handle to the policy for the SRK.
  TSS_HPOLICY srk_policy_;

  // A set of Platform Configuration Registers used for sealing.
  TSS_HPCRS seal_pcrs_;

  // A set of Platform Configuration Registers used for quotes.
  TSS_HPCRS quote_pcrs_;

  // A handle to the AIK.
  TSS_HKEY aik_;

  // The maximum number of PCRs in this TPM.
  UINT32 pcr_max_;

  // The total number of bytes needed to store the PCR bit mask.
  UINT32 pcr_mask_len_;

  DISALLOW_COPY_AND_ASSIGN(TPMTaoChildChannel);
};
}  // namespace tao

#endif  // TAO_TPM_TAO_CHILD_CHANNEL_H_
