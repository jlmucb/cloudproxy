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

#include <list>
#include <string>

#include <tss/platform.h>
#include <tss/tspi.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/tss_structs.h>
#include <tss/tss_typedef.h>

#include <trousers/trousers.h>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_child_channel.h"
#include "tao/util.h"

using std::string;

namespace tao {
/// A TaoChildChannel implementation that wraps a TPM and presents the Tao
/// interface. This allows other Tao implementations to treat the TPM
/// like an implementation of the Tao. This implementation uses the TrouSerS
/// library (hence implicitly the tcsd service) to access the TPM.
class TPMTaoChildChannel : public TaoChildChannel {
 public:
  /// Initializes the TPMTaoChildChannel
  /// @param aik_blob A public AIK blob produced by the TPM.
  /// @param pcrs_indexes A list of PCR indexes used for sealing and unsealing.
  /// For DRTM we typically use indexes 17 and 18. Relevant PCR indexes are:
  ///   17 - trusted os policy (DRTM LCP)
  ///   18 - trusted os startup code (DRTM MLE)
  ///   19 - tboot initrd hash (?)
  ///   20 - trusted os kernel and other code (?)
  ///   21 - defined by trusted os
  ///   22 - defined by trusted os
  TPMTaoChildChannel(const string &aik_blob, const list<int> &pcr_indexes);
  virtual ~TPMTaoChildChannel() {}

  /// These methods have the same semantics as TaoChildChannel.
  /// @{
  virtual bool Init();
  virtual bool Destroy();
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &data, int policy, string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data, int *policy) const;
  virtual bool Attest(const string &stmt, string *attestation) const;
  virtual bool GetHostedProgramFullName(string *full_name) const;
  virtual bool ExtendName(const string &subprin) const;
  /// @}

  /// Verify a TPM-generated quote signature.
  /// @param signer The TPM AIK, encoded as a principal name.
  /// @param data The serialized Statement that was signed.
  /// @param sig The signature to be verified.
  static bool VerifySignature(const string &signer, const string &stmt,
                              const string &sig);

 protected:
  virtual bool SendRPC(const TaoChildRequest &rpc) const { return false; }
  virtual bool ReceiveRPC(TaoChildResponse *resp, bool *eof) const {
    *eof = false;
    return false;
  }

 private:
  static const int PcrLen = 20;
  static const int PcrMaxIndex = 0x7fff; // uint16 max

  /// An Attestation Identity Key associated with this TPM.
  string aik_blob_;

  /// A handle to the AIK within the TPM after it is loaded.
  TSS_HKEY aik_;

  /// The AIK encoded as a principal name.
  string aik_name_;

  /// A list of Platform Configuration Register indexes used to identify the
  /// hosted program.
  std::list<int> pcr_indexes_;

  /// A set of PCR values for the hosted program, encoded as hex strings.
  std::list<string> child_pcr_values_;

  /// A handle to a set of PCR values within the TPM for the hosted program, used
  /// for Seal operations.
  TSS_HPCRS tss_pcr_values_;

  /// A handle to a set of PCR indexes within the TPM for the hosted program, used
  /// for Quote operations.
  TSS_HPCRS tss_pcr_indexes_;

  // The maximum number of PCRs in this TPM.
  //UINT32 pcr_max_;

  // The total number of bytes needed to store the PCR bit mask.
  //UINT32 pcr_mask_len_;

  /// A handle to the Storage Root Key for the TPM, used for Seal operations.
  TSS_HKEY srk_;
  
  /// A handle for a connection to the TPM.
  TSS_HTPM tpm_;
  
  /// The context for TSS operations (e.g., handles memory management).
  TSS_HCONTEXT tss_ctx_;

  DISALLOW_COPY_AND_ASSIGN(TPMTaoChildChannel);
};
}  // namespace tao

#endif  // TAO_TPM_TAO_CHILD_CHANNEL_H_
