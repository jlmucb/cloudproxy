//  File: tpm_tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A Tao interface for accessing a hardware TPM.
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
#ifndef TAO_TPM_TAO_H_
#define TAO_TPM_TAO_H_

#include <list>
#include <string>

#include <tss/platform.h>
#include <tss/tspi.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/tss_structs.h>
#include <tss/tss_typedef.h>

#include <trousers/trousers.h>

#include "tao/tao.h"
#include "tao/util.h"

namespace tao {
/// A Tao interface for accessing a hardware TPM. This implementation uses the
/// TrouSerS library (hence implicitly the tcsd service) to access the TPM.
class TPMTao : public Tao {
 public:
  /// Construct a TPMTao.
  /// @param aik_blob A public AIK blob produced by the TPM.
  /// @param pcrs_indexes A list of PCR indexes used for sealing and unsealing.
  /// For DRTM we typically use indexes 17 and 18. Relevant PCR indexes are:
  ///   17 - trusted os policy (DRTM LCP)
  ///   18 - trusted os startup code (DRTM MLE)
  ///   19 - tboot initrd hash (?)
  ///   20 - trusted os kernel and other code (?)
  ///   21 - defined by trusted os
  ///   22 - defined by trusted os
  TPMTao(const string &aik_blob, const list<int> &pcr_indexes)
      : aik_blob_(aik_blob),
        pcr_indexes_(pcr_indexes.begin(), pcr_indexes.end()) {}

  /// Construct a TPMTao without an AIK. The TPMTao will not be able to perform
  /// Attest operations, but it can be used for examing the current PCR values,
  /// creating AIK blobs, etc.
  /// @param pcrs_indexes A list of PCR indexes used for sealing and unsealing.
  TPMTao(const list<int> &pcr_indexes) : TPMTao("", pcr_indexes) {}

  virtual bool Init();
  virtual bool Destroy();
  virtual ~TPMTao() {}

  /// These methods have the same semantics as Tao.
  /// @{
  virtual bool GetTaoName(string *name) const;
  virtual bool ExtendTaoName(const string &subprin) const;
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Attest(const Statement &stmt, string *attestation) const;
  virtual bool Seal(const string &data, const string &policy,
                    string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data, string *policy) const;
  /// @}

  /// Verify a TPM-generated quote signature.
  /// @param signer The TPM AIK, encoded as a principal name.
  /// @param data The serialized Statement that was signed.
  /// @param sig The signature to be verified.
  static bool VerifySignature(const string &signer, const string &stmt,
                              const string &sig);

  /// Get the list of PCR values corresponding to the PCR indexes specified when
  /// the TPMTao was constructed.
  /// @param[out] values A list of hex-encoded PCR values.
  bool GetPCRValues(list<string> *values) const {
    values->assign(child_pcr_values_.begin(), child_pcr_values_.end());
    return true;
  }

  /// Create a fresh AIK blob.
  /// @param[out] aik_blob The AIK blob.
  bool CreateAIK(string *aik_blob);

  /// Size of PCR values.
  static const int PcrLen = 20;
 
  /// The largest possible PCR index (24 is the minimum for TPM 1.2).
  static const int PcrMaxIndex = 0x7fff;  // max value for INT16

 private:

  /// An Attestation Identity Key associated with this TPM.
  string aik_blob_;

  /// A handle to the AIK within the TPM after it is loaded.
  TSS_HKEY aik_;

  /// The AIK encoded as a principal name.
  string aik_name_;

  /// A list of Platform Configuration Register indexes used to identify the
  /// hosted program.
  list<int> pcr_indexes_;

  /// A set of PCR values for the hosted program, encoded as hex strings.
  list<string> child_pcr_values_;

  /// A handle to a set of PCR values within the TPM for the hosted program,
  /// used
  /// for Seal operations.
  TSS_HPCRS tss_pcr_values_;

  /// A handle to a set of PCR indexes within the TPM for the hosted program,
  /// used
  /// for Quote operations.
  TSS_HPCRS tss_pcr_indexes_;

  /// A handle to the Storage Root Key for the TPM, used for Seal operations.
  TSS_HKEY srk_;

  /// A handle for a connection to the TPM.
  TSS_HTPM tpm_;

  /// The context for TSS operations (e.g., handles memory management).
  TSS_HCONTEXT tss_ctx_;

  DISALLOW_COPY_AND_ASSIGN(TPMTao);
};
}  // namespace tao

#endif  // TAO_TPM_TAO_H_
