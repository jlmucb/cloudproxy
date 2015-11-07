// Copyright 2015 Google Corporation, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// File: quote_protocol.cc

// standard buffer size

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <tpm20.h>
#include <tpm2_lib.h>
#include <errno.h>

#include <tpm2.pb.h>
#include <openssl/sha.h>
#include <openssl_helpers.h>

#include <string>
#define DEBUG


/*
 *  typedef struct {
 *    TPM_GENERATED   magic;
 *    TPMI_ST_ATTEST  type;
 *    TPM2B_NAME      qualifiedSigner;
 *    TPM2B_DATA      extraData; (none)
 *    TPMS_CLOCK_INFO clockInfo;
 *    uint64_t        firmwareVersion;
 *    TPMU_ATTEST     attested;  (quote info) TPML_PCR_SELECTION, DIGEST
 *         TPML_PCR_SELECTION pcrSelect;
 *         TPM2B_DIGEST       pcrDigest;
 *  } TPMS_ATTEST;  This is the certInfo
 *  
 *  hash certifyinfo  (contains pcrDigests)
 *  hash(qualifyingData || hash(certInfo))
 */

bool MarshalCertifyInfo(TPMS_ATTEST& in, int* size, byte* out) {
  return true;
}

bool UnmarshalCertifyInfo(int size, byte* in, TPMS_ATTEST* out) {
  return true;
}

bool ProtoToCertifyInfo(quote_certification_information& message, TPMS_ATTEST* out) {
  memcpy((byte*)&out->magic, (byte*)message.magic().data(), sizeof(uint32_t));
  out->type = *(uint16_t*)message.type().data();
  message.qualifiedsigner();
  out->extraData.size = 0;
  memcpy(&out->clockInfo, message.clockinfo().data(), message.clockinfo().size());
  out->firmwareVersion = message.firmwareversion();
  memcpy(&out->attested.quote.pcrSelect, message.pcr_selection().data(), message.pcr_selection().size());
  out->attested.quote.pcrDigest.size = message.digest().size();
  return true;
}

bool CertifyInfoToProto(TPMS_ATTEST& in, quote_certification_information& message) {
  return true;
}

bool ComputeQuotedValue(TPMS_PCR_SELECTION pcrSelection, int size_pcr, byte* pcr_buf,
                        int quote_size, byte* quote, int* size_quoted, byte* quoted) {
  byte pcr_digest[256];
  int size_out;

  size_out = 256;
  if (!ComputePcrDigest(pcrSelection, size_pcr, pcr_buf,
                      &size_out, pcr_digest)) {
    printf("ComputePcrDigest failed\n");
    return false;
  }

#ifdef DEBUG
  printf("PCR digest: ");
  PrintBytes(size_out, pcr_digest);
  printf("\n");
#endif

  if (pcrSelection.hash == TPM_ALG_SHA1) {
    SHA_CTX sha1;
    SHA_Update(&sha1, pcr_digest, 20);
    SHA_Update(&sha1, quote, quote_size);
    SHA_Final(quoted, &sha1);
    *size_quoted = 20;
  } else if (pcrSelection.hash == TPM_ALG_SHA256) {
    SHA256_CTX sha256;
    SHA256_Update(&sha256, pcr_digest, 32);
    SHA256_Update(&sha256, quote, quote_size);
    SHA256_Final(quoted, &sha256);
    *size_quoted = 32;
  } else {
    printf("unsupported hash alg\n");
    return false;
  }

  return true;
}


