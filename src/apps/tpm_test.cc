//  File: tpm_test.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A test of the TrouSerS API
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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include <netinet/in.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#include <fstream>
#include <list>
#include <sstream>
#include <string>

using std::ifstream;
using std::list;
using std::string;
using std::stringstream;

#define PCR_LEN 20

DEFINE_string(
    aikblobfile, "aikblob",
    "A file containing an AIK blob that has been loaded into the TPM");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  TSS_HCONTEXT tss_ctx;
  TSS_HTPM tpm;
  TSS_RESULT result;
  TSS_HKEY srk = 0;
  TSS_HPOLICY srk_policy = 0;
  TSS_UUID srk_uuid = {0x00000000, 0x0000, 0x0000, 0x00, 0x00,
                       {0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
  BYTE secret[20];

  // Use the well-known secret of 20 zeroes.
  memset(secret, 0, 20);

  // Set up the TSS context and the SRK + policy (with the right secret).
  result = Tspi_Context_Create(&tss_ctx);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a TSS context.";

  result = Tspi_Context_Connect(tss_ctx, NULL /* Default TPM */);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not connect to the default TPM";

  result = Tspi_Context_GetTpmObject(tss_ctx, &tpm);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get a handle to the TPM";

  result =
      Tspi_Context_LoadKeyByUUID(tss_ctx, TSS_PS_TYPE_SYSTEM, srk_uuid, &srk);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the SRK handle";

  result = Tspi_GetPolicyObject(srk, TSS_POLICY_USAGE, &srk_policy);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the SRK policy handle";

  result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1, 20, secret);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not set the well-known secret";

  // Create and fill the PCR information.
  TSS_HPCRS pcrs;
  result = Tspi_Context_CreateObject(tss_ctx, TSS_OBJECT_TYPE_PCRS, 0, &pcrs);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a PCRs object";

  // This seal operation is meant to be used with DRTM, so the only PCRs that it
  // reads are 17 and 18. This is where you can set other PCRs to use.
  list<UINT32> pcrs_to_seal{17, 18};
  BYTE *pcr_value = NULL;
  UINT32 pcr_value_len = 0;
  for (UINT32 ui : pcrs_to_seal) {
    result = Tspi_TPM_PcrRead(tpm, ui, &pcr_value_len, &pcr_value);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not read the value of PCR " << ui;

    result = Tspi_PcrComposite_SetPcrValue(pcrs, ui, pcr_value_len, pcr_value);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not set the PCR value" << ui
                                  << " for sealing";
  }

  TSS_HENCDATA enc_data;
  result = Tspi_Context_CreateObject(tss_ctx, TSS_OBJECT_TYPE_ENCDATA,
                                     TSS_ENCDATA_SEAL, &enc_data);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create the data for sealing";

  BYTE data[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  result = Tspi_Data_Seal(enc_data, srk, 16, data, pcrs);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not seal the test data";

  // Extract the sealed data, then try to unseal it.
  BYTE *sealed_data;
  UINT32 sealed_data_len;
  result = Tspi_GetAttribData(enc_data, TSS_TSPATTRIB_ENCDATA_BLOB,
                              TSS_TSPATTRIB_ENCDATABLOB_BLOB, &sealed_data_len,
                              &sealed_data);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the sealed bits";

  BYTE *unsealed_data;
  UINT32 unsealed_data_len;
  result = Tspi_Data_Unseal(enc_data, srk, &unsealed_data_len, &unsealed_data);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not unseal the data";

  // Check that the data was unsealed correctly.
  CHECK_EQ(unsealed_data_len, 16U) << "The unsealed data was the wrong length";
  CHECK_EQ(memcmp(unsealed_data, data, 16), 0)
      << "The unsealed data did not match the original data";

  // Get the public key blob from the AIK.
  // Load the blob and try to load the AIK
  ifstream blob_stream(FLAGS_aikblobfile, ifstream::in);
  stringstream blob_buf;
  blob_buf << blob_stream.rdbuf();
  string blob = blob_buf.str();
  UINT32 blob_len = (UINT32)blob.size();
  TSS_HKEY aik;
  result = Tspi_Context_LoadKeyByBlob(
      tss_ctx, srk, blob_len,
      reinterpret_cast<BYTE *>(const_cast<char *>(blob.data())), &aik);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the AIK";

  // Generate a Quote using this AIK.
  BYTE hash_to_sign[20];
  memset(hash_to_sign, 0, sizeof(hash_to_sign));

  // First get the max number of PCRs in the TPM
  UINT32 tpm_property = TSS_TPMCAP_PROP_PCR;
  UINT32 npcrs_len;
  BYTE *npcrs;
  result =
      Tspi_TPM_GetCapability(tpm, TSS_TPMCAP_PROPERTY, sizeof(tpm_property),
                             (BYTE *)&tpm_property, &npcrs_len, &npcrs);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the number of PCRs";

  UINT32 pcr_max = *(UINT32 *)npcrs;
  Tspi_Context_FreeMemory(tss_ctx, npcrs);

  // The total number of bytes needed to store the PCR mask
  UINT32 pcr_mask_len = (pcr_max + 7) / 8;

  TSS_HPCRS quote_pcrs;
  result = Tspi_Context_CreateObject(tss_ctx, TSS_OBJECT_TYPE_PCRS,
                                     TSS_PCRS_STRUCT_INFO, &quote_pcrs);
  CHECK_EQ(result, TSS_SUCCESS)
      << "Could not create a PCRs object for the Quote";

  // The following code for setting up the composite hash is based on
  // aikquote.c, the sample AIK quote code.
  scoped_array<BYTE> serialized_pcrs(new BYTE[
      sizeof(UINT16) + pcr_mask_len + sizeof(UINT32) + PCR_LEN * pcr_max]);

  // So, the format is:
  // UINT16: size of pcr mask (in network byte order)
  // pcr mask
  // UINT32: size of serialized pcrs
  // serialized pcrs

  BYTE *pcr_buf = serialized_pcrs.get();
  UINT32 index = 0;

  // size of pcr mask
  *(UINT16 *)(pcr_buf + index) = htons(pcr_mask_len);
  index += sizeof(UINT16);
  memset(pcr_buf + index, 0, pcr_mask_len);

  // Set the appropriate bits for the PCRs
  for (UINT32 pcr_val : pcrs_to_seal) {
    result = Tspi_PcrComposite_SelectPcrIndex(quote_pcrs, pcr_val);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not select PCR " << (int)pcr_val;
    pcr_buf[index + (pcr_val / 8)] |= 1 << (pcr_val % 8);
  }
  index += pcr_mask_len;

  // Write the length of the set of PCRs
  *(UINT32 *)(pcr_buf + index) = htonl(PCR_LEN * pcrs_to_seal.size());
  index += sizeof(UINT32);

  TSS_VALIDATION valid;
  valid.ulExternalDataLength = sizeof(hash_to_sign);
  valid.rgbExternalData = hash_to_sign;

  result = Tspi_TPM_Quote(tpm, aik, quote_pcrs, &valid);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not quote data with the AIK";

  // Check the hash from the quote
  TPM_QUOTE_INFO *quote_info = (TPM_QUOTE_INFO *)valid.rgbData;

  BYTE *temp_pcr;
  UINT32 temp_pcr_len;
  for (UINT32 pcr_val : pcrs_to_seal) {
    result = Tspi_PcrComposite_GetPcrValue(quote_pcrs, pcr_val, &temp_pcr_len,
                                           &temp_pcr);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not get PCR " << (int)pcr_val;

    memcpy(pcr_buf + index, temp_pcr, temp_pcr_len);
    index += temp_pcr_len;

    Tspi_Context_FreeMemory(tss_ctx, temp_pcr);
  }

  // Compute the composite hash to check against the hash in the quote info.
  BYTE pcr_digest[20];
  SHA1(pcr_buf, index, pcr_digest);

  if (memcmp(pcr_digest, quote_info->compositeHash.digest,
             sizeof(pcr_digest)) !=
      0) {
    // aikquote.c here says "Try with a smaller digest length". I don't know
    // why. This code removes one of the bytes in the pcr mask and shifts
    // everything over to account for the difference, then hashes and tries
    // again.
    *(UINT16 *)pcr_buf = htons(pcr_mask_len - 1);
    memmove(pcr_buf + sizeof(UINT16) + pcr_mask_len - 1,
            pcr_buf + sizeof(UINT16) + pcr_mask_len,
            index - (sizeof(UINT16) + pcr_mask_len));
    index -= 1;
    SHA1(pcr_buf, index, pcr_digest);
    if (memcmp(pcr_digest, quote_info->compositeHash.digest,
               sizeof(pcr_digest)) !=
        0) {
      LOG(FATAL) << "Neither size of hash input worked";
      return 1;
    }
  }

  // At this point, the quote is in pcr_buf with length index.

  // Extract the modulus from the AIK
  UINT32 aik_mod_len;
  BYTE *aik_mod;
  result = Tspi_GetAttribData(aik, TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aik_mod_len,
                              &aik_mod);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not extract the RSA modulus";

  // Set up an OpenSSL RSA public key to use to verify the Quote
  RSA *aik_rsa = RSA_new();
  aik_rsa->n = BN_bin2bn(aik_mod, aik_mod_len, NULL);
  aik_rsa->e = BN_new();
  BN_set_word(aik_rsa->e, 0x10001);

  // Try hashing and verifying the TPM_QUOTE_INFO itself
  BYTE quote_hash[20];

  // The quote can be verified in a qinfo, which has a header of 8 bytes, and
  // two hashes.
  // The first hash is the hash of the external data, and the second is the hash
  // of the
  // quote itself (pcr_buf above with length in index). This can be hashed and
  // verified
  // directly by OpenSSL.

  BYTE qinfo[8 + 2 * 20];
  qinfo[0] = 1;
  qinfo[1] = 1;
  qinfo[2] = 0;
  qinfo[3] = 0;
  qinfo[4] = 'Q';
  qinfo[5] = 'U';
  qinfo[6] = 'O';
  qinfo[7] = 'T';
  SHA1(pcr_buf, index, qinfo + 8);
  memcpy(qinfo + 8 + 20, hash_to_sign, 20);

  SHA1(qinfo, sizeof(qinfo), quote_hash);
  BYTE *sig = valid.rgbValidationData;
  UINT32 sig_len = valid.ulValidationDataLength;
  CHECK_EQ(RSA_verify(NID_sha1, quote_hash, sizeof(quote_hash), sig, sig_len,
                      aik_rsa),
           1) << "The RSA signature did not pass verification";

  // Clean-up code.
  result = Tspi_Context_FreeMemory(tss_ctx, NULL);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not free the context";

  result = Tspi_Context_Close(tss_ctx);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not clean up the context";

  return 0;
}
