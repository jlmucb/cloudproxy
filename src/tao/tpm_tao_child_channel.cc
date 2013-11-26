//  File: tpm_tao_child_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the TPM Tao child channel.
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

#include "tao/tpm_tao_child_channel.h"

#include <netinet/in.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "tao/attestation.pb.h"

namespace tao {
TPMTaoChildChannel::TPMTaoChildChannel(const string &aik_blob,
                                       const string &aik_attestation,
                                       const list<UINT32> &pcrs_to_seal)
    : aik_blob_(aik_blob),
      aik_attestation_(aik_attestation),
      pcrs_to_seal_(pcrs_to_seal.begin(), pcrs_to_seal.end()) {
  // nothing to do yet. But this should be get the information needed for Init
  // to connect to the TPM
}

bool TPMTaoChildChannel::Init() {
  TSS_RESULT result;
  TSS_UUID srk_uuid = {0x00000000, 0x0000, 0x0000, 0x00, 0x00,
                       {0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
  BYTE secret[20];

  // Use the well-known secret of 20 zeroes.
  memset(secret, 0, 20);

  // Set up the TSS context and the SRK + policy (with the right secret).
  result = Tspi_Context_Create(&tss_ctx_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a TSS context.";

  result = Tspi_Context_Connect(tss_ctx_, NULL /* Default TPM */);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not connect to the default TPM";

  result = Tspi_Context_GetTpmObject(tss_ctx_, &tpm_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get a handle to the TPM";

  result =
      Tspi_Context_LoadKeyByUUID(tss_ctx_, TSS_PS_TYPE_SYSTEM, srk_uuid, &srk_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the SRK handle";

  result = Tspi_GetPolicyObject(srk_, TSS_POLICY_USAGE, &srk_policy_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the SRK policy handle";

  result = Tspi_Policy_SetSecret(srk_policy_, TSS_SECRET_MODE_SHA1, 20, secret);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not set the well-known secret";

  // Create and fill the PCR information for sealing and unsealing.
  result =
      Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_PCRS, 0, &seal_pcrs_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a PCRs object";

  // This seal operation is meant to be used with DRTM, so the only PCRs that it
  // reads are 17 and 18. This is where you can set other PCRs to use.
  list<UINT32> pcrs_to_seal{17, 18};
  BYTE *pcr_value = NULL;
  UINT32 pcr_value_len = 0;
  for (UINT32 ui : pcrs_to_seal) {
    result = Tspi_TPM_PcrRead(tpm_, ui, &pcr_value_len, &pcr_value);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not read the value of PCR " << ui;

    result =
        Tspi_PcrComposite_SetPcrValue(seal_pcrs_, ui, pcr_value_len, pcr_value);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not set the PCR value" << ui
                                  << " for sealing";
  }

  // Get the AIK for quote operations.
  result = Tspi_Context_LoadKeyByBlob(
      tss_ctx_, srk_, aik_blob_.size(),
      reinterpret_cast<BYTE *>(const_cast<char *>(aik_blob_.data())), &aik_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the AIK";

  // Extract the modulus from the AIK
  UINT32 aik_mod_len;
  BYTE *aik_mod;
  result = Tspi_GetAttribData(aik_, TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aik_mod_len,
                              &aik_mod);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not extract the RSA modulus";

  // Set up an OpenSSL RSA public key to use to verify the Quote
  aik_rsa_.reset(RSA_new());
  aik_rsa_->n = BN_bin2bn(aik_mod, aik_mod_len, NULL);
  aik_rsa_->e = BN_new();
  BN_set_word(aik_rsa_->e, 0x10001);

  Tspi_Context_FreeMemory(tss_ctx_, aik_mod);

  // Get the max number of PCRs in the TPM.
  UINT32 tpm_property = TSS_TPMCAP_PROP_PCR;
  UINT32 npcrs_len;
  BYTE *npcrs;
  result =
      Tspi_TPM_GetCapability(tpm_, TSS_TPMCAP_PROPERTY, sizeof(tpm_property),
                             (BYTE *)&tpm_property, &npcrs_len, &npcrs);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the number of PCRs";

  pcr_max_ = *(UINT32 *)npcrs;
  Tspi_Context_FreeMemory(tss_ctx_, npcrs);

  // The total number of bytes needed to store the PCR mask
  pcr_mask_len_ = (pcr_max_ + 7) / 8;

  // Create an object to manage the PCRs used for quotes.
  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_PCRS,
                                     TSS_PCRS_STRUCT_INFO, &quote_pcrs_);
  CHECK_EQ(result, TSS_SUCCESS)
      << "Could not create a PCRs object for the Quote";

  // Set the appropriate bits for the PCRs.
  for (UINT32 pcr_val : pcrs_to_seal) {
    result = Tspi_PcrComposite_SelectPcrIndex(quote_pcrs_, pcr_val);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not select PCR " << (int)pcr_val;
  }

  return true;
}

bool TPMTaoChildChannel::Destroy() {
  // Clean-up code.
  TSS_RESULT result;
  result = Tspi_Context_FreeMemory(tss_ctx_, NULL);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not free the context";

  result = Tspi_Context_Close(tss_ctx_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not clean up the context";
  return true;
}

bool TPMTaoChildChannel::GetRandomBytes(size_t size, string *bytes) const {
  return false;
}

bool TPMTaoChildChannel::Seal(const string &data, string *sealed) const {
  TSS_RESULT result;
  TSS_HENCDATA enc_data;
  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_ENCDATA,
                                     TSS_ENCDATA_SEAL, &enc_data);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not create the data for sealing";
    return false;
  }

  result = Tspi_Data_Seal(
      enc_data, srk_, data.size(),
      reinterpret_cast<BYTE *>(const_cast<char *>(data.data())), seal_pcrs_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not seal the test data";
    return false;
  }

  // Extract the sealed data.
  BYTE *sealed_data;
  UINT32 sealed_data_len;
  result = Tspi_GetAttribData(enc_data, TSS_TSPATTRIB_ENCDATA_BLOB,
                              TSS_TSPATTRIB_ENCDATABLOB_BLOB, &sealed_data_len,
                              &sealed_data);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not get the sealed bits";
    return false;
  }

  sealed->assign(reinterpret_cast<char *>(sealed_data), sealed_data_len);

  // Clean up the enc data and the extracted data.
  Tspi_Context_FreeMemory(tss_ctx_, sealed_data);
  Tspi_Context_CloseObject(tss_ctx_, enc_data);
  return true;
}

bool TPMTaoChildChannel::Unseal(const string &sealed, string *data) const {
  TSS_RESULT result;
  TSS_HENCDATA enc_data;
  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_ENCDATA,
                                     TSS_ENCDATA_SEAL, &enc_data);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not create the data for sealing";
    return false;
  }

  result = Tspi_SetAttribData(
      enc_data, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB,
      sealed.size(),
      reinterpret_cast<BYTE *>(const_cast<char *>(sealed.data())));
  CHECK_EQ(result, TSS_SUCCESS)
      << "Could not set the sealed data for unsealing";

  BYTE *unsealed_data;
  UINT32 unsealed_data_len;
  result = Tspi_Data_Unseal(enc_data, srk_, &unsealed_data_len, &unsealed_data);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not unseal the data";

  data->assign(reinterpret_cast<char *>(unsealed_data), unsealed_data_len);

  Tspi_Context_FreeMemory(tss_ctx_, unsealed_data);
  Tspi_Context_CloseObject(tss_ctx_, enc_data);
  return true;
}

bool TPMTaoChildChannel::Attest(const string &data, string *attestation) const {
  TSS_RESULT result;

  // The following code for setting up the composite hash is based on
  // aikquote.c, the sample AIK quote code.
  scoped_array<BYTE> serialized_pcrs(new BYTE[
      sizeof(UINT16) + pcr_mask_len_ + sizeof(UINT32) + PcrLen * pcr_max_]);

  // The Quote format is:
  // UINT16: size of pcr mask (in network byte order)
  // pcr mask
  // UINT32: size of serialized pcrs
  // serialized pcrs

  BYTE *pcr_buf = serialized_pcrs.get();
  UINT32 index = 0;

  // size of pcr mask
  *(UINT16 *)(pcr_buf + index) = htons(pcr_mask_len_);
  index += sizeof(UINT16);
  memset(pcr_buf + index, 0, pcr_mask_len_);

  // Set the appropriate bits for the PCRs
  for (UINT32 pcr_val : pcrs_to_seal_) {
    pcr_buf[index + (pcr_val / 8)] |= 1 << (pcr_val % 8);
  }
  index += pcr_mask_len_;

  // Write the length of the set of PCRs
  *(UINT32 *)(pcr_buf + index) = htonl(PcrLen * pcrs_to_seal_.size());
  index += sizeof(UINT32);

  // Set up a statement containing the data and hash it with SHA1
  Statement s;
  time_t cur_time;
  time(&cur_time);

  s.set_time(cur_time);
  s.set_expiration(cur_time + AttestationTimeout);
  s.set_data(data);
  // i.e., see Attestation.quote
  s.set_hash_alg("TPM1.2 Quote");
  s.set_hash("");

  string serialized_statement;
  if (!s.SerializeToString(&serialized_statement)) {
    LOG(ERROR) << "Could not serialize the statement to a string";
    return false;
  }

  // Hash the data with SHA1
  BYTE statement_hash[20];
  SHA1(reinterpret_cast<const BYTE *>(serialized_statement.data()),
       serialized_statement.size(), statement_hash);

  TSS_VALIDATION valid;
  valid.ulExternalDataLength = sizeof(statement_hash);
  valid.rgbExternalData = statement_hash;

  result = Tspi_TPM_Quote(tpm_, aik_, quote_pcrs_, &valid);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not quote data with the AIK";

  // Check the hash from the quote
  TPM_QUOTE_INFO *quote_info = (TPM_QUOTE_INFO *)valid.rgbData;

  BYTE *temp_pcr;
  UINT32 temp_pcr_len;
  for (UINT32 pcr_val : pcrs_to_seal_) {
    result = Tspi_PcrComposite_GetPcrValue(quote_pcrs_, pcr_val, &temp_pcr_len,
                                           &temp_pcr);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not get PCR " << (int)pcr_val;

    memcpy(pcr_buf + index, temp_pcr, temp_pcr_len);
    index += temp_pcr_len;

    Tspi_Context_FreeMemory(tss_ctx_, temp_pcr);
  }

  // Compute the composite hash to check against the hash in the quote info.
  // TODO(tmroeder): Gate this check on a FLAGS value, like FLAGS_tpm_tao_debug
  BYTE pcr_digest[20];
  SHA1(pcr_buf, index, pcr_digest);

  if (memcmp(pcr_digest, quote_info->compositeHash.digest,
             sizeof(pcr_digest)) !=
      0) {
    // aikquote.c here says "Try with a smaller digest length". I don't know
    // why. This code removes one of the bytes in the pcr mask and shifts
    // everything over to account for the difference, then hashes and tries
    // again.
    *(UINT16 *)pcr_buf = htons(pcr_mask_len_ - 1);
    memmove(pcr_buf + sizeof(UINT16) + pcr_mask_len_ - 1,
            pcr_buf + sizeof(UINT16) + pcr_mask_len_,
            index - (sizeof(UINT16) + pcr_mask_len_));
    index -= 1;
    SHA1(pcr_buf, index, pcr_digest);
    if (memcmp(pcr_digest, quote_info->compositeHash.digest,
               sizeof(pcr_digest)) !=
        0) {
      LOG(ERROR) << "Neither size of hash input worked for Quote computation";
      return 1;
    }
  }

  // At this point, the quote is in pcr_buf with length index.
  string quote(reinterpret_cast<char *>(pcr_buf), index);
  string signature(reinterpret_cast<char *>(valid.rgbValidationData),
                   valid.ulValidationDataLength);

  Attestation a;
  a.set_type(TPM_1_2_QUOTE);
  a.set_serialized_statement(serialized_statement);
  a.set_quote(quote);
  a.set_signature(signature);
  a.set_cert(aik_attestation_);

  if (!a.SerializeToString(attestation)) {
    LOG(ERROR) << "Could not serialize the TPM 1.2 Quote attestation";
    return false;
  }

  return true;
}
}  // namespace tao
