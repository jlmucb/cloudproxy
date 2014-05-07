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
#include <sys/stat.h>
#include <sys/types.h>

#include <sstream>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/keyczar.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "tao/attestation.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/util.h"

using std::stringstream;

using keyczar::Verifier;
using keyczar::base::Base64WDecode;
using keyczar::base::Base64WEncode;

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
  TSS_UUID srk_uuid = {0x00000000,
                       0x0000,
                       0x0000,
                       0x00,
                       0x00,
                       {0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
  BYTE secret[20];

  // Use the well-known secret of 20 zeroes.
  memset(secret, 0, 20);

  // Set up the TSS context and the SRK + policy (with the right secret).
  result = Tspi_Context_Create(&tss_ctx_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a TSS context.";

  result = Tspi_Context_Connect(tss_ctx_, nullptr /* Default TPM */);
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
  // kwalsh: Why not others? e.g.
  //   17 - drtm and LCP
  //   18 - trusted os startup code (MLE)
  //   19 - tboot initrd hash?),
  //   20 - ? trusted os kernel and other code ?
  //   21 - defined by trusted os
  //   22 - defined by trusted os
  list<UINT32> pcrs_to_seal{17, 18};
  BYTE *pcr_value = nullptr;
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
  aik_rsa_->n = BN_bin2bn(aik_mod, aik_mod_len, nullptr);
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

bool TPMTaoChildChannel::VerifySignature(const Verifier &v, const string &stmt,
                                         const string &sig) {
  ScopedEvpPkey evp_key;
  if (!ExportPublicKeyToOpenSSL(v, &evp_key)) {
    LOG(ERROR) << "Could not export key to openssl format";
    return false;
  }
  ScopedRsa rsa_key(EVP_PKEY_get1_RSA(evp_key.get()));
  if (!rsa_key.get()) {
    LOG(ERROR) << "Key was not expected (RSA) type.";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(stmt)) {
    LOG(ERROR) << "Could not parse statement";
    return false;
  }
  // Extract PCR info from name in the statement
  string aik_name;
  if (!VerifierUniqueID(v, &aik_name)) {
    LOG(ERROR) << "Could not get aik name";
    return false;
  }
  string child_name = s.name();
  stringstream in(child_name);
  skip(in, aik_name);
  skip(in, "::");
  skip(in, "PCRs(");
  string pcr_index_list, pcr_value_list;
  getQuotedString(in, &pcr_index_list);
  skip(in, ", ");
  getQuotedString(in, &pcr_value_list);
  skip(in, ")");
  if (!in || !in.str().empty()) {
    LOG(ERROR) << "Bad child name in TPM quote statement";
    return false;
  }
  list<UINT32> pcr_indexes;
  in.str(pcr_index_list);
  UINT32 pcr_max = 0;
  bool first = true;
  while (in && !in.str().empty()) {
    if (!first) skip(in, ", ");
    first = false;
    UINT32 idx;
    in >> idx;
    pcr_indexes.push_back(idx);
    pcr_max = (idx > pcr_max ? idx : pcr_max);
  }
  if (!in) {
    LOG(ERROR) << "Bad PCR index list in TPM quote statement";
    return false;
  }
  list<string> pcr_values;
  in.str(pcr_value_list);
  first = true;
  while (in && !in.str().empty()) {
    if (!first) skip(in, ", ");
    first = false;
    string value;
    getQuotedString(in, &value);
    pcr_values.push_back(value);
  }
  if (!in || pcr_values.size() != pcr_indexes.size()) {
    LOG(ERROR) << "Bad PCR value list in TPM quote statement";
    return false;
  }

  // Hash the statement for the external data part of the quote.
  uint8 stmt_hash[20];
  SHA1(reinterpret_cast<const uint8 *>(stmt.data()), stmt.size(), stmt_hash);

  // Reconstruct pcrbuf

  // Serialized PCR format is:
  // UINT16: size of pcr mask (in network byte order)
  // BYTES: pcr mask
  // UINT32: size of serialized pcrs
  // BYTES: serialized pcrs
  int pcr_mask_len_min = (pcr_max + 7) / 8;
  pcr_mask_len_min = pcr_mask_len_min < 3 ? 3 : pcr_mask_len_min;

  // Try with minimal mask, then try larger mask.
  for (int i = 0; i < 2; i++) {
    int pcr_mask_len = pcr_mask_len_min + i;

    scoped_array<BYTE> serialized_pcrs(
        new BYTE[sizeof(UINT16) + pcr_mask_len + sizeof(UINT32) +
                 PcrLen * pcr_values.size()]);
    BYTE *pcr_buf = serialized_pcrs.get();
    UINT32 index = 0;

    // Size of pcr mask.
    *(UINT16 *)(pcr_buf + index) = htons(pcr_mask_len);
    index += sizeof(UINT16);
    memset(pcr_buf + index, 0, pcr_mask_len);

    // Set the appropriate bits for the PCRs.
    for (UINT32 idx : pcr_indexes) {
      pcr_buf[index + (idx / 8)] |= 1 << (idx % 8);
    }
    index += pcr_mask_len;

    // Size of the set of PCR values.
    *(UINT32 *)(pcr_buf + index) = htonl(PcrLen * pcr_values.size());
    index += sizeof(UINT32);

    // Set the PCR values.
    for (auto &pcr_info : pcr_values) {
      string pcr;
      if (!Base64WDecode(pcr_info, &pcr) || pcr.size() != PcrLen) {
        LOG(ERROR) << "Bad PCR encoded in TPM quote";
        return false;
      }
      memcpy(pcr_buf + index, pcr.data(), PcrLen);
      index += PcrLen;
    }

    // Hash the pcrbuf for the internal data part of the quote.
    uint8 pcr_hash[20];
    SHA1(pcr_buf, index, pcr_hash);

    // The quote signature can be verified in a qinfo, which has a header of 8
    // bytes, and two hashes.  The first hash is the hash of the external data,
    // and the second is the hash of the quote itself. This can be hashed and
    // verified directly using the key.

    uint8 qinfo[8 + 20 + 20];
    memcpy(qinfo, "\x1\x1\0\0QUOT", 8);  // 1 1 0 0 Q U O T
    memcpy(qinfo + 8, pcr_hash, 20);
    memcpy(qinfo + 8 + 20, stmt_hash, 20);

    uint8 quote_hash[20];
    SHA1(qinfo, sizeof(qinfo), quote_hash);

    if (1 == RSA_verify(NID_sha1, quote_hash, 20,
                        reinterpret_cast<const uint8 *>(sig.data()), sig.size(),
                        rsa_key.get())) {
      return true;
    }
    LOG(INFO) << "The RSA signature did not pass verification with mask size "
              << pcr_mask_len;
  }
  LOG(ERROR) << "The RSA signature did not pass verification";
  return false;
}

// TODO(kwalsh) This file could use some love

bool TPMTaoChildChannel::Destroy() {
  // Clean-up code.
  TSS_RESULT result;
  result = Tspi_Context_FreeMemory(tss_ctx_, nullptr);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not free the context";

  result = Tspi_Context_Close(tss_ctx_);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not clean up the context";
  return true;
}

bool TPMTaoChildChannel::GetRandomBytes(size_t size, string *bytes) const {
  TSS_RESULT result;
  BYTE *random;
  result = Tspi_TPM_GetRandom(tpm_, size, &random);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not get random bytes from the TPM";
    return false;
  }

  bytes->assign(reinterpret_cast<char *>(random), size);
  Tspi_Context_FreeMemory(tss_ctx_, random);
  return true;
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

bool TPMTaoChildChannel::Attest(const string &key_prin,
                                string *attestation) const {
  TSS_RESULT result;

  // The following code for setting up the composite hash is based on
  // aikquote.c, the sample AIK quote code.

  // Serialized PCR format is:
  // UINT16: size of pcr mask (in network byte order)
  // BYTES: pcr mask
  // UINT32: size of serialized pcrs
  // BYTES: serialized pcrs

  scoped_array<BYTE> serialized_pcrs(
      new BYTE[sizeof(UINT16) + pcr_mask_len_ + sizeof(UINT32) +
               PcrLen * pcr_max_]);
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

  // We have choices here.
  // (1) If we had a parent, which we don't, we could use it.
  // (2) We can create a binding via our key, to get:
  //   K_aik::PCRs(...)
  // where K_tpm is the tpm attestation key.
  // (3) We can create a binding via the policy key, to get:
  //   K_policy::TrustedPlatform::child_name
  // where K_policy::TrustedPlatform is the name we bound to K_aik by TaoCA.

  int option = 3;
  string name, delegation;
  if (option == 2) {
    if (!GetHostedProgramFullName(&name)) {
      LOG(ERROR) << "Could not get child's full name";
      return false;
    }
    delegation = "";
  } else {
    if (!GetNameFromKeyNameBinding(aik_attestation_, &name)) {
      LOG(ERROR) << "Could not get full name for policy attestation";
      return false;
    }
    delegation = aik_attestation_;
  }

  s.set_time(CurrentTime());
  s.set_expiration(s.time() + Tao::DefaultAttestationTimeout);
  s.set_key(key_prin);
  s.set_name(name);

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

  /*
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
             sizeof(pcr_digest)) != 0) {
    // aikquote.c here says "Try with a smaller digest length". I don't know
    // why. This code removes one of the bytes in the pcr mask and shifts
    // everything over to account for the difference, then hashes and tries
    // again.
    // kwalsh: Speculation, here... but not all TPMs are required to support or
    // use all possible mask lengths for every operation. If there are 32 PCRs
    // we will initially try with 4 bytes for the mask. But if only a subset of
    // the first 24 PCRs are active in the mask, the TPM might use a 3 byte mask
    // instead, since the last byte will be zero anyway.
    *(UINT16 *)pcr_buf = htons(pcr_mask_len_ - 1);
    memmove(pcr_buf + sizeof(UINT16) + pcr_mask_len_ - 1,
            pcr_buf + sizeof(UINT16) + pcr_mask_len_,
            index - (sizeof(UINT16) + pcr_mask_len_));
    index -= 1;
    SHA1(pcr_buf, index, pcr_digest);
    if (memcmp(pcr_digest, quote_info->compositeHash.digest,
               sizeof(pcr_digest)) != 0) {
      LOG(ERROR) << "Neither size of hash input worked for Quote computation";
      return 1;
    }
  }

  // At this point, the quote is in pcr_buf with length index.
  string quote(reinterpret_cast<char *>(pcr_buf), index);
  */
  string signature(reinterpret_cast<char *>(valid.rgbValidationData),
                   valid.ulValidationDataLength);

  string aik_name;
  if (!GetLocalName(&aik_name)) {
    LOG(ERROR) << "Could not get aik name";
    return false;
  }

  Attestation a;
  a.set_serialized_statement(serialized_statement);
  a.set_signer(aik_name);
  a.set_signature(signature);
  a.set_serialized_delegation(aik_attestation_);

  if (!a.SerializeToString(attestation)) {
    LOG(ERROR) << "Could not serialize the TPM 1.2 attestation";
    return false;
  }

  return true;
}

bool TPMTaoChildChannel::GetLocalName(string *aik_name) const {
  ScopedBio mem(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_RSA_PUBKEY(mem.get(), aik_rsa_.get())) {
    LOG(ERROR) << "Could not serialize public signing key";
    return false;
  }

  // The key should take up less than 8k in size.
  size_t len = BIO_ctrl_pending(mem.get());
  scoped_array<char> key_bytes(new char[len]);
  int result = BIO_read(mem.get(), key_bytes.get(), len);
  if (result <= 0 || size_t(result) != len) {
    LOG(ERROR) << "Could not read serialize public signing key";
    return false;
  }
  string key_info;
  string key_data(key_bytes.get(), len);

  // string hash;
  // if (!CryptoFactory::SHA256()->Digest(key_data, *hash)) {
  //   LOG(ERROR) << "Can't compute hash of public signing key";
  //   return false;
  // }
  // Base64WEncode(hash, &key_info);

  Base64WEncode(key_data, &key_info);

  stringstream out;
  out << "TPM(" << quotedString(key_info) << ")";
  aik_name->assign(out.str());
  return true;
}

bool TPMTaoChildChannel::GetHostedProgramFullName(string *full_name) const {
  // encode the host key and PCRs into a name

  string aik_name;
  if (!GetLocalName(&aik_name)) {
    LOG(ERROR) << "Could not get aik name";
    return false;
  }

  stringstream out;
  out << aik_name;

  // now get the pcrs
  out << "::PCRs(\"17, 18\",\"";
  list<UINT32> pcrs_to_quote{17, 18};
  bool first = true;
  for (UINT32 pcr_val : pcrs_to_quote) {
    BYTE *temp_pcr;
    UINT32 temp_pcr_len;
    TSS_RESULT result;
    result = Tspi_PcrComposite_GetPcrValue(seal_pcrs_, pcr_val, &temp_pcr_len,
                                           &temp_pcr);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not get PCR " << (int)pcr_val;

    string pcr((char *)temp_pcr, temp_pcr_len);
    string pcr_info;
    Base64WEncode(pcr, &pcr_info);
    if (!first) out << ", ";
    out << pcr_info;

    Tspi_Context_FreeMemory(tss_ctx_, temp_pcr);
  }
  out << "\")";

  full_name->assign(out.str());
  return true;
}

bool TPMTaoChildChannel::ExtendName(const string &subprin) const {
  LOG(ERROR) << "Not yet implemented -- extend the pcrs";
  // extend pcr 20 (or 21 or 22)?
  return false;
}

}  // namespace tao
