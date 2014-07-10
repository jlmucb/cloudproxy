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
#include "tao/tpm_tao.h"

#include <netinet/in.h>

#include <glog/logging.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "tao/attestation.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/util.h"

namespace tao {
static bool AIKToPrincipalName(TSS_HCONTEXT tss_ctx, TSS_HKEY aik,
                               string *name) {
  // Extract the modulus from the AIK
  TSS_RESULT result;
  UINT32 aik_mod_len;
  BYTE *aik_mod;
  result = Tspi_GetAttribData(aik, TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aik_mod_len,
                              &aik_mod);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not extract the RSA modulus";
    return false;
  }
  // Set up an OpenSSL RSA public key to use to verify the Quote
  ScopedRsa aik_rsa(RSA_new());
  aik_rsa->n = BN_bin2bn(aik_mod, aik_mod_len, nullptr);
  aik_rsa->e = BN_new();
  BN_set_word(aik_rsa->e, 0x10001);
  Tspi_Context_FreeMemory(tss_ctx, aik_mod);
  // Serialize the OpenSSL key
  ScopedBio mem(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_RSA_PUBKEY(mem.get(), aik_rsa.get())) {
    LOG(ERROR) << "Could not serialize public signing key";
    return false;
  }
  size_t len = BIO_ctrl_pending(mem.get());
  unique_ptr<char[]> key_bytes(new char[len]);
  int bio_len = BIO_read(mem.get(), key_bytes.get(), len);
  if (bio_len <= 0 || size_t(bio_len) != len) {
    LOG(ERROR) << "Could not read serialize public signing key";
    return false;
  }
  string key_data(key_bytes.get(), len);
  // Encode it with base64w.
  string key_info;
  Base64WEncode(key_data, &key_info);
  // Convert to principal name.
  stringstream out;
  out << "TPM(" << quotedString(key_info) << ")";
  name->assign(out.str());
  return true;
}

static bool PrincipalNameToAIKRsa(const string &name, ScopedRsa *rsa_key) {
  string key_text;
  stringstream in(name);
  skip(in, "TPM(");
  getQuotedString(in, &key_text);
  skip(in, ")");
  if (!in || (in.get() && !in.eof())) {
    LOG(ERROR) << "Bad format for TPM AIK principal name";
    return false;
  }
  string key_data;
  if (!Base64WDecode(key_text, &key_data)) {
    LOG(ERROR) << "Could not decode AIK key";
    return false;
  }
  char *key_data_ptr = const_cast<char *>(key_data.data());
  ScopedBio mem(BIO_new_mem_buf(key_data_ptr, key_data.size()));
  RSA *rsa = nullptr;
  if (!PEM_read_bio_RSA_PUBKEY(mem.get(), &rsa, nullptr /* password callback */,
                               nullptr /* callback arg */)) {
    LOG(ERROR) << "Could not deserialize AIK key";
    return false;
  }
  rsa_key->reset(rsa);
  return true;
}

// There is, apparently, some flexibility in the bitmask size used within
// the serialized PCR buffer, since one can always append some extra zero bytes
// to the end of the mask without changing the semantics. The extra_mask_len
// parameter specifies how many extra zero bytes to include in the mask.
// Logically, 0 should be the right answer, but who knows...
static bool serializePCRs(const list<int> &pcr_indexes,
                          const list<string> &pcr_values, int extra_mask_len,
                          string *serialized_pcrs) {
  size_t n = pcr_indexes.size();
  if (n > TPMTao::PcrMaxIndex || pcr_values.size() != n) {
    LOG(ERROR) << "Invalid PCR value list";
    return false;
  }

  // sanity check the pcr indexes
  for (auto &pcr_idx : pcr_indexes) {
    if (pcr_idx < 0 || pcr_idx > TPMTao::PcrMaxIndex) {
      LOG(ERROR) << "Invalid PCR index: " << pcr_idx;
      return false;
    }
  }

  int pcr_max = 24;  // always include at least 24 PCR indexes for TPM 1.2
  for (auto &pcr_idx : pcr_indexes)
    pcr_max = (pcr_max >= pcr_idx ? pcr_max : pcr_idx);

  UINT16 pcr_mask_len = (pcr_max + 7) / 8;
  pcr_mask_len += extra_mask_len;

  // TPM Serialized PCR format is:
  // UINT16: size of pcr index mask (in network byte order)
  // BYTES: pcr index mask
  // UINT32: size of serialized pcr values (in network byte order)
  // BYTES: serialized pcr values

  int buf_len = 0;
  buf_len += sizeof(UINT16);  // mask len
  buf_len += pcr_mask_len;
  buf_len += sizeof(UINT32);  // values len
  buf_len += n * TPMTao::PcrLen;

  unique_ptr<BYTE[]> scoped_pcr_buf(new BYTE[buf_len]);
  BYTE *pcr_buf = scoped_pcr_buf.get();

  // Set mask len.
  *(UINT16 *)pcr_buf = htons(pcr_mask_len);
  pcr_buf += sizeof(UINT16);

  // Set mask bits.
  memset(pcr_buf, 0, pcr_mask_len);
  for (auto &pcr_idx : pcr_indexes)
    pcr_buf[(pcr_idx / 8)] |= 1 << (pcr_idx % 8);
  pcr_buf += pcr_mask_len;

  // Set values len.
  *(UINT32 *)pcr_buf = htonl(n * TPMTao::PcrLen);
  pcr_buf += sizeof(UINT32);

  // Set values.
  for (auto &pcr_hex : pcr_values) {
    string pcr_data;
    if (!bytesFromHex(pcr_hex, &pcr_data) ||
        pcr_data.size() != TPMTao::PcrLen) {
      LOG(ERROR) << "Bad PCR encoded in TPM quote";
      return false;
    }
    memcpy(pcr_buf, pcr_data.data(), TPMTao::PcrLen);
    pcr_buf += TPMTao::PcrLen;
  }

  const char *pcr_bytes = reinterpret_cast<const char *>(scoped_pcr_buf.get());
  serialized_pcrs->assign(string(pcr_bytes, buf_len));
  return true;
}

bool TPMTao::Init() {
  TSS_RESULT result;
  TSS_UUID srk_uuid = {0x00000000,
                       0x0000,
                       0x0000,
                       0x00,
                       0x00,
                       {0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
  BYTE secret[20];

  // TODO(kwalsh) Use a better secret.
  // Use the well-known secret of 20 zeroes.
  memset(secret, 0, 20);

  // Set up the TSS context and the SRK + policy (with the right secret).
  result = Tspi_Context_Create(&tss_ctx_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not create a TSS context.";
    return false;
  }

  result = Tspi_Context_Connect(tss_ctx_, nullptr /* Default TPM */);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not connect to the default TPM";
    return false;
  }

  result = Tspi_Context_GetTpmObject(tss_ctx_, &tpm_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not get a handle to the TPM";
    return false;
  }

  result =
      Tspi_Context_LoadKeyByUUID(tss_ctx_, TSS_PS_TYPE_SYSTEM, srk_uuid, &srk_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not load the SRK handle";
    return false;
  }

  TSS_HPOLICY srk_policy;
  result = Tspi_GetPolicyObject(srk_, TSS_POLICY_USAGE, &srk_policy);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not get the SRK policy handle";
    return false;
  }

  result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1, 20, secret);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not set the well-known secret";
    return false;
  }

  // Get the max number of PCRs in the TPM.
  UINT32 tpm_property = TSS_TPMCAP_PROP_PCR;
  UINT32 npcrs_len;
  BYTE *npcrs;
  result =
      Tspi_TPM_GetCapability(tpm_, TSS_TPMCAP_PROPERTY, sizeof(tpm_property),
                             (BYTE *)&tpm_property, &npcrs_len, &npcrs);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not get the number of PCRs";
    return false;
  }
  UINT32 pcr_max = *(UINT32 *)npcrs;
  Tspi_Context_FreeMemory(tss_ctx_, npcrs);

  // Get the AIK and encode it as a principal name.
  if (!aik_blob_.empty()) {
    BYTE *blob = reinterpret_cast<BYTE *>(const_cast<char *>(aik_blob_.data()));
    result = Tspi_Context_LoadKeyByBlob(tss_ctx_, srk_, aik_blob_.size(), blob,
                                        &aik_);
    if (result != TSS_SUCCESS) {
      LOG(ERROR) << "Could not load the AIK";
      return false;
    }

    if (!AIKToPrincipalName(tss_ctx_, aik_, &aik_name_)) {
      LOG(ERROR) << "Could not get TPM principal name";
      return false;
    }
  } else {
    aik_ = 0;
    aik_name_ = "TPMTao()";
  }

  // Gather PCR info.
  // TODO(kwalsh) The second 0 here was TSS_PCRS_STRUCT_INFO... why?

  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_PCRS, 0,
                                     &tss_pcr_values_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not create a PCRs object";
    return false;
  }
  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_PCRS, 0,
                                     &tss_pcr_indexes_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not create a PCR values handle";
    return false;
  }

  for (auto &pcr_idx : pcr_indexes_) {
    if (pcr_idx < 0 || pcr_idx > PcrMaxIndex || (UINT32)pcr_idx > pcr_max) {
      LOG(ERROR) << "Invalid PCR index: " << pcr_idx;
      return false;
    }
    // Read value
    BYTE *pcr_value = nullptr;
    UINT32 pcr_value_len = 0;
    result = Tspi_TPM_PcrRead(tpm_, pcr_idx, &pcr_value_len, &pcr_value);
    if (result != TSS_SUCCESS) {
      LOG(ERROR) << "Could not read the value of PCR " << pcr_idx;
      return false;
    }

    // Store value (for use in seal operations).
    result = Tspi_PcrComposite_SetPcrValue(tss_pcr_values_, pcr_idx,
                                           pcr_value_len, pcr_value);
    if (result != TSS_SUCCESS) {
      LOG(ERROR) << "Could not set the PCR value" << pcr_idx << " for sealing";
      return false;
    }

    // Cache value (for building hosted program name).
    string pcr_bytes((char *)pcr_value, pcr_value_len);
    child_pcr_values_.push_back(bytesToHex(pcr_bytes));

    // Select index (for use in quote operation).
    result = Tspi_PcrComposite_SelectPcrIndex(tss_pcr_indexes_, pcr_idx);
    if (result != TSS_SUCCESS) {
      LOG(ERROR) << "Could not select PCR " << pcr_idx;
      return false;
    }

    Tspi_Context_FreeMemory(tss_ctx_, pcr_value);
  }

  return true;
}

bool TPMTao::Close() {
  // Clean-up code.
  if (!tss_ctx_) return true;
  bool ok = true;
  TSS_RESULT result;
  result = Tspi_Context_FreeMemory(tss_ctx_, nullptr);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not free the context";
    ok = false;
  }
  result = Tspi_Context_Close(tss_ctx_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not clean up the context";
    ok = false;
  }
  tss_ctx_ = 0;
  return ok;
}

bool TPMTao::GetTaoName(string *full_name) {
  stringstream out;
  out << aik_name_;
  out << "::PCRs(\"" << join(pcr_indexes_, ", ") << "\"";
  out << ", \"" << join(child_pcr_values_, ", ") << "\")";
  out << name_extension_;
  full_name->assign(out.str());
  return true;
}

bool TPMTao::ExtendTaoName(const string &subprin) {
  // We should extend the PCRs, e.g. PCR 20 (or 21 or 22). But the semantics are
  // complicated: we need to have a single TPMTao instance on the machine, and
  // that instance should do one of the following:
  // - Reset those PCRs on each execution. This can't be done within the
  // TaoHost, obviously, because that lets a subprincipal escalate back to a
  // parent principal by partially replaying the ExtendTaoName operations. So it
  // would have to be controlled externally.
  // - Don't reset the PCRs, but keep track of list of extensions across each
  // execution of this TaoHost. Upon boot, the TPM principal would be
  // AIK::PCRs(p). After extend "foo", the principal would be
  // AIK::PCRs(p)::Extend("foo") where we can take p and "foo" and calculate the
  // new PCR values p' to use in verifying quotes.
  // - Don't reset the PCRs, and don't track list of extensions across each
  // execution of the TaoHost. The principal name would always be AIK::PCRs(p)
  // with the current PCR values p. But when we extend from p to p', also give
  // out a
  // delegation so that p speaks for p', since that wouldn't be evident from the
  // names.
  // TODO(kwalsh) This needs to go to PCRs, not simply stored here.
  name_extension_ += "::" + subprin;
  return true;
}

static bool ParseHostedProgramFullName(const string &full_name,
                                       const string &aik_name,
                                       list<int> *pcr_indexes,
                                       list<string> *pcr_values) {
  stringstream in(full_name);
  skip(in, aik_name);
  skip(in, "::");
  skip(in, "PCRs(");
  string pcr_index_list, pcr_value_list;
  getQuotedString(in, &pcr_index_list);
  skip(in, ", ");
  getQuotedString(in, &pcr_value_list);
  skip(in, ")");
  if (!in || (in.get() && !in.eof())) {
    LOG(ERROR) << "Bad child name in TPM quote statement";
    return false;
  }
  if (!split(pcr_index_list, ", ", pcr_indexes)) {
    LOG(ERROR) << "Bad PCR index list in TPM quote statement";
    return false;
  }
  if (!split(pcr_value_list, ", ", pcr_values)) {
    LOG(ERROR) << "Bad PCR value list in TPM quote statement";
    return false;
  }
  return true;
}

bool TPMTao::VerifySignature(const string &signer, const string &stmt,
                             const string &sig) {
  ScopedRsa rsa_key;
  if (!PrincipalNameToAIKRsa(signer, &rsa_key)) {
    LOG(ERROR) << "Could not deserialize AIK";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(stmt)) {
    LOG(ERROR) << "Could not parse statement";
    return false;
  }
  // Extract PCR info from name in the statement
  list<int> pcr_indexes;
  list<string> pcr_values;
  if (!ParseHostedProgramFullName(s.issuer(), signer, &pcr_indexes,
                                  &pcr_values)) {
    LOG(ERROR) << "Could not parse statement issuer";
    return false;
  }

  // Hash the statement for the external data part of the quote.
  uint8 stmt_hash[20];
  SHA1(reinterpret_cast<const uint8 *>(stmt.data()), stmt.size(), stmt_hash);

  // Try with defaul mask size, then try one byte larger.
  for (int padding = 0; padding < 2; padding++) {
    // Reconstruct pcrbuf
    string serialized_pcrs;
    if (!serializePCRs(pcr_indexes, pcr_values, padding, &serialized_pcrs)) {
      LOG(ERROR) << "Could not reconstruct PCR serialization";
      return false;
    }

    // Hash the pcrbuf for the internal data part of the quote.
    uint8 pcr_hash[20];
    SHA1(reinterpret_cast<const unsigned char *>(serialized_pcrs.data()),
         serialized_pcrs.size(), pcr_hash);

    // TPM Quote Info format is:
    // BYTES[8]: header
    // BYTES[20]: hash of serialized PCRs
    // BYTES[20]: hash of statement

    uint8 qinfo[8 + 20 + 20];
    memcpy(qinfo, "\x1\x1\0\0QUOT", 8);  // 1 1 0 0 Q U O T
    memcpy(qinfo + 8, pcr_hash, 20);
    memcpy(qinfo + 8 + 20, stmt_hash, 20);

    uint8 quote_hash[20];
    SHA1(qinfo, sizeof(qinfo), quote_hash);

    const uint8 *sig_bytes = reinterpret_cast<const uint8 *>(sig.data());
    if (1 == RSA_verify(NID_sha1, quote_hash, 20, sig_bytes, sig.size(),
                        rsa_key.get())) {
      return true;
    }
    LOG(INFO) << "RSA signature failed with padding size " << padding;
  }
  LOG(ERROR) << "RSA signature did not pass verification";
  return false;
}

bool TPMTao::GetRandomBytes(size_t size, string *bytes) {
  TSS_RESULT result;
  BYTE *random;
  result = Tspi_TPM_GetRandom(tpm_, size, &random);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not get random bytes from the TPM";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  bytes->assign(reinterpret_cast<char *>(random), size);
  Tspi_Context_FreeMemory(tss_ctx_, random);
  return true;
}

bool TPMTao::GetSharedSecret(size_t size, const string &policy, string *bytes) {
  failure_msg_ = "TPMTao shared secrets not yet implemented";
  LOG(ERROR) << failure_msg_;
  return false;
}

bool TPMTao::Seal(const string &data, const string &policy, string *sealed) {
  if (policy != Tao::SealPolicyDefault) {
    failure_msg_ = "TPM-specific policies not yet implemented";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  TSS_RESULT result;
  TSS_HENCDATA enc_data;
  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_ENCDATA,
                                     TSS_ENCDATA_SEAL, &enc_data);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not create the data for sealing";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  BYTE *bytes = reinterpret_cast<BYTE *>(const_cast<char *>(data.data()));
  result = Tspi_Data_Seal(enc_data, srk_, data.size(), bytes, tss_pcr_values_);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not seal the test data";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  // Extract the sealed data.
  BYTE *sealed_data;
  UINT32 sealed_data_len;
  result = Tspi_GetAttribData(enc_data, TSS_TSPATTRIB_ENCDATA_BLOB,
                              TSS_TSPATTRIB_ENCDATABLOB_BLOB, &sealed_data_len,
                              &sealed_data);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not get the sealed bits";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  sealed->assign(reinterpret_cast<char *>(sealed_data), sealed_data_len);

  // Clean up the enc data and the extracted data.
  Tspi_Context_FreeMemory(tss_ctx_, sealed_data);
  Tspi_Context_CloseObject(tss_ctx_, enc_data);
  return true;
}

bool TPMTao::Unseal(const string &sealed, string *data, string *policy) {
  TSS_RESULT result;
  TSS_HENCDATA enc_data;
  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_ENCDATA,
                                     TSS_ENCDATA_SEAL, &enc_data);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not create the data for sealing";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  BYTE *bytes = reinterpret_cast<BYTE *>(const_cast<char *>(sealed.data()));
  result =
      Tspi_SetAttribData(enc_data, TSS_TSPATTRIB_ENCDATA_BLOB,
                         TSS_TSPATTRIB_ENCDATABLOB_BLOB, sealed.size(), bytes);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not set the sealed data for unsealing";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  BYTE *unsealed_data;
  UINT32 unsealed_data_len;
  result = Tspi_Data_Unseal(enc_data, srk_, &unsealed_data_len, &unsealed_data);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not unseal the data";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  data->assign(reinterpret_cast<char *>(unsealed_data), unsealed_data_len);
  policy->assign(Tao::SealPolicyDefault);

  Tspi_Context_FreeMemory(tss_ctx_, unsealed_data);
  Tspi_Context_CloseObject(tss_ctx_, enc_data);
  return true;
}

bool TPMTao::Attest(const Statement &stmt, string *attestation) {
  if (!aik_) {
    failure_msg_ = "TPMTao was configured without a signing key";
    LOG(ERROR) << failure_msg_;
    return false;
  }
  // Set up a (copy) of statement and fill in defaults.
  Statement s;
  s.MergeFrom(stmt);
  if (!s.has_time()) s.set_time(CurrentTime());
  if (!s.has_expiration())
    s.set_expiration(s.time() + Tao::DefaultAttestationTimeout);
  if (!s.has_issuer()) {
    string issuer;
    if (!GetTaoName(&issuer)) {
      failure_msg_ = "Could not get issuer name";
      LOG(ERROR) << failure_msg_;
      return false;
    }
    s.set_issuer(issuer);
  }
  string serialized_statement;
  if (!s.SerializeToString(&serialized_statement)) {
    failure_msg_ = "Could not serialize the statement to a string";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  // Hash the data with SHA1
  BYTE statement_hash[20];
  SHA1(reinterpret_cast<const BYTE *>(serialized_statement.data()),
       serialized_statement.size(), statement_hash);

  TSS_VALIDATION valid;
  valid.ulExternalDataLength = sizeof(statement_hash);
  valid.rgbExternalData = statement_hash;

  TSS_RESULT result;
  result = Tspi_TPM_Quote(tpm_, aik_, tss_pcr_indexes_, &valid);
  if (result != TSS_SUCCESS) {
    failure_msg_ = "Could not quote data with the AIK";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  string signature(reinterpret_cast<char *>(valid.rgbValidationData),
                   valid.ulValidationDataLength);

  Attestation a;
  a.set_serialized_statement(serialized_statement);
  a.set_signer(aik_name_);
  a.set_signature(signature);

  if (!a.SerializeToString(attestation)) {
    failure_msg_ = "Could not serialize the TPM 1.2 attestation";
    LOG(ERROR) << failure_msg_;
    return false;
  }

  return true;
}

bool TPMTao::CreateAIK(string *aik_blob) {
  TSS_HKEY aik;
  TSS_RESULT result;
  if (aik_ != 0) {
    LOG(ERROR) << "AIK already installed";
    return false;
  }
  // Create the AIK.
  result =
      Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_RSAKEY,
                                TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048 |
                                    TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE,
                                &aik);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not create an AIK";
    return false;
  }

  // Create a bogus key to serve as a Privacy Certificate Authority Key (PCAKey)
  TSS_HKEY pca_key;
  result = Tspi_Context_CreateObject(tss_ctx_, TSS_OBJECT_TYPE_RSAKEY,
                                     TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048,
                                     &pca_key);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not create a fake PCAKey";
    return false;
  }
  result = Tspi_SetAttribUint32(pca_key, TSS_TSPATTRIB_KEY_INFO,
                                TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                TSS_ES_RSAESPKCSV15);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not set the encryption scheme to PKCS v1.5";
    return false;
  }
  // Use all 1s for the bogus pca_key.
  BYTE pca_modulus_bytes[2048 / 8];
  memset(pca_modulus_bytes, 0xff, sizeof(pca_modulus_bytes));
  result = Tspi_SetAttribData(pca_key, TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
                              sizeof(pca_modulus_bytes), pca_modulus_bytes);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not add a fake modulus to the PCAKey";
    return false;
  }
  // Create an identity request for the bogus PCA and get the AIK blob.
  BYTE *id_req = nullptr;
  UINT32 id_req_len = 0;
  result = Tspi_TPM_CollateIdentityRequest(tpm_, srk_, pca_key, 0, nullptr, aik,
                                           TSS_ALG_AES, &id_req_len, &id_req);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not set up a fake identity request for the AIK";
    return false;
  }
  Tspi_Context_CloseObject(tss_ctx_, pca_key);

  result = Tspi_Key_LoadKey(aik, srk_);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not load the AIK";
    return false;
  }

  BYTE *blob = nullptr;
  UINT32 blob_len = 0;
  result = Tspi_GetAttribData(aik, TSS_TSPATTRIB_KEY_BLOB,
                              TSS_TSPATTRIB_KEYBLOB_BLOB, &blob_len, &blob);
  if (result != TSS_SUCCESS) {
    LOG(ERROR) << "Could not get the blob data";
    return false;
  }

  const char *blob_bytes = reinterpret_cast<const char *>(blob);
  aik_blob->assign(blob_bytes, blob_len);
  Tspi_Context_FreeMemory(tss_ctx_, blob);

  string aik_name;
  if (!AIKToPrincipalName(tss_ctx_, aik, &aik_name)) {
    LOG(ERROR) << "Could not get TPM principal name";
    return false;
  }

  aik_ = aik;
  aik_name_ = aik_name;
  aik_blob_ = *aik_blob;

  // TODO(kwalsh) This method leaks Tspi objects if there are errors.

  return true;
}

bool TPMTao::SerializeToString(string *params) const {
  stringstream out;
  string aik_encoded;
  Base64WEncode(aik_blob_, &aik_encoded);
  out << "tao::TPMTao(";
  out << quotedString("base64w:" + aik_encoded);
  out << ", ";
  out << quotedString(join(pcr_indexes_, ", "));
  out << ")";
  params->assign(out.str());
  return true;
}

bool TPMTao::SerializeToStringWithFile(const string &path,
                                       string *params) const {
  stringstream out;
  out << "tao::TPMTao(";
  out << quotedString("file:" + path);
  out << ", ";
  out << quotedString(join(pcr_indexes_, ", "));
  out << ")";
  params->assign(out.str());
  return true;
}

bool TPMTao::SerializeToStringWithDirectory(const string &path,
                                            string *params) const {
  stringstream out;
  out << "tao::TPMTao(";
  out << quotedString("dir:" + path);
  out << ")";
  params->assign(out.str());
  return true;
}

TPMTao *TPMTao::DeserializeFromString(const string &params) {
  string aik_blob, pcr_index_list;
  stringstream in(params);
  skip(in, "tao::TPMTao(");
  if (!in) return nullptr;  // not for us
  string s;
  getQuotedString(in, &s);
  if (!in) {
    LOG(ERROR) << "Could not parse TPMTao parameters";
    return nullptr;
  }
  if (s.substr(0, 4) == "dir:") {
    string path = s.substr(4);
    if (!ReadFileToString(path + "/aikblob", &aik_blob)) {
      LOG(ERROR) << "Could not read aik blob for TPMTao";
      return nullptr;
    }
    if (!ReadFileToString(path + "/pcrlist", &pcr_index_list)) {
      LOG(ERROR) << "Could not read pcr index list for TPMTao";
      return nullptr;
    }
  } else {
    if (s.substr(0, 5) == "file:") {
      string path = s.substr(5);
      if (!ReadFileToString(path, &aik_blob)) {
        LOG(ERROR) << "Could not decode aik blob for TPMTao";
        return nullptr;
      }
    } else if (s.substr(0, 8) == "base64w:") {
      string aik_encoded = s.substr(8);
      if (!Base64WDecode(aik_encoded, &aik_blob)) {
        LOG(ERROR) << "Could not decode aik blob for TPMTao";
        return nullptr;
      }
    } else {
      LOG(ERROR) << "Bad encoding of aik blob for TPMTao";
      return nullptr;
    }
    skip(in, ", ");
    getQuotedString(in, &pcr_index_list);
  }
  skip(in, ")");
  if (!in || (in.get() && !in.eof())) {
    LOG(ERROR) << "Could not deserialize TPMTao";
    return nullptr;
  }
  list<int> pcr_indexes;
  if (!split(pcr_index_list, ",", &pcr_indexes)) {
    LOG(ERROR) << "Bad PCR index list in serialized TPMTao";
    return nullptr;
  }
  unique_ptr<TPMTao> tao(new TPMTao(aik_blob, pcr_indexes));
  if (!tao->Init()) {
    LOG(ERROR) << "Could not initialize TPMTao";
    return nullptr;
  }
  return tao.release();
}

}  // namespace tao
