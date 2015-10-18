#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <tpm20.h>
#include <tpm2_lib.h>
#include <gflags/gflags.h>

//
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
// Portions of this code were derived tboot published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived from the crypto utility
// published by John Manferdelli under the Apache 2.0 license.
// See github.com/jlmucb/crypto.
// File: CreateAndSaveCloudProxyKeyHierarchy.cc


// This program creates a primary key, signing key (for quotes) and sealing key under the owner hierarchy
// and saves them to the cloudproxy defined namespace in nv ram so they can be reloaded.  NV ram
//  is protected with PCR's of current "authenticated boot" so they can only be reread by
//  the same cloudproxy environment.  It optionally seals an input string and quotes a quote string.
//  This program removes existing cloudproxy slots with same names and slot numbers.


// Calling sequence
//   CreateAndSaveCloudProxyKeyHierarchy.exe --cloudproxy_namespace="name"
//      --cloudproxy_slot_primary=int32 --cloudproxy_slot_seal=int32 --slot_quote=int32
//      --seal_value=value-string --quote_value=value-string --pcr_hash_alg_name=[sha1 | sha256]
//      --pcr_list="int, int, ..." --seal_output_file=output-file-name
//      --quote_output_file= output-file-name --pcr_file=output-file-name

using std::string;


#define CALLING_SEQUENCE "CreateAndSaveCloudProxyKeyHierarchy.exe " \
"--cloudproxy_namespace=name " \
"--cloudproxy_slot_primary=int32 --cloudproxy_slot_seal=int32 " \
"--slot_quote=int32 " \
"--seal_value=value-string --quote_value=value-string " \
"--pcr_hash_alg_name=[sha1 | sha256] " \
"--pcr_list='int, int, ...' --seal_output_file=output-file-name " \
"--quote_output_file= output-file-name --pcr_file=output-file-name\n"

void PrintOptions() {
  printf("Calling sequence: %s", CALLING_SEQUENCE);
}

DEFINE_string(cloudproxy_namespace, "", "");
DEFINE_int32(cloudproxy_slot_primary, 0, "");
DEFINE_int32(cloudproxy_slot_seal, 1, "");
DEFINE_int32(slot_quote, 2, "");
DEFINE_string(seal_value, "", "test seal value");
DEFINE_string(quote_value, "", "test quote value");
DEFINE_string(pcr_hash_alg_name, "", "hash alg (sha1 or sha256");
DEFINE_string(pcr_list, "", "comma separated pcr list");
DEFINE_string(seal_output_file, "", "output-file-name");
DEFINE_string(quote_output_file, "", "output-file-name");
DEFINE_string(pcr_file, "", "output-file-name");

#ifndef GFLAGS_NS
#define GFLAGS_NS gflags
#endif

#define MAX_SIZE_PARAMS 8192

int main(int an, char** av) {
  LocalTpm tpm;
  int ret_val = 0;

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

  // Create the Heirarchy 
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;
  
  TPML_PCR_SELECTION pcrSelect;
  TPMA_OBJECT root_flags;

  TPM2B_CREATION_DATA creation_out;
  TPM2B_DIGEST digest_out;
  TPMT_TK_CREATION creation_ticket;

  TPM_HANDLE root_handle; 
  TPM2B_PUBLIC root_pub_out;
  int root_size_public = MAX_SIZE_PARAMS;
  byte root_out_public[MAX_SIZE_PARAMS];
  int root_size_private = MAX_SIZE_PARAMS;
  byte root_out_private[MAX_SIZE_PARAMS];

  TPM2B_PUBLIC seal_pub_out;
  TPM_HANDLE seal_load_handle;
  TPMA_OBJECT seal_create_flags;
  TPM2B_NAME seal_name;
  int seal_size_public = MAX_SIZE_PARAMS;
  byte seal_out_public[MAX_SIZE_PARAMS];
  int seal_size_private = MAX_SIZE_PARAMS;
  byte seal_out_private[MAX_SIZE_PARAMS];

  TPM_HANDLE sealed_load_handle;
  TPM2B_NAME sealed_name;
  int sealed_size_public = MAX_SIZE_PARAMS;
  byte sealed_out_public[MAX_SIZE_PARAMS];
  int sealed_size_private = MAX_SIZE_PARAMS;
  byte sealed_out_private[MAX_SIZE_PARAMS];

  TPMA_OBJECT quote_create_flags;
  TPM_HANDLE quote_load_handle;
  TPM2B_NAME quote_name;
  int quote_size_public = MAX_SIZE_PARAMS;
  byte quote_out_public[MAX_SIZE_PARAMS];
  int quote_size_private = MAX_SIZE_PARAMS;
  byte quote_out_private[MAX_SIZE_PARAMS];

  TPM2B_DIGEST policy_digest;
  TPM2B_DIGEST secret;

  uint16_t size_context_save_area =  MAX_SIZE_PARAMS;
  byte context_save_area[MAX_SIZE_PARAMS];
  int context_data_size = 1024;

  // read pcrlist and make selection
  // InitSinglePcrSelection(pcr_num, TPM_ALG_SHA1, pcrSelect);
  // FLAGS_pcr_list
 
  // root of hierarchy 
  *(uint32_t*)(&root_flags) = 0;
  root_flags.fixedTPM = 1;
  root_flags.fixedParent = 1;
  root_flags.sensitiveDataOrigin = 1;
  root_flags.userWithAuth = 1;
  root_flags.decrypt = 1;
  root_flags.restricted = 1;
  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA1, root_flags,
                         TPM_ALG_AES, 128, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001, &root_handle, &root_pub_out)) {
    printf("CreatePrimary succeeded\n");
  } else {
    ret_val = 1;
    goto done;
  }

  *(uint32_t*)(&seal_create_flags) = 0;
  seal_create_flags.fixedTPM = 1;
  seal_create_flags.fixedParent = 1;
  seal_create_flags.sensitiveDataOrigin = 1;
  seal_create_flags.userWithAuth = 1;
  seal_create_flags.sign = 1;

  if (Tpm2_CreateKey(tpm, root_handle, parentAuth, authString, pcrSelect,
                     TPM_ALG_RSA, TPM_ALG_SHA1, seal_create_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     2048, 0x010001, &seal_size_public, seal_out_public,
                     &seal_size_private, seal_out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("Create succeeded private size: %d, public size: %d\n",
           root_size_private, root_size_public);
  } else {
    printf("Create failed\n");
    ret_val = 1;
    goto done;
  }

  if (Tpm2_Load(tpm, root_handle, parentAuth, seal_size_public, seal_out_public,
               seal_size_private, seal_out_private, &seal_load_handle, &seal_name)) {
    printf("Load succeeded, handle: %08x\n", seal_load_handle);
  } else {
    Tpm2_FlushContext(tpm, root_handle);
    ret_val = 1;
    goto done;
  }

  if (Tpm2_CreateSealed(tpm, root_handle, policy_digest.size, policy_digest.buffer,
                        parentAuth, secret.size, secret.buffer, pcrSelect,
                        TPM_ALG_SHA1, seal_create_flags, TPM_ALG_NULL,
                        (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                        1024, 0x010001,
                        &sealed_size_public, sealed_out_public,
                        &sealed_size_private, sealed_out_private,
                        &creation_out, &digest_out, &creation_ticket)) {
    printf("Create with digest succeeded private size: %d, public size: %d\n",
           sealed_size_private, sealed_size_public);
  } else {
    Tpm2_FlushContext(tpm, root_handle);
    ret_val = 1;
    goto done;
  }

  if (Tpm2_Load(tpm, root_handle, parentAuth, sealed_size_public, sealed_out_public,
               sealed_size_private, sealed_out_private, &sealed_load_handle, &sealed_name)) {
    printf("Load succeeded\n");
  } else {
    printf("Load failed\n");
    Tpm2_FlushContext(tpm, root_handle);
    ret_val = 1;
    goto done;
  }

  *(uint32_t*)(&quote_create_flags) = 0;
  quote_create_flags.fixedTPM = 1;
  quote_create_flags.fixedParent = 1;
  quote_create_flags.sensitiveDataOrigin = 1;
  quote_create_flags.userWithAuth = 1;
  quote_create_flags.sign = 1;
  quote_create_flags.restricted = 1;

  if (Tpm2_CreateKey(tpm, root_handle, parentAuth, authString, pcrSelect,
                     TPM_ALG_RSA, TPM_ALG_SHA1, quote_create_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     1024, 0x010001,
                     &sealed_size_public, sealed_out_public,
                     &sealed_size_private, sealed_out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("Create succeeded, private size: %d, public size: %d\n",
           sealed_size_private, sealed_size_public);
  } else {
    printf("Create failed\n");
    ret_val = 1;
    goto done;
  }

  if (Tpm2_Load(tpm, root_handle, parentAuth, quote_size_public, quote_out_public,
               quote_size_private, quote_out_private, &quote_load_handle, &quote_name)) {
    printf("Load succeeded\n");
  } else {
    printf("Load failed\n");
    ret_val = 1;
    goto done;
  }

#if 0
  // Save to TPM slots
  // FLAGS_cloudproxy_slot_seal

  TPMI_RH_NV_INDEX index = FLAGS_cloudproxy_slot_primary;
  if (!Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, index)) {
    printf("UndefinedSpace failed\n");
    ret_val = 1;
    goto done;
  }

  if (!Tpm2_DefineSpace(tpm, TPM_RH_OWNER, index,
                      authString, context_data_size)) {
    printf("DefinedSpace failed\n");
    ret_val = 1;
    goto done;
  }
  if (!Tpm2_SaveContext(tpm, TPM_RH_OWNER, &size_context_save_area,
                        context_save_area)) {
    printf("SaveContext failed\n");
    ret_val = 1;
    goto done;
  }
  if (!Tpm2_ReadNv(tpm, index, authString, &size_context_save_area,
                        context_save_area)) {
    printf("ReadNv failed\n");
    ret_val = 1;
    goto done;
  }
  if (!Tpm2_WriteNv(tpm, index, authString, 
                    &size_context_save_area, context_save_area)){
    printf("WriteNv failed\n");
    ret_val = 1;
    goto done;
  }
#endif

  // FLAGS_pcr_hash_alg_name

  // FLAGS_slot_quote
  // FLAGS_pcr_file

  // seal and quote as test
  // FLAGS_seal_value
  // FLAGS_quote_value
  // FLAGS_seal_output_file
  // FLAGS_quote_output_file

done:
  tpm.CloseTpm();
  return ret_val;
}

