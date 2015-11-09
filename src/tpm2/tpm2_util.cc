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
// File: tpm2_util.cc


// Calling sequence
// tpm2_util.exe --Commmand=command 

using std::string;

DEFINE_string(command, "", "command");
DEFINE_int32(numbytes, 16, "numbytes");
DEFINE_int32(num_param, 16, "integer parameter");
DEFINE_string(password, "password", "password");
DEFINE_string(authString, "", "authString");
DEFINE_string(parentAuth, "", "parent auth String");
DEFINE_string(handle, "", "handle");
DEFINE_int32(pcr_num, -1, "integer parameter");
DEFINE_int32(index, -1, "nv index");
DEFINE_int32(nv_slot, 1000, "nv slot");
DEFINE_int32(nv_size, -1, "nv size");
DEFINE_string(parent_public_file, "", "parent public area");
DEFINE_string(public_file, "", "public area");
DEFINE_string(private_file, "", "private public area");
DEFINE_string(creation_data_file, "", "private public area");
DEFINE_string(save_context_file, "", "save(d) context area");
DEFINE_string(decrypt, "", "decrypt flag");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

int num_tpmutil_ops = 27;
std::string tpmutil_ops[] = {
    "--command=Startup",
    "--command=Shutdown",
    "--command=GetCapabilities",
    "--command=Flushall",
    "--command=GetRandom",
    "--command=ReadClock",
    "--command=CreatePrimary",
    "--command=Load",
    "--command=Save",
    "--command=CreateKey",
    "--command=ReadPcr",
    "--command=Unseal",
    "--command=Quote",
    "--command=LoadContext",
    "--command=SaveContext",
    "--command=FlushContext",
    "--command=ReadNv",
    "--command=WriteNv",
    "--command=DefineSpace",
    "--command=UndefineSpace",
    "--command=SealCombinedTest",
    "--command=QuoteCombinedTest",
    "--command=DictionaryAttackLockReset",
    "--command=KeyCombinedTest",
    "--command=NvCombinedTest",
    "--command=ContextCombinedTest",
    "--command=EndorsementCombinedTest",
};

void PrintOptions() {
  printf("Permitted operations:\n");
  for (int i = 0; i < num_tpmutil_ops; i++) {
    printf("  tpmutil.exe %s\n", tpmutil_ops[i].c_str());
  }
  return;
}

int main(int an, char** av) {
  LocalTpm tpm;

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

  if (FLAGS_command == "GetCapabilities") {
    int size = 512;
    byte buf[512];
    if (!Tpm2_GetCapability(tpm, TPM_CAP_TPM_PROPERTIES, &size, buf)) {
      printf("Tpm2_GetCapability failed\n");
    }
    PrintCapabilities(size, buf);
  } else if (FLAGS_command == "Startup") {
    if (!Tpm2_Startup(tpm)) {
      printf("Tpm2_Startup failed\n");
    }
  } else if (FLAGS_command == "Shutdown") {
    if (!Tpm2_Shutdown(tpm)) {
      printf("Tpm2_Shutdown failed\n");
    }
  } else if (FLAGS_command == "GetRandom") {
    byte buf[256];

    if (FLAGS_numbytes >256) {
      printf("Can only get up to 256 bytes\n");
      goto done;
    }
    memset(buf, 0, 256);
    if (Tpm2_GetRandom(tpm, FLAGS_numbytes, buf)) {
      printf("Random bytes: ");
      PrintBytes(FLAGS_numbytes, buf);
      printf("\n");
    } else {
      printf("GetRandom failed\n");
    }
  } else if (FLAGS_command == "ReadClock") {
    uint64_t current_time, current_clock;
    if (Tpm2_ReadClock(tpm, &current_time, &current_clock)) {
      printf("time: %lx %lx\n\n", current_time, current_clock);
    } else {
      printf("ReadClock failed\n");
    }
  } else if (FLAGS_command == "CreatePrimary") {
#if 0
    TPM_HANDLE handle;
    TPM2B_PUBLIC pub_out;
    TPML_PCR_SELECTION pcrSelect;
    InitSinglePcrSelection(FLAGS_pcr_num, TPM_ALG_SHA1, pcrSelect);
    bool sign = true;
    if (FLAGS_decrypt.size() > 0)
      sign = false;
    if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, FLAGS_authString,
                           pcrSelect, sign,
                           &handle, &pub_out)) {
      printf("Tpm2_CreatePrimary succeeds\n");
      printf("Public handle: %08x\n", (uint32_t)handle);
      printf("type: %04x\n", pub_out.publicArea.type);
      printf("nameAlg: %04x\n", pub_out.publicArea.nameAlg);
      printf("Attributes: %08x\n", *(uint32_t*)
                &pub_out.publicArea.objectAttributes);
      printf("Algorithm: %08x\n",
        pub_out.publicArea.parameters.rsaDetail.symmetric.algorithm);
      printf("keySize: %04x\n", pub_out.publicArea.parameters.rsaDetail.keyBits);
      printf("Modulus: ");
      PrintBytes(pub_out.publicArea.unique.rsa.size,
                pub_out.publicArea.unique.rsa.buffer);
      printf("\n");
    } else {
      printf("CreatePrimary failed\n");
    }
#endif
  } else if (FLAGS_command == "Load") {
    TPM_HANDLE parent_handle = 0x80000000;
    TPM_HANDLE new_handle;
    TPM2B_NAME name;
    if (FLAGS_handle.size() >0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      parent_handle = (TPM_HANDLE) t;
    } 
    int size_public = 4096;
    byte inPublic[4096];
    int size_private = 4096;
    byte inPrivate[4096];
    bool ok = true;
    if (!ReadFileIntoBlock(FLAGS_public_file, &size_public, inPublic)) {
      printf("Can't read public block\n");
      ok = false;
    }
    if (!ReadFileIntoBlock(FLAGS_private_file, &size_private, inPrivate)) {
      printf("Can't read public block\n");
      ok = false;
    }
    if (ok && Tpm2_Load(tpm, parent_handle, FLAGS_parentAuth, size_public, inPublic,
                        size_private, inPrivate, &new_handle, &name)) {
      printf("Load succeeded, new handle: %08x\n", new_handle);
    } else {
      printf("Load failed\n");
    }
  } else if (FLAGS_command == "Save") {
    if (Tpm2_Save(tpm)) {
      printf("Save succeeded\n");
    } else {
      printf("Save failed\n");
    }
  } else if (FLAGS_command == "ReadPcr") {
    uint32_t updateCounter;
    TPML_PCR_SELECTION pcrSelectOut;
    TPML_DIGEST values;
    if (Tpm2_ReadPcr(tpm, FLAGS_pcr_num, &updateCounter,
                     &pcrSelectOut, &values)) {
      printf("ReadPcr succeeds, updateCounter: %08x\n", updateCounter);
      printf("Pcr %d :", FLAGS_pcr_num);
      PrintBytes(values.digests[0].size, values.digests[0].buffer);
      printf("\n");
    } else {
      printf("ReadPcr failed\n");
    }
  } else if (FLAGS_command == "CreateKey") {
#if 0
    TPM_HANDLE parent_handle;

    TPM2B_CREATION_DATA creation_out;
    TPM2B_DIGEST digest_out;
    TPMT_TK_CREATION creation_ticket;
    int size_public = 4096;
    byte out_public[4096];
    int size_private = 4096;
    byte out_private[4096];

    parent_handle = 0x80000000;
    if (FLAGS_handle.size() > 0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      parent_handle = (TPM_HANDLE) t;
    } 
    TPML_PCR_SELECTION pcrSelect;
    InitSinglePcrSelection(FLAGS_pcr_num, TPM_ALG_SHA1, pcrSelect);
    bool sign = true;
    if (FLAGS_decrypt.size() > 0)
      sign = false;
    if (Tpm2_CreateKey(tpm, parent_handle, FLAGS_parentAuth,
                    FLAGS_authString, pcrSelect,
                    sign, false, &size_public, out_public,
                    &size_private, out_private,
                    &creation_out, &digest_out, &creation_ticket)) {
      printf("CreateKey succeeded\n");
      printf("Public (%d): ", size_public);
      PrintBytes(size_public, out_public);
      printf("\n");
      printf("Private (%d): ", size_private);
      PrintBytes(size_private, out_private);
      printf("\n");
      if (!WriteFileFromBlock(FLAGS_public_file, 
                              size_public, out_public)) {
        printf("Can't write %s, CreateKey failed\n", FLAGS_private_file.c_str());
      } else if (!WriteFileFromBlock(FLAGS_private_file,
                                     size_private, out_private)){ 
        printf("Can't write %s\n", FLAGS_private_file.c_str());
      } else {
        printf("CreateKey succeeded\n");
      }
    }
    printf("CreateKey failed\n");
#endif
  } else if (FLAGS_command == "Unseal") {
#if 0
    TPM_HANDLE item_handle = 0;
    int out_size = 1024;
    byte out[1024];
    int size_digest = 0;
    byte digest[64];
    if (Tpm2_Unseal(tpm, item_handle, FLAGS_parentAuth,
                    pcrSelector, TPM_ALG_SHA1, size_digest, digest,
                    &out_size, out)) {
      printf("Unseal succeeded: ");
      PrintBytes(out_size, out);
      printf("\n");
    } else {
      printf("Unseal failed\n");
    }
#endif
  } else if (FLAGS_command == "Quote") {
#if 0
    int quote_size = 1024;
    byte quote[1024];
    TPM_HANDLE signingHandle = 0;
    TPMT_SIG_SCHEME scheme;
    TPML_PCR_SELECTION pcr_selection;
    int attest_size = 1024;
    byte attest[1024];
    int sig_size = 1024;
    byte sig[1024];
    if (Tpm2_Quote(tpm, signingHandle, quote_size, quote, scheme, pcr_selection,
               &attest_size, attest, &sig_size, sig)) {
      printf("Quote succeeded\n");
    } else {
      printf("Quote failed\n");
    }
#endif
  } else if (FLAGS_command == "UndefineSpace") {
    TPM_HANDLE nv_handle = GetNvHandle(FLAGS_nv_slot);
    
    if (FLAGS_nv_slot < 0) {
      printf("Invalid index\n");
    } else if (!Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
      printf("UndefineSpace succeeded\n");
    } else {
      printf("UndefineSpace failed\n");
    }
  } else if (FLAGS_command == "DefineSpace") {
    TPM_HANDLE nv_handle = GetNvHandle(FLAGS_nv_slot);
    uint16_t size_data = (uint16_t) FLAGS_nv_size;
    if (Tpm2_DefineSpace(tpm, TPM_RH_OWNER, nv_handle,
                         FLAGS_authString, size_data)) {
      printf("DefineSpace succeeded\n");
    } else {
      printf("DefineSpace failed\n");
    }
  } else if (FLAGS_command == "LoadContext") {
    int size = 4096;
    byte saveArea[4096];
    memset(saveArea, 0, 4096);
    TPM_HANDLE handle = 0;

    if (!ReadFileIntoBlock(FLAGS_save_context_file, &size, saveArea)) {
        printf("Can't read %s, LoadContext failed\n", FLAGS_save_context_file.c_str());
    } else if (Tpm2_LoadContext(tpm, size, saveArea, &handle)) {
      printf("LoadContext succeeded\n");
    } else {
      printf("LoadContext failed\n");
    }
  } else if (FLAGS_command == "SaveContext") {
    int size = 4096;
    byte saveArea[4096];
    memset(saveArea, 0, 4096);

    TPM_HANDLE handle = 0x80000000;
    if (FLAGS_handle.size() > 0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      handle = (TPM_HANDLE) t;
    } else if (Tpm2_SaveContext(tpm, handle, &size, saveArea)) {
      if (!WriteFileFromBlock(FLAGS_save_context_file, size, saveArea)) {
        printf("Can't write %s, SaveContext failed\n", FLAGS_save_context_file.c_str());
      } else { 
        printf("SaveContext successful\n");
      }
    } else {
      printf("SaveContext failed\n");
    }
  } else if (FLAGS_command == "FlushContext") {
    TPM_HANDLE handle = 0x80000000;
    if (FLAGS_handle.size() >0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      handle = (TPM_HANDLE) t;
    } 
    if (Tpm2_FlushContext(tpm, handle)) {
      printf("FlushContext succeeded\n");
    } else {
      printf("FlushContext failed\n");
    }
  } else if (FLAGS_command == "Tpm2_Read_Nv") {
    TPMI_RH_NV_INDEX index = (TPMI_RH_NV_INDEX) FLAGS_index;
    int size_data = 0;
    byte data[1024];
    if (Tpm2_ReadNv(tpm, index, FLAGS_authString, size_data, data)) {
      printf("Tpm2_Read_Nv succeeded\n");
      PrintBytes(size_data, data);
      printf("\n");
    } else {
      printf("Tpm2_Read_Nv failed\n");
    }
  } else if (FLAGS_command == "Tpm2_Write_Nv") {
    TPMI_RH_NV_INDEX index = (TPMI_RH_NV_INDEX) FLAGS_index;
    int size_data = 0;
    byte data[1024];
    if (Tpm2_WriteNv(tpm, index, FLAGS_authString, size_data, data)) {
      printf("Tpm2_Write_Nv succeeded\n");
    } else {
      printf("Tpm2_Write_Nv failed\n");
    }
  } else if (FLAGS_command == "Flushall") {
    if (Tpm2_Flushall(tpm)) {
      printf("Flushall succeeded\n");
    } else {
      printf("Flushall failed\n");
    }
  } else if (FLAGS_command == "KeyCombinedTest") {
    if (Tpm2_KeyCombinedTest(tpm, FLAGS_pcr_num)) {
      printf("Tpm2_KeyCombinedTest succeeded\n");
    } else {
      printf("Tpm2_KeyCombinedTest failed\n");
    }
  } else if (FLAGS_command == "SealCombinedTest") {
    if (Tpm2_SealCombinedTest(tpm, FLAGS_pcr_num)) {
      printf("SealCombinedTest succeeded\n");
    } else {
      printf("SealCombinedTest failed\n");
    }
  } else if (FLAGS_command == "QuoteCombinedTest") {
    if (Tpm2_QuoteCombinedTest(tpm, FLAGS_pcr_num)) {
      printf("QuoteCombinedTest succeeded\n");
    } else {
      printf("QuoteCombinedTest failed\n");
    }
  } else if (FLAGS_command == "NvCombinedTest") {
    if (Tpm2_NvCombinedTest(tpm)) {
      printf("NvCombinedTest succeeded\n");
    } else {
      printf("NvCombinedTest failed\n");
    }
  } else if (FLAGS_command == "ContextCombinedTest") {
    if (Tpm2_ContextCombinedTest(tpm)) {
      printf("ContextCombinedTest succeeded\n");
    } else {
      printf("ContextCombinedTest failed\n");
    }
  } else if (FLAGS_command == "EndorsementCombinedTest") {
    if (Tpm2_EndorsementCombinedTest(tpm)) {
      printf("EndorsementCombinedTest succeeded\n");
    } else {
      printf("EndorsementCombinedTest failed\n");
    }
  } else if (FLAGS_command == "DictionaryAttackLockReset") {
    if (Tpm2_DictionaryAttackLockReset(tpm)) {
      printf("Tpm2_DictionaryAttackLockReset succeeded\n");
    } else {
      printf("Tpm2_DictionaryAttackLockReset failed\n");
    }
  } else {
    printf("Invalid command\n");
    PrintOptions();
  }
done:
  tpm.CloseTpm();
}

