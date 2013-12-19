//  File: make_aik.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Creates an AIK the TPM, assuming the caller controls the TPM
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <list>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

using std::ifstream;
using std::ofstream;
using std::list;
using std::string;
using std::stringstream;

DEFINE_string(aik_blob_file, "aikblob", "A file to receive the AIK blob");

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
  // TODO(tmroeder): allow this to use a real secret
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

  // Create the AIK and a fake PCAKey
  TSS_HKEY aik;
  result =
      Tspi_Context_CreateObject(tss_ctx, TSS_OBJECT_TYPE_RSAKEY,
                                TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048 |
                                    TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE,
                                &aik);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create an AIK";

  TSS_HKEY pca_key;
  result = Tspi_Context_CreateObject(tss_ctx, TSS_OBJECT_TYPE_RSAKEY,
                                     TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048,
                                     &pca_key);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a fake PCAKey";

  result = Tspi_SetAttribUint32(pca_key, TSS_TSPATTRIB_KEY_INFO,
                                TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                TSS_ES_RSAESPKCSV15);
  CHECK_EQ(result, TSS_SUCCESS)
      << "Could not set the encryption scheme to PKCS v1.5";

  // The fake key has a modulus that is all 1s
  BYTE pca_modulus_bytes[2048 / 8];
  memset(pca_modulus_bytes, 0xff, sizeof(pca_modulus_bytes));
  result = Tspi_SetAttribData(pca_key, TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
                              sizeof(pca_modulus_bytes), pca_modulus_bytes);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not add a fake modulus to the PCAKey";

  BYTE *id_req = NULL;
  UINT32 id_req_len = 0;
  result = Tspi_TPM_CollateIdentityRequest(tpm, srk, pca_key, 0, NULL, aik,
                                           TSS_ALG_AES, &id_req_len, &id_req);
  CHECK_EQ(result, TSS_SUCCESS)
      << "Could not set up a fake identity request for the AIK";

  result = Tspi_Key_LoadKey(aik, srk);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the AIK";

  BYTE *blob = NULL;
  UINT32 blob_len = 0;
  result = Tspi_GetAttribData(aik, TSS_TSPATTRIB_KEY_BLOB,
                              TSS_TSPATTRIB_KEYBLOB_BLOB, &blob_len, &blob);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the blob data";

  ofstream aik_blob_file(FLAGS_aik_blob_file.c_str());
  if (!aik_blob_file) {
    LOG(ERROR) << "Could not open the AIK blob file for writing";
    return 1;
  }

  aik_blob_file.write(reinterpret_cast<char *>(blob), blob_len);
  aik_blob_file.close();
  return 0;
}
