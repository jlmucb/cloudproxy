//  File: tpm_seal.cc
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

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  TSS_HCONTEXT tss_ctx;
  TSS_HTPM tpm;
  TSS_RESULT result;
  TSS_HKEY srk = 0;
  TSS_HPOLICY srk_policy = 0;
  TSS_UUID srk_uuid = {0x00000000, 0x0000, 0x0000, 0x00, 0x00, {0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
  BYTE secret[20];

  // Use the well-known secret of 20 zeroes.
  memset(secret, 0, 20);

  // Set up the TSS context and the SRK + policy (with the right secret).
  result = Tspi_Context_Create(&tss_ctx);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a TSS context.";

  result = Tspi_Context_Connect(tss_ctx,
                                NULL /* Default TPM */);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not connect to the default TPM";

  result = Tspi_Context_GetTpmObject(tss_ctx, &tpm);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get a handle to the TPM";

  result = Tspi_Context_LoadKeyByUUID(tss_ctx,
                                      TSS_PS_TYPE_SYSTEM,
                                      srk_uuid,
                                      &srk);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the SRK handle";

  result = Tspi_GetPolicyObject(srk,
                                        TSS_POLICY_USAGE,
                                        &srk_policy);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the SRK policy handle";

  result = Tspi_Policy_SetSecret(srk_policy,
                                 TSS_SECRET_MODE_SHA1,
                                 20,
                                 secret);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not set the well-known secret";

  // Create and fill the PCR information.
  TSS_HPCRS pcrs;
  result = Tspi_Context_CreateObject(tss_ctx,
                                     TSS_OBJECT_TYPE_PCRS,
                                     0,
                                     &pcrs);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a PCRs object";

  // This seal operation is meant to be used with DRTM, so the only PCRs that it
  // reads are 17 and 18. This is where you can set other PCRs to use.
  list<UINT32> pcrs_to_seal{17, 18};
  BYTE *pcr_value = NULL;
  UINT32 pcr_value_len = 0;
  for(UINT32 ui : pcrs_to_seal) {
    result = Tspi_TPM_PcrRead(tpm, ui, &pcr_value_len, &pcr_value);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not read the value of PCR " << ui;

    result = Tspi_PcrComposite_SetPcrValue(pcrs, ui, pcr_value_len, pcr_value);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not set the PCR value"
                                  << ui << " for sealing";
  }

  TSS_HENCDATA enc_data;
  result = Tspi_Context_CreateObject(tss_ctx,
                                     TSS_OBJECT_TYPE_ENCDATA,
                                     TSS_ENCDATA_SEAL,
                                     &enc_data);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create the data for sealing";

  BYTE data[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  result = Tspi_Data_Seal(enc_data, srk, 16, data, pcrs);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not seal the test data";

  // Extract the sealed data, then try to unseal it.
  BYTE *sealed_data;
  UINT32 sealed_data_len;
  result = Tspi_GetAttribData(enc_data,
                              TSS_TSPATTRIB_ENCDATA_BLOB,
                              TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                              &sealed_data_len,
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
  ifstream blob_stream("aikblob", ifstream::in);
  stringstream blob_buf;
  blob_buf << blob_stream.rdbuf();
  string blob = blob_buf.str();
  UINT32 blob_len = (UINT32)blob.size();
  TSS_HKEY aik;
  result = Tspi_Context_LoadKeyByBlob(tss_ctx, srk, blob_len,
reinterpret_cast<BYTE *>(const_cast<char
*>(blob.data())), &aik);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the AIK";

  // Clean-up code.
  result = Tspi_Context_FreeMemory(tss_ctx, NULL);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not free the context";

  result = Tspi_Context_Close(tss_ctx);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not clean up the context";

  return 0;
}
