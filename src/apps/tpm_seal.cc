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

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  TSS_HCONTEXT tss_ctx;
  TSS_HTPM tpm;
  TSS_RESULT result;
  TSS_HKEY srk;
  TSS_HPOLICY srk_policy;
  TSS_UUID srk_uuid = TSS_UUID_SRK;
  BYTE secret[20];

  // Use the well-known secret of 20 zeroes.
  memset(secret, 0, 20);

  result = Tspi_Context_Create(&tss_ctx);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not create a TSS context";

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

  result = Tspi_GetPolicyObject(tss_ctx,
                                        TSS_POLICY_USAGE,
                                        &srk_policy);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not get the SRK policy handle";

  result = Tspi_Policy_SetSecret(srk_policy,
                                 TSS_SECRET_MODE_SHA1,
                                 20,
                                 secret);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not set the well-known secret";

  result = Tspi_Context_Close(tss_ctx);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not clean up the context";

  result = Tspi_Context_FreeMemory(tss_ctx, NULL);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not free the context";

  return 0;
}
