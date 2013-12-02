//  File: get_pcrs.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Gets a Base64W-encoded representation of the current PCRs 17
//  and 18
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

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <list>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/base64w.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

using std::list;
using std::string;

#define PCR_LEN 20

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
  list<UINT32> pcrs_to_read{17, 18};
  BYTE *pcr_value = NULL;
  UINT32 pcr_value_len = 0;
  scoped_array<char> vals(new char[pcrs_to_read.size() * PCR_LEN]);
  size_t index = 0;
  for (UINT32 ui : pcrs_to_read) {
    result = Tspi_TPM_PcrRead(tpm, ui, &pcr_value_len, &pcr_value);
    CHECK_EQ(result, TSS_SUCCESS) << "Could not read the value of PCR " << ui;

    memcpy(vals.get() + index, pcr_value, pcr_value_len);
    index += pcr_value_len;
  }

  string pcr_str(vals.get(), index);
  string serialized;
  if (!keyczar::base::Base64WEncode(pcr_str, &serialized)) {
    LOG(ERROR) << "Could not base64-encode the pcrs";
    return 1;
  }

  printf("%s", serialized.c_str());
  return 0;
}
