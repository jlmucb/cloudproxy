//  File: convert_aik_to_openssl.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Produces an OpenSSL public key file for the AIK given the AIK
//  blob from the TPM
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
#include <fstream>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/file_util.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <tss/platform.h>
#include <tss/tspi.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/tss_structs.h>
#include <tss/tss_typedef.h>

#include <trousers/trousers.h>

#include "tao/attestation.pb.h"
#include "tao/tao.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::ifstream;
using std::ofstream;
using std::string;
using std::stringstream;

using tao::Statement;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "cppolicy", "A password for the policy private key");
DEFINE_string(
    aik_blob_file, "aikblob",
    "A file containing an AIK blob that has been loaded into the TPM");
DEFINE_string(
    aik_attest_file, "aik.attest",
    "A serialized attestation to the AIK, signed by the policy private key");

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

  result = Tspi_Context_Connect(tss_ctx, nullptr /* Default TPM */);
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

  // Get the public key blob from the AIK.
  // Load the blob and try to load the AIK
  ifstream blob_stream(FLAGS_aik_blob_file, ifstream::in);
  if (!blob_stream) {
    LOG(ERROR) << "Could not load the blob file " << FLAGS_aik_blob_file;
    return 1;
  }

  stringstream blob_buf;
  blob_buf << blob_stream.rdbuf();
  string blob = blob_buf.str();
  UINT32 blob_len = (UINT32)blob.size();
  TSS_HKEY aik;
  result = Tspi_Context_LoadKeyByBlob(
      tss_ctx, srk, blob_len,
      reinterpret_cast<BYTE *>(const_cast<char *>(blob.data())), &aik);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not load the AIK";

  // Extract the modulus from the AIK
  UINT32 aik_mod_len;
  BYTE *aik_mod;
  result = Tspi_GetAttribData(aik, TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aik_mod_len,
                              &aik_mod);
  CHECK_EQ(result, TSS_SUCCESS) << "Could not extract the RSA modulus";

  // Set up an OpenSSL RSA public key to use to verify the Quote
  RSA *aik_rsa = RSA_new();
  aik_rsa->n = BN_bin2bn(aik_mod, aik_mod_len, nullptr);
  aik_rsa->e = BN_new();
  BN_set_word(aik_rsa->e, 0x10001);

  // Write to a memory-based BIO for signing
  BIO *mem = BIO_new(BIO_s_mem());

  if (!PEM_write_bio_RSAPublicKey(mem, aik_rsa)) {
    LOG(ERROR) << "Could not write the AIK to a PEM file";
    return 1;
  }

  BUF_MEM *buf;
  BIO_get_mem_ptr(mem, &buf);

  string pem(buf->data, buf->length);
  BIO_free(mem);

  Statement s;
  s.set_data(pem);

  // load policy key
  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";
  CHECK(admin->Unlock(FLAGS_policy_pass)) << "Could not unlock configuration";

  // sign this serialized data with policy key
  string attestation;
  if (admin->AttestByRoot(&s, &attestation)) return 1;

  // save to file
  ofstream attest_file(FLAGS_aik_attest_file, ofstream::out);
  if (!attest_file) {
    LOG(ERROR) << "Could not open the attest file " << FLAGS_aik_attest_file
               << " for writing";
    return 1;
  }

  CHECK(attest_file << attestation)
      << "Could not serialize the attestation to a file";
  return 0;
}
