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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "tao/attestation.pb.h"
#include "tao/util.h"

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

using keyczar::Keyczar;

using std::ifstream;
using std::ofstream;
using std::list;
using std::string;
using std::stringstream;

using tao::Attestation;
using tao::Statement;

DEFINE_string(
    aik_blob_file, "aikblob",
    "A file containing an AIK blob that has been loaded into the TPM");
DEFINE_string(aik_attest_file, "aik.attest", "A serialized attestation to the AIK, signed by the policy private key");
DEFINE_string(policy_key, "policy_key", "The path to the policy private key");
DEFINE_string(policy_pass, "cppolicy", "A password for the policy private key");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  const int AttestationTimeout = 31556926;
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

  // Get the public key blob from the AIK.
  // Load the blob and try to load the AIK
  ifstream blob_stream(FLAGS_aik_blob_file, ifstream::in);
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
  aik_rsa->n = BN_bin2bn(aik_mod, aik_mod_len, NULL);
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

  // decrypt the private policy key so we can construct a signer
  keyczar::base::ScopedSafeString password(new string(FLAGS_policy_pass));
  scoped_ptr<keyczar::rw::KeysetReader> reader(
      new keyczar::rw::KeysetPBEJSONFileReader(FLAGS_policy_key.c_str(),
                                               *password));

  // sign this serialized data with the keyset in FLAGS_policy_key
  scoped_ptr<keyczar::Keyczar> signer(keyczar::Signer::Read(*reader));
  CHECK(signer.get()) << "Could not initialize the signer from "
                      << FLAGS_policy_key;
  signer->set_encoding(keyczar::Keyczar::NO_ENCODING);

  Attestation a;
  Statement s;
  time_t cur_time;
  time(&cur_time);

  s.set_time(cur_time);
  s.set_expiration(cur_time + AttestationTimeout);
  s.set_data(pem);
  s.set_hash_alg("None");
  s.set_hash("");

  string serialized_statement;
  CHECK(s.SerializeToString(&serialized_statement)) << "Could not serialize";
  string sig;
  CHECK(signer->Sign(serialized_statement, &sig))
    << "Could not sign the key";

  // There's no cert, since this is signed by the root key
  a.set_type(tao::ROOT);
  a.set_serialized_statement(serialized_statement);
  a.set_signature(sig);

  ofstream attest_file(FLAGS_aik_attest_file, ofstream::out);
  CHECK(a.SerializeToOstream(&attest_file))
    << "Could not serialize the attestation to a file";
  return 0;
}
