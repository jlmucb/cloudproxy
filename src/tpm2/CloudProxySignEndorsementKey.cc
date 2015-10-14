#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl_helpers.h>

#include <tpm20.h>
#include <tpm2_lib.h>
#include <tpm2.pb.h>
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
// File: CloudProxySignEndorsementKey.cc


// Calling sequence
//   CloudProxySignEndorsementKey.exe --cloudproxy_private_key_file=file-name [IN]
//       --endorsement_info_file=file-name [IN]
//       --signing_instructions_file=file-name [IN]
//       --signed_endorsement_cert=file-name [OUT]

using std::string;

//  This program reads the endorsement_info_file and produces a certificate
//  for the endorsement key using the cloudproxy_signing_key in accordance with
//  the signing instructions.  signing instructions contains a subset of:
//  duration, purpose, and other information to be included in the 
//  signed certificate.


#define MAX_BUF_SIZE 8192

#define CALLING_SEQUENCE "Calling secquence: CloudProxySignEndorsementKey.exe" \
"--cloudproxy_private_key_file=input-file-name" \
"--endorsement_info_file=file-name  --signing_instructions_file=input-file-name" \
"--signed_endorsement_cert=output-file-name\n"

void PrintOptions() {
  printf(CALLING_SEQUENCE);
}

DEFINE_string(endorsement_info_file, "", "output file");
DEFINE_string(cloudproxy_private_key_file, "", "private key file");
DEFINE_string(signing_instructions_file, "", "signing instructions file");
DEFINE_string(signed_endorsement_cert, "", "signed endorsement cert file");

#ifndef GFLAGS_NS
#define GFLAGS_NS gflags
#endif

int main(int an, char** av) {
  int ret_val = 0;
  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);

  if (FLAGS_signing_instructions_file == "") {
    printf("signing_instructions_file is empty\n");
    return 1;
  }
  if (FLAGS_endorsement_info_file == "") {
    printf("endorsement_info_file is empty\n");
    return 1;
  }
  if (FLAGS_cloudproxy_private_key_file == "") {
    printf("cloudproxy_private_key_file is empty\n");
    return 1;
  }
  if (FLAGS_signed_endorsement_cert == "") {
    printf("signed_endorsement_cert is empty\n");
    return 1;
  }

  int in_size = MAX_BUF_SIZE;
  byte in_buf[MAX_BUF_SIZE];

  string input;
  signing_instructions_message signing_message;
  if (!ReadFileIntoBlock(FLAGS_signing_instructions_file, &in_size, 
                         in_buf)) {
    printf("Can't read signing instructions %s\n",
           FLAGS_signing_instructions_file.c_str());
    return 1;
  }
  input.assign((const char*)in_buf, in_size);
  if (!signing_message.ParseFromString(input)) {
    printf("Can't parse signing instructions\n");
    return 1;
  }
  printf("issuer: %s, duration: %lld, purpose: %s, hash: %s\n",
         signing_message.issuer().c_str(), signing_message.duration(),
         signing_message.purpose().c_str(), signing_message.hash_alg().c_str());
  
  if (!signing_message.can_sign()) {
    printf("Signing is invalid\n");
    return 1;
  }

  in_size = MAX_BUF_SIZE;
  endorsement_key_message endorsement_info;
  if (!ReadFileIntoBlock(FLAGS_endorsement_info_file, &in_size, 
                         in_buf)) {
    printf("Can't read endorsement info\n");
    return 1;
  }
  input.assign((const char*)in_buf, in_size);
  if (!endorsement_info.ParseFromString(input)) {
    printf("Can't parse endorsement info\n");
    return 1;
  }

  in_size = MAX_BUF_SIZE;
  private_key_blob_message private_key;
  if (!ReadFileIntoBlock(FLAGS_cloudproxy_private_key_file, &in_size, 
                         in_buf)) {
    printf("Can't read private key\n");
    return 1;
  }
  input.assign((const char*)in_buf, in_size);
  if (!private_key.ParseFromString(input)) {
    printf("Can't parse private key\n");
    return 1;
  }

  printf("Key type: %s\n", private_key.key_type().c_str());
  printf("Key name: %s\n", private_key.key_name().c_str());
  string the_blob = private_key.blob();
  PrintBytes(the_blob.size(), (byte*)the_blob.data());
  const byte* p = (byte*)the_blob.data();
  RSA* key = d2i_RSAPrivateKey(nullptr, &p, the_blob.size());
  if (key == nullptr) {
    printf("Can't translate private key\n");
    return 1;
  }

  printf("\n\n");
  printf("\nModulus: \n");
  BN_print_fp(stdout, key->n);
  printf("\n\n");
  printf("\ne: \n");
  BN_print_fp(stdout, key->e);
  printf("\n\n");
  printf("\nd: \n");
  BN_print_fp(stdout, key->d);
  printf("\n\n");
  printf("\np: \n");
  BN_print_fp(stdout, key->p);
  printf("\n\n");
  printf("\nq: \n");
  BN_print_fp(stdout, key->q);
  printf("\n\n");
  printf("\ndmp1: \n");
  BN_print_fp(stdout, key->dmp1);
  printf("\n\n");
  printf("\ndmq1: \n");
  BN_print_fp(stdout, key->dmq1);
  printf("\n\n");
  printf("\niqmp: \n");
  BN_print_fp(stdout, key->iqmp);
  printf("\n\n");

  public_key_message msg_key;
  msg_key.set_key_type(private_key.key_type());
  msg_key.set_key_type(private_key.key_name());
  if (!FillPrivateKeyStructure(*key, &msg_key)) {
    printf("Can't fill public key structure\n");
    return 1;
  }

  signed_cert_message cert_message;
  /*
    signed_cert_message.algorithm
    signed_cert_message.key_size
    signed_cert_message.issuer
    signed_cert_message.body_type
    signed_cert_message.body
    signed_cert_message.hash_alg
    signed_cert_message.hash
   */

  // create x509 certificate template

  // sign it

  // fill the output buffer and save it
  string output;
  cert_message.SerializeToString(&output);
  if (!WriteFileFromBlock(FLAGS_signed_endorsement_cert,
                          output.size(),
                          (byte*)output.data())) {
  }
  return ret_val;
}

