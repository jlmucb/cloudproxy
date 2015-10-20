#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl_helpers.h>

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
// File: ServerSignProgramKeyRequest.cc


//   This program creates a primary key and signingkey.  Produces the signed_interim_cert_request_file
//   which contains a protobuf consisting of the endorsement key certificate, and
//   a request signed by the signing key with the public portion of the signing key, the
//   the policy for MakeCredential to activate the key and the date/time.

// Calling sequence: ServerSignProgramKeyRequest.exe
//    --program_cert_request_file=input-file-name
//    --program_cert_response_file=output-file-name


using std::string;


#define CALLING_SEQUENCE "ServerSignProgramKeyRequest.exe " \
"--cloud_proxy_key_file=input-file" \
"--program_cert_request_file=output-file-name " \
"--program_cert_response_file=output-file-name"

void PrintOptions() {
  printf("Calling sequence: %s", CALLING_SEQUENCE);
}


DEFINE_string(signed_endorsement_cert_file, "", "input-file-name");
DEFINE_string(program_cert_request_file, "", "input-file-name");
// TODO(jlm): policy file should contain list of approved pcrs
DEFINE_string(policy_file, "", "input-file-name");
DEFINE_string(cloudproxy_key_file, "", "input-file-name");
DEFINE_string(program_response_file, "", "output-file-name");

#ifndef GFLAGS_NS
#define GFLAGS_NS gflags
#endif

#define MAX_SIZE_PARAMS 8192

int main(int an, char** av) {
  int ret_val = 0;

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);

  int size_cert_request = MAX_SIZE_PARAMS;
  byte* cert_request_buf[MAX_SIZE_PARAMS];
  x509_cert_request_parameters_message cert_request;
  
  int in_size = MAX_BUF_SIZE;
  byte in_buf[MAX_BUF_SIZE];

  string input;

#if 0
  X509_REQ* req = X509_REQ_new();
  X509_REQ_set_version(req, 2);

  TPM2B_DIGEST credential;
  TPM2B_NAME objectName;
  TPM2B_ID_OBJECT credentialBlob;
  TPM2B_ENCRYPTED_SECRET secret ;

  X509* cert = X509_new();

  private_key_blob_message private_key;
  program_cert_request_message request;
  program_cert_response_message response;
  string output;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if (FLAGS_signing_instructions_file == "") {
    printf("signing_instructions_file is empty\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_program_cert_request_file == "") {
    printf("program_cert_request_file is empty\n");
  }
  if (FLAGS_cloudproxy_key_file == "") {
    printf("cloudproxy_key_file is empty\n");
  }
  if (FLAGS_signed_endorsement_cert == "") {
    printf("signed_endorsement_cert is empty\n");
  }

  // Get cloudproxy key
  if (!ReadFileIntoBlock(FLAGS_program_cert_request_file, &size_cert_request, cert_request_buf)) {
    printf("Can't read cert request\n");
    ret_val = 1;
    goto done;
  }
  input.assign((const char*)in_buf, in_size);
  if (!request.ParseFromString(input)) {
    printf("Can't parse cert request\n");
    ret_val = 1;
    goto done;
  }

  signing_instructions_message signing_message;
  if (!ReadFileIntoBlock(FLAGS_signing_instructions_file, &in_size, in_buf)) {
    printf("Can't read signing instructions %s\n",
           FLAGS_signing_instructions_file.c_str());
    ret_val = 1;
    goto done;
  }
  input.assign((const char*)in_buf, in_size);
  if (!signing_message.ParseFromString(input)) {
    printf("Can't parse signing instructions\n");
    ret_val = 1;
    goto done;
  }
  printf("issuer: %s, duration: %ld, purpose: %s, hash: %s\n",
         signing_message.issuer().c_str(), signing_message.duration(),
         signing_message.purpose().c_str(), signing_message.hash_alg().c_str());
  if (!signing_message.can_sign()) {
    printf("Signing is invalid\n");
    ret_val = 1;
    goto done;
  }

  in_size = MAX_BUF_SIZE;
  if (!ReadFileIntoBlock(FLAGS_cloudproxy_key_file, &in_size, in_buf)) {
    printf("Can't read private key\n");
    printf("    %s\n", FLAGS_cloudproxy_key_file.c_str());
  }
  input.assign((const char*)in_buf, in_size);
  if (!private_key.ParseFromString(input)) {
    printf("Can't parse private key\n");
  }
  printf("Key type: %s\n", private_key.key_type().c_str());
  printf("Key name: %s\n", private_key.key_name().c_str());
  string the_blob = private_key.blob();
  PrintBytes(the_blob.size(), (byte*)the_blob.data());
  const byte* p = (byte*)the_blob.data();
  RSA* signing_key = d2i_RSAPrivateKey(nullptr, &p, the_blob.size());
  if (signing_key == nullptr) {
    printf("Can't translate private key\n");
    ret_val = 1;
    goto done;
  }
  print_internal_private_key(*signing_key);

  ChangeEndian16((uint16_t*)key_blob.data(), (uint16_t*)&size_in);
  TPM2B_PUBLIC outPublic;
  if (!GetReadPublicOut(size_in, (byte*)(key_blob.data() + sizeof(uint16_t)),
                        outPublic)) {
    printf("Can't parse endorsement blob\n");
    ret_val = 1;
    goto done;
  }
  // Extract program key request

  // Extract quote key info

  // Validate request

  if (!GenerateX509CertificateRequest(cert_request, false, req)) {
    printf("Can't generate x509 request\n");
    ret_val = 1;
    goto done;
  }

  // sign it
  if (!SignX509Certificate(signing_key, signing_message, req, false, cert)) {
    printf("Can't sign x509 request\n");
    ret_val = 1;
    goto done;
  }
  printf("message signed\n");

  byte* out = nullptr;
  int size = i2d_X509(cert, &out);

  // Sign program key

  // Encrypt for ActivateCredential

  // bool MakeCredential(TPM2B_DIGEST& credential, TPM2B_NAME& objectName,
  //                     TPM2B_ID_OBJECT* credentialBlob, TPM2B_ENCRYPTED_SECRET* secret);

  // Write response file

  response.SerializeToString(&output);
  if (!WriteFileFromBlock(FLAGS_program_response_file,
                          output.size(),
                          (byte*)output.data())) {
    printf("Can't write endorsement cert\n");
    ret_val = 1;
    goto done;
  }
#endif

done:
  return ret_val;
}


