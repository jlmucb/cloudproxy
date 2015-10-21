#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl_helpers.h>
#include <openssl/rand.h>

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


//   This program verifies endorsement cert, quote key and signature. It then
//   constructs and signs an x509 cert for the proposed program key.  It encrypts
//   the signed cert to the Endorsement key referencing the Quote Key and creates
//   the decrypt information required by ActivateCredential.  It saves the encrypted
//   information in the response file.

// Calling sequence: ServerSignProgramKeyRequest.exe
//    --program_cert_request_file=input-file-name
//    --program_cert_response_file=output-file-name


using std::string;


#define CALLING_SEQUENCE "ServerSignProgramKeyRequest.exe " \
"--signing_instructions_file=input-file" \
"--cloudproxy_key_file=input-file" \
"--program_cert_request_file=output-file-name " \
"--program_response_file=output-file-name"

void PrintOptions() {
  printf("Calling sequence: %s", CALLING_SEQUENCE);
}


DEFINE_string(signed_endorsement_cert_file, "", "input-file-name");
DEFINE_string(signing_instructions_file, "", "input-file-name");
DEFINE_string(program_cert_request_file, "", "input-file-name");
// TODO(jlm): policy file should contain list of approved pcrs
DEFINE_string(policy_file, "", "input-file-name");
DEFINE_string(policy_identifier, "cloudproxy", "policy domain name");
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
  byte cert_request_buf[MAX_SIZE_PARAMS];
  x509_cert_request_parameters_message cert_request;
  
  int in_size = MAX_SIZE_PARAMS;
  byte in_buf[MAX_SIZE_PARAMS];

  OpenSSL_add_all_algorithms();

  X509_REQ* req = nullptr;

  TPM2B_DIGEST secret;
  TPM2B_NAME objectName;
  TPM2B_ID_OBJECT credentialBlob;
  TPM2B_ENCRYPTED_SECRET encrypted_secret;

  byte* out = nullptr;
  byte* der_cert_request_in = nullptr;
  int der_cert_request_size = 0;
  byte* der_cert_in = nullptr;
  int size = 0;
  X509* cert = X509_new();
  byte quoted_hash[256];
  uint16_t secret_size = 0;
  byte encrypted_data[MAX_SIZE_PARAMS];

  private_key_blob_message private_key;
  program_cert_request_message request;
  program_cert_response_message response;
  signing_instructions_message signing_message;
  x509_cert_request_parameters_message cert_parameters;

  string input;
  string output;
  string the_blob;

  uint16_t size_in = 0;
  SHA256_CTX sha256;
#if 0
  string* mod = nullptr;
  uint64_t expIn;
  uint64_t expOut;
#endif
  byte* p = nullptr;
  RSA* signing_key = nullptr;

  if (FLAGS_signing_instructions_file == "") {
    printf("signing_instructions_file is empty\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_program_cert_request_file == "") {
    printf("program_cert_request_file is empty\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_cloudproxy_key_file == "") {
    printf("cloudproxy_key_file is empty\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_program_response_file == "") {
    printf("program_response_file is empty\n");
    ret_val = 1;
    goto done;
  }

  // Get request
  if (!ReadFileIntoBlock(FLAGS_program_cert_request_file, &size_cert_request,
                         cert_request_buf)) {
    printf("Can't read cert request\n");
    ret_val = 1;
    goto done;
  }
  input.assign((const char*)cert_request_buf, size_cert_request);
  if (!request.ParseFromString(input)) {
    printf("Can't parse cert request\n");
    ret_val = 1;
    goto done;
  }

  // Get signing instructions
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

  // Get cloudproxy key
  in_size = MAX_SIZE_PARAMS;
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

  the_blob = private_key.blob();
  PrintBytes(the_blob.size(), (byte*)the_blob.data()); printf("\n");
  p = (byte*)the_blob.data();
  signing_key = d2i_RSAPrivateKey(nullptr, (const byte**)&p, the_blob.size());
  if (signing_key == nullptr) {
    printf("Can't translate private key\n");
    ret_val = 1;
    goto done;
  }
  print_internal_private_key(*signing_key);

  // Extract program key request
  if (!request.has_cred()) {
    printf("No information to construct cred\n");
    ret_val = 1;
    goto done;
  }

  // Validate request: self-signed, endorsement, quote sig

  // Check self-signed

  // Check endorsement cert

  // Get certificate request for program key
  der_cert_request_in = (byte*)request.x509_program_key_request().data();
  der_cert_request_size = request.x509_program_key_request().size();
  out = der_cert_request_in;
  req = d2i_X509_REQ(nullptr, (const byte**)&out, der_cert_request_size);
  // sign program key
  if (!SignX509Certificate(signing_key, signing_message, req, false, cert)) {
    printf("Can't sign x509 request\n");
    ret_val = 1;
    goto done;
  }
  printf("message signed\n");

  // Serialize program cert
  der_cert_in = nullptr;
  size = i2d_X509(cert, &der_cert_in);
  printf("Program cert: ");
  PrintBytes(size, der_cert_in); printf("\n");

  // Hash request
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, (byte*)request.x509_program_key_request().data(),
                request.x509_program_key_request().size());
  SHA256_Final(quoted_hash, &sha256);
  printf("quoted_hash: "); PrintBytes(32, quoted_hash); printf("\n");

  // Encrypt with quote key

  // Compare signature and computed hash

  // Generate encryption key for cert
  secret_size = 16;
  RAND_bytes(secret.buffer, secret_size);
  ChangeEndian16(&secret_size, &secret.size);

  // Encrypt cert
  if (!AesCtrCrypt(128, secret.buffer, size,
                   der_cert_in, encrypted_data)) {
    printf("Can't encrypt cert\n");
    ret_val = 1;
    goto done;
  }
  response.set_encrypted_cert(encrypted_data, size);
goto done;

  // Encrypt credential for ActivateCredential
#if 0
  request.endorsement_cert_blob();
  request.x509_program_key_request();
  request.hash_quote_alg();
  request.quote_signature();
  if (!request.cred().has_public_key()) {
  }
  request.cred().name
  request.cred().properties
  request.cred().hash_alg
  request.cred().hash
  request.cred().secret
  request.cred().qualified_name
#endif

  // Define:
  // bool MakeCredential(TPM2B_DIGEST& credential, TPM2B_NAME& objectName,
  //                     TPM2B_ID_OBJECT* credentialBlob, TPM2B_ENCRYPTED_SECRET* secret);

  // Fill, serialize and write program_cert_response_message
  response.set_enc_alg("aes");
  response.set_enc_mode("ctr");
  // response.mutable_info();

  response.SerializeToString(&output);
  if (!WriteFileFromBlock(FLAGS_program_response_file,
                          output.size(),
                          (byte*)output.data())) {
    printf("Can't write endorsement cert\n");
    ret_val = 1;
    goto done;
  }

done:
  return ret_val;
}


