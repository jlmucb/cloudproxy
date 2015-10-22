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

  int size_buf;
  int out_size;
  byte out_buf[MAX_SIZE_PARAMS];

  OpenSSL_add_all_algorithms();

  X509_REQ* req = nullptr;

  int size_seed = 32;
  byte seed[32];
  TPM2B_NAME objectName;
  TPM2B_ID_OBJECT credentialBlob;
  TPM2B_DIGEST secret;
  TPM2B_ENCRYPTED_SECRET encrypted_secret;

  int size_symKey;
  byte symKey[MAX_SIZE_PARAMS];
  int size_hmacKey;
  byte hmacKey[MAX_SIZE_PARAMS];
  string key;
  string label;
  string contextU;
  string contextV;
  HMAC_CTX hctx;
  int size_encIdentity;
  byte encIdentity[MAX_SIZE_PARAMS];
  byte outerHmac[64];

  int size_out = 0;
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
  RSA* signing_key = nullptr;
  RSA* protector_key = nullptr;

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
  // request.endorsement_cert_blob();

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
  // if (!request.cred().has_public_key()) {
  // }
  // request.hash_quote_alg();
  // request.quote_signature();

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

  // generate seed
  RAND_bytes(seed, size_seed);

  protector_key = RSA_new();
  // get modulus and exponent from request.x509_program_key_request
  size_in= 0;
  memcpy(in_buf, seed, size_seed);
  size_in+= size_seed;
  memcpy(&in_buf[size_in], (byte*)"IDENTITY", strlen("IDENTITY") + 1);
  size_in += strlen("IDENTITY") + 1;

  // Secret= E(protector_key, seed || "IDENTITY")
  size_out = RSA_public_encrypt(size_in, in_buf, encrypted_secret.buffer,
                                protector_key, RSA_PKCS1_OAEP_PADDING);
  // prependedSecret is encrypted_secret structure above
  ChangeEndian16((uint16_t*)&size_out, &encrypted_secret.size);
  response.set_Secret(encrypted_secret.buffer, encrypted_secret.size);

  // symKey= KDFa(hash, seed, "STORAGE", name, nullptr, 128);
  label = "STORAGE";
  key.assign(seed, size_seed);
  contextV.clear();
  if (!KDFa(TPM_ALG_SHA256, key, label, request.cred().name, contextV, 256, 32, symKey)) {
    printf("Can't KDFa symKey\n");
    ret_val = 1;
    goto done;
  }
  // encIdentity = AesCFBEncrypt(symKey, prependedSecret, encIdentity, &size_out)
  if (!AesCFBEncrypt(symKey, size_out + 2, (byte*)&encrypted_secret,
                             &size_encIdentity, encIdentity)) {
    printf("Can't AesCFBEncrypt\n");
    ret_val = 1;
    goto done;
  }
  // hmacKey= KDFa(hash, seed, "INTEGRITY", nullptr, nullptr, 8*hashsize);
  label = "INTEGRITY";
  if (!KDFa(TPM_ALG_SHA256, key, label, contextV, contextV, 256, 32, hmacKey)) {
    printf("Can't KDFa hmacKey\n");
    ret_val = 1;
    goto done;
  }
  
  // outerMac = HMAC(hmacKey, encIdentity || name);
  HMAC_CTX_init(&hctx);
  HMAC_Init_ex(&hctx, hmacKey, 32, EVP_sha256(), nullptr);
  HMAC_Update(&hctx, encIdentity, size_encIdentity);
  HMAC_Update(&hctx, request.cred().name().data(), request.cred().name().size());
  size_hmac = 32;
  HMAC_Final(&hctx, outerHmac, &size_hmac);
  HMAC_CTX_cleanup(&hctx);

  // CredentialBlob= outerMac || encIdentity
  size_out = 0;
  memcpy(out_buf, outerHmac, 32);
  size_out += 32;
  memcpy(&out_buf[size_out], encIdentity, size_encIdentity);
  size_out += size_encIdentity;
  response.set_CredentialBlob(out_buf, size_out);

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


