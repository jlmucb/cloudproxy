//
// Copyright 2016, Google Corporation , All Rights Reserved.
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
// File: genkeys.cc

#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>

#include "ssl_helpers.h"

DEFINE_string(key_type, "ECC", "key type for generated keys");

int main(int an, char** av) {
  string path("/Domains/test_keys");
  string ca_cert_string;
  string client_cert_string;
  string server_cert_string;
  string ca_key_string;
  string client_key_string;
  string server_key_string;

#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif

  string key_type;
  int key_size;
  if(FLAGS_key_type == "ECC") {
    key_type = "ECC";
    key_size = 256;
  } else if (FLAGS_key_type == "RSA") {
    key_type = "RSA";
    key_size = 2048;
  } else {
    printf("Invalid key type\n");
    return 1;
  }
  printf("Key type is %s\n", key_type.c_str()); 

  string ca_common_name("test_ca");
  string client_common_name("test_client");
  string server_common_name("test_server");
  string issuer("test_ca");
  string keyUsage("critical,keyAgreement,keyCertSign");
  string extendedKeyUsage("serverAuth,clientAuth");

  // CA cert
  X509_REQ* ca_req = X509_REQ_new();
  X509* ca_cert = X509_new();
  EVP_PKEY* ca_key= GenerateKey(key_type, key_size);
  if (!GenerateX509CertificateRequest(key_type, ca_common_name, ca_key, false, ca_req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }
  if (!SignX509Certificate(ca_key, true, true, issuer, keyUsage,
                           extendedKeyUsage, 365*86400,
                           ca_key, ca_req, false, ca_cert)) {
    printf("Can't sign x509 ca request\n");
    return 1;
  }

  // Save cert and key.
  byte ca_out[4096];
  byte* ca_ptr = ca_out;
  int ca_der_size = i2d_X509(ca_cert, &ca_ptr);
  if (ca_der_size <= 0) {
    printf("Can't der encode ca cert\n");
    return 1;
  }
  ca_cert_string.assign((const char*) ca_out, ca_der_size);
  if (!SerializePrivateKey(key_type, ca_key, &ca_key_string)) {
    printf("Can't serialize ca key\n");
    return 1;
  }
  string ca_cert_file_name = path + "/ca_cert";
  if (!WriteFile(ca_cert_file_name, ca_cert_string)) {
    printf("Can't write ca cert\n");
    return 1;
  }
  string ca_key_file_name = path + "/ca_key";
  if (!WriteFile(ca_key_file_name, ca_key_string)) {
    printf("Can't write ca key\n");
    return 1;
  }

  // server cert
  X509_REQ* server_req = X509_REQ_new();
  X509* server_cert = X509_new();
  EVP_PKEY* server_key= GenerateKey(key_type, key_size);
  if (!GenerateX509CertificateRequest(key_type, server_common_name, server_key, false, server_req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }
  if (!SignX509Certificate(ca_key, true, true, issuer, keyUsage,
                           extendedKeyUsage, 365*86400, server_key,
                           server_req, false, server_cert)) {
    printf("Can't sign x509 ca request\n");
    return 1;
  }

  // Save cert and key.
  byte server_out[4096];
  byte* server_ptr = server_out;
  int server_der_size = i2d_X509(server_cert, &server_ptr);
  if (server_der_size <= 0) {
    printf("Can't der encode server cert\n");
    return 1;
  }
  server_cert_string.assign((const char*) server_out, server_der_size);
  if (!SerializePrivateKey(key_type, server_key, &server_key_string)) {
    printf("Can't serialize server key\n");
    return 1;
  }
  string server_cert_file_name = path + "/server_cert";
  if (!WriteFile(server_cert_file_name, server_cert_string)) {
    printf("Can't write server cert\n");
    return 1;
  }
  string server_key_file_name = path + "/server_key";
  if (!WriteFile(server_key_file_name, server_key_string)) {
    printf("Can't write server key\n");
    return 1;
  }

  // client cert
  X509_REQ* client_req = X509_REQ_new();
  X509* client_cert = X509_new();
  EVP_PKEY* client_key= GenerateKey(key_type, key_size);
  if (!GenerateX509CertificateRequest(key_type, client_common_name, client_key, false, client_req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }
  if (!SignX509Certificate(ca_key, true, true, issuer, keyUsage,
                           extendedKeyUsage, 365*86400,
                           client_key, client_req, false, client_cert)) {
    printf("Can't sign x509 ca request\n");
    return 1;
  }

  // Save cert and key.
  byte client_out[4096];
  byte* client_ptr = client_out;
  int client_der_size = i2d_X509(client_cert, &client_ptr);
  if (client_der_size <= 0) {
    printf("Can't der encode server cert\n");
    return 1;
  }
  client_cert_string.assign((const char*) client_out, client_der_size);
  if (!SerializePrivateKey(key_type, client_key, &client_key_string)) {
    printf("Can't serialize server key\n");
    return 1;
  }
  string client_cert_file_name = path + "/client_cert";
  if (!WriteFile(client_cert_file_name, client_cert_string)) {
    printf("Can't write server cert\n");
    return 1;
  }
  string client_key_file_name = path + "/client_key";
  if (!WriteFile(client_key_file_name, client_key_string)) {
    printf("Can't write server key\n");
    return 1;
  }

  return 0;
}

