//
// Copyright 2014 John Manferdelli, All Rights Reserved.
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
// Project: New Cloudproxy Crypto
// File: gen_keys_test.cc

#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>

#include "helpers.h"

bool test_gen() {
  string path("/Domains/test_keys");
  string ca_cert_string;
  string client_cert_string;
  string server_cert_string;
  string ca_key_string;
  string client_key_string;
  string server_key_string;
  string ca_key_type;
  string server_key_type;
  string client_key_type;

  // CA
  string ca_cert_file_name = path + "/ca_cert";
  string ca_key_file_name = path + "/ca_key";
  if(!ReadFile(ca_cert_file_name, &ca_cert_string)) {
    printf("can't read ca_cert.\n");
    return false;
  }
  if(!ReadFile(ca_key_file_name, &ca_key_string)) {
    printf("can't read ca key.\n");
    return false;
  }
  byte* ca_ptr = (byte*)ca_cert_string.data();
  X509* ca_cert = d2i_X509(nullptr, (const byte**)&ca_ptr,
        ca_cert_string.size());
  if (ca_cert == nullptr) {
    printf("ca_cert doesnt translate.\n");
    return false;
  }

  EVP_PKEY* ca_key = nullptr;

  if (!DeserializePrivateKey(ca_key_string, &ca_key_type, &ca_key)) {
    printf("Can't deserialize ca key\n");
    return false;
  }
  if (!VerifyX509CertificateChain(ca_cert, ca_cert)) {
    printf("Can't verify ca cert\n");
    return false;
  }
  printf("CA verifies\n");

  // server
  string server_cert_file_name = path + "/server_cert";
  string server_key_file_name = path + "/server_key";
  if(!ReadFile(server_cert_file_name, &server_cert_string)) {
    printf("can't read server_cert.\n");
    return false;
  }
  if(!ReadFile(server_key_file_name, &server_key_string)) {
    printf("Can't read server key.\n");
    return false;
  }
  byte* server_ptr = (byte*)server_cert_string.data();
  X509* server_cert = d2i_X509(nullptr, (const byte**)&server_ptr,
        server_cert_string.size());
  if (server_cert == nullptr) {
    printf("server_cert doesnt translate.\n");
    return false;
  }

  EVP_PKEY* server_key = nullptr;

  if (!DeserializePrivateKey(server_key_string, &server_key_type, &server_key)) {
    printf("Can't deserialize server key\n");
    return false;
  }
  if (!VerifyX509CertificateChain(ca_cert, server_cert)) {
    printf("Can't verify server cert\n");
    return false;
  }
  printf("Server verifies\n");

  // client
  string client_cert_file_name = path + "/client_cert";
  string client_key_file_name = path + "/client_key";
  if(!ReadFile(client_cert_file_name, &client_cert_string)) {
    printf("can't read client_cert.\n");
    return false;
  }
  if(!ReadFile(client_key_file_name, &client_key_string)) {
    printf("Can't read client key.\n");
    return false;
  }
  byte* client_ptr = (byte*)client_cert_string.data();
  X509* client_cert = d2i_X509(nullptr, (const byte**)&client_ptr,
        client_cert_string.size());
  if (client_cert == nullptr) {
    printf("client_cert doesnt translate.\n");
    return false;
  }

  EVP_PKEY* client_key = nullptr;

  if (!DeserializePrivateKey(client_key_string, &client_key_type, &client_key)) {
    printf("Can't deserialize client key\n");
    return false;
  }
  if (!VerifyX509CertificateChain(ca_cert, client_cert)) {
    printf("Can't verify client cert\n");
    return false;
  }
  printf("Client verifies\n");
  
  return true;
}


TEST(test_gen, test_gen) { EXPECT_TRUE(test_gen()); }

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
  int result = RUN_ALL_TESTS();
  return result;
}

