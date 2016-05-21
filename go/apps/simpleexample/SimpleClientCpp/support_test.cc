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
// File: support_test.cc

#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>

#include "helpers.h"

bool readwritetest() {
  string filename("/tmp/test1");
  string in("12345");
  string out;

  if (!WriteFile(filename, in)) {
    return false;
  }
  if (!ReadFile(filename, &out)) {
    return false;
  }
  if (out != in) {
    return false;
  }
  return true;
}

bool cert_test() {
  string policy_cert;
  string policy_cert_file = "/Domains/domain.simpleexample/SimpleClientCpp/policy_keys/cert";

  if (!ReadFile(policy_cert_file, &policy_cert)) {
    printf("Can't read policy cert.\n");
    return false;
  }
  PrintBytes((int)policy_cert.size(), (byte*)policy_cert.data()); printf("\n");

  // Parse policy cert.
  byte* pc = (byte*)policy_cert.data();
  X509* parsed_policy_cert = d2i_X509(nullptr, (const byte**)&pc,
          policy_cert.size());
  if (parsed_policy_cert == nullptr) {
    printf("Can't DER parse policy cert.\n");
    return false;
  }
  EVP_PKEY* evp_policy_key = X509_get_pubkey(parsed_policy_cert);
  if (evp_policy_key == nullptr) {
    printf("Can't get policy public key from cert.\n");
    return false;
  }
  int key_type = EVP_PKEY_id(evp_policy_key);
  if (EVP_PKEY_EC == key_type) {
    printf("EC key type\n");
  } else if (EVP_PKEY_RSA == key_type) {
    printf("RSA key type\n");
  } else {
    printf("Unknown key type\n");
  }
  EC_KEY* policy_key = EVP_PKEY_get1_EC_KEY(evp_policy_key);
  if (policy_key == nullptr) {
    printf("Can't set policy public key.\n");
    return false;
  }
  EVP_PKEY* pubkey = X509_get_pubkey(parsed_policy_cert);
  int cert_OK = X509_verify(parsed_policy_cert,
           pubkey);
  if (cert_OK <= 0) {
    printf("Can't verify policy cert %d.\n", cert_OK);
    return false;
  }
  return true;
}

TEST(ReadWriteTest, ReadWriteTest) { EXPECT_TRUE(readwritetest()); }
TEST(cert_test, cert_test) { EXPECT_TRUE(cert_test()); }

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
  int result = RUN_ALL_TESTS();
  return result;
}

