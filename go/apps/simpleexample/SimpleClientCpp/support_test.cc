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
  if (pubkey == nullptr) {
    return false;
  }
#if 0
  int cert_OK = X509_verify(parsed_policy_cert,
           pubkey);
  if (cert_OK <= 0) {
    printf("Can't verify policy cert %d.\n", cert_OK);
    return false;
  }
#endif
  return true;
}

EVP_PKEY* key_choice(string& key_type, int key_size) {
  EVP_PKEY* key = nullptr;
  string* key_bytes;
  key = EVP_PKEY_new();
  if (key == nullptr)
    return nullptr;

  if (key_type == "RSA") {
    RSA* rsa_program_key = RSA_generate_key(key_size, 0x010001ULL, nullptr, nullptr);
    if (rsa_program_key == nullptr) {
      printf("key_choice: couldn't generate RSA program key.\n");
      return nullptr;
    }
    EVP_PKEY_assign_RSA(key, rsa_program_key);
    // Bytes for public key are the hash of the der encoding of it.
    byte out[4096];
    byte* ptr = out;
    int n = i2d_RSA_PUBKEY(rsa_program_key, &ptr);
    if (n <= 0) {
      printf("key_choice: Can't i2d RSA public key\n");
      return nullptr;
    }
    byte rsa_key_hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, out, n);
    SHA256_Final(rsa_key_hash, &sha256);
    key_bytes = ByteToHexLeftToRight(32, rsa_key_hash);
  } else if (key_type == "ECC") {
    EC_KEY* ec_program_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_program_key == nullptr) {
      printf("key_choice: couldn't generate ECC program key.\n");
      return nullptr;
    }
    if (1 != EC_KEY_generate_key(ec_program_key)) {
      printf("key_choice: couldn't generate ECC program key(2).\n");
      return nullptr;
    }
    EVP_PKEY_assign_EC_KEY(key, ec_program_key);
    // Bytes for public key are the hash of the der encoding of it.
    byte out[4096];
    byte* ptr = out;
    int n = i2d_EC_PUBKEY(ec_program_key, &ptr);
    if (n <= 0) {
      printf("key_choice: Can't i2d ECC public key\n");
      return nullptr;
    }
    byte ec_key_hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, out, n);
    SHA256_Final(ec_key_hash, &sha256);
    key_bytes = ByteToHexLeftToRight(32, ec_key_hash);
  } else {
    printf("unsupported key type.\n");
    return nullptr;
  }
  // Print key bytes
  printf("Bytes: ");
  PrintBytes((int)key_bytes->size(), (byte*)key_bytes->data());
  printf("\n");
  return key;
}


bool crypt_test() {
  int n;
  string key_type("RSA");
  int key_size = 2048;
  EVP_PKEY* key = key_choice(key_type, key_size);
  if (key == nullptr) {
    return false;
  }

  byte in[20] = {
    0,1,2,3,4,5,6,7,8,9,
    0,1,2,3,4,5,6,7,8,9,
  };
  byte out[512];

  RSA* rsa = EVP_PKEY_get1_RSA(key);
  if (rsa == nullptr) {
    return false;
  }
  n = RSA_public_encrypt(20, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
  if (n <= 0) {
    return false;
  }

  byte recover[512];
  int m = RSA_private_decrypt(n, out, recover, rsa, RSA_PKCS1_OAEP_PADDING);
  if (m != 20 || memcmp(in, recover, m) !=0) {
    return false;
  }

  key_type = "ECC";
  key_size = 256;
  key = key_choice(key_type, key_size);
  if (key == nullptr) {
    return false;
  }
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key);
  if (ec_key == nullptr) {
    return false;
  }

  byte sig[8192];
  unsigned int len = 8192;
  n =  ECDSA_sign(0, in, 20, sig, &len, ec_key);
  if (n <= 0) {
    return false;
  }
  printf("Len: %d\n", len);

  m = ECDSA_verify(0, in, 20, sig, len, ec_key);
  if (m <= 0) {
    return false;
  }
  return true;
}


TEST(ReadWriteTest, ReadWriteTest) { EXPECT_TRUE(readwritetest()); }
TEST(cert_test, cert_test) { EXPECT_TRUE(cert_test()); }
TEST(crypt_test, crypt_test) { EXPECT_TRUE(crypt_test()); }

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
  int result = RUN_ALL_TESTS();
  return result;
}

