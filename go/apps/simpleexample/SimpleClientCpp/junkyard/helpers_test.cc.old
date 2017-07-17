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

// Cert request test
bool cert_test() {
  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();

  int size = 256;
  string key_type("ECC");
  string common_name("Fred");
  string issuer("Fred");
  string keyUsage("critical,digitalSignature,keyEncipherment,keyAgreement,keyCertSign");
  string extendedKeyUsage("serverAuth,clientAuth");

  EVP_PKEY* self = GenerateKey(key_type, size);
  if (self == nullptr) {
    printf("Can't generate key.\n");
    return false;
  }
  if (!GenerateX509CertificateRequest(key_type, common_name,
          self, false, req)) {
    printf("Can't generate x509 request\n");
    return false;
  }

  if (!SignX509Certificate(self, true, true, issuer, keyUsage,
                           extendedKeyUsage, 86400,
                           self, req, false, cert)) {
    printf("Can't sign x509 request\n");
    return false;
  }

  if(!VerifyX509CertificateChain(cert, cert)) {
    printf("cert DOES NOT verifies\n");
    return false;
  }
  printf("cert verifies\n");
  return true;
}

// Verify chains test
bool verify_chains_test() {
  return true;
}

// Key bytes test
bool key_bytes_test() {
  string key_type("RSA");
  int key_size = 2048;
  EVP_PKEY* key = GenerateKey(key_type, key_size);
  if (key == nullptr) {
    printf("GenerateKey fails\n");
    return false;
  }
  EVP_PKEY_free(key);
  key = nullptr;

  key_type = "ECC";
  key_size = 256;
  key = GenerateKey(key_type, key_size);
  if (key == nullptr) {
    printf("GenerateKey fails\n");
    return false;
  }

  EVP_PKEY_free(key);
  key = nullptr;
  return true;
}

// Serialize/Deserialize tests
bool serialize_test() {
  string key_type("RSA");
  int key_size = 2048;
  string out_buf;

  EVP_PKEY* key = GenerateKey(key_type, key_size);
  if (key == nullptr) {
    printf("GenerateKey fails\n");
    return false;
  }
  if (!SerializePrivateKey(key_type, key, &out_buf)) {
    printf("SerializePrivateKey fails\n");
    return false;
  }
  string new_key_type; 
  EVP_PKEY* new_key = nullptr;
  if (!DeserializePrivateKey(out_buf, &new_key_type, &new_key)) {
    printf("DeserializePrivateKey fails\n");
    return false;
  }
  if  (key->type != new_key->type) {
    printf("Key type mismatch\n");
    return false;
  }
  RSA* rsa_key = EVP_PKEY_get1_RSA(key);
  RSA* new_rsa_key = EVP_PKEY_get1_RSA(new_key);
  if (rsa_key == nullptr || new_rsa_key == nullptr) {
    return false;
  }
  if (rsa_key->n == nullptr || new_rsa_key->n == nullptr) {
    return false;
  }
  if (BN_cmp(rsa_key->n, new_rsa_key->n) != 0) {
    return false;
  }
  if (rsa_key->e == nullptr || new_rsa_key->e == nullptr) {
    return false;
  }
  if (BN_cmp(rsa_key->e, new_rsa_key->e) != 0) {
    return false;
  }
  if (rsa_key->d != nullptr && new_rsa_key->d != nullptr) {
    if (BN_cmp(rsa_key->d, new_rsa_key->d) != 0) {
      return false;
    }
  }
  if (rsa_key->p != nullptr && new_rsa_key->p != nullptr) {
    if (BN_cmp(rsa_key->p, new_rsa_key->p) != 0) {
      return false;
    }
  }
  if (rsa_key->q != nullptr && new_rsa_key->q != nullptr) {
    if (BN_cmp(rsa_key->q, new_rsa_key->q) != 0) {
      return false;
    }
  }
  EVP_PKEY_free(key);
  EVP_PKEY_free(new_key);
  key = nullptr;
  new_key = nullptr;
  printf("RSA done\n");

  key_type = "ECC";
  key_size = 256;
  out_buf.clear();
  new_key_type.clear();

  key = GenerateKey(key_type, key_size);
  if (key == nullptr) {
    printf("GenerateKey fails\n");
    return false;
  }
  if (!SerializePrivateKey(key_type, key, &out_buf)) {
    printf("SerializePrivateKey fails\n");
    return false;
  }
  new_key = nullptr;
  if (!DeserializePrivateKey(out_buf, &new_key_type, &new_key)) {
    printf("DeserializePrivateKey fails\n");
    return false;
  }
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key);
  EC_KEY* new_ec_key = EVP_PKEY_get1_EC_KEY(new_key);
  if  (key->type != new_key->type) {
    printf("Key type mismatch\n");
    return false;
  }
  if (ec_key == nullptr || new_ec_key == nullptr) {
    return false;
  }
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  const EC_GROUP* new_group = EC_KEY_get0_group(new_ec_key);
  if (group == nullptr || new_group == nullptr) {
    return false;
  }

  byte out[4096];
  byte* ptr = out;
  int n = i2d_ECPrivateKey(ec_key, &ptr);
  if (n <= 0) {
    printf("Can't i2d ECC private key\n");
    return false;
  }
  byte new_out[4096];
  byte* new_ptr = new_out;
  int new_n = i2d_ECPrivateKey(new_ec_key, &new_ptr);
  if (new_n <= 0) {
    printf("Can't i2d ECC private key\n");
    return false;
  }
  if (n != new_n) {
    return false;
  }
  if (memcmp(out, new_out, n) != 0) {
    return false;
  }

#if 0
  BIGNUM order;
  BIGNUM cofactor;
  BN_CTX* bn_ctx = BN_CTX_new();
  const EC_POINT* generator = EC_GROUP_get0_generator(group);
  int o1 = EC_GROUP_get_order(group, &order, bn_ctx);
  int o2 = EC_GROUP_get_cofactor(group, &cofactor, bn_ctx);
  BN_CTX_free(bn_ctx);
#endif

  EVP_PKEY_free(key);
  EVP_PKEY_free(new_key);
  key = nullptr;
  new_key = nullptr;
  printf("ECC done\n");
  return true;
}

bool crypt_test() {
  int n;
  string key_type("RSA");
  int key_size = 2048;
  EVP_PKEY* key = GenerateKey(key_type, key_size);
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
  key = GenerateKey(key_type, key_size);
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

  m = ECDSA_verify(0, in, 20, sig, len, ec_key);
  if (m <= 0) {
    return false;
  }
  return true;
}


TEST(cert_test, cert_test) { EXPECT_TRUE(cert_test()); }
TEST(ReadWriteTest, ReadWriteTest) { EXPECT_TRUE(readwritetest()); }
TEST(crypt_test, crypt_test) { EXPECT_TRUE(crypt_test()); }
TEST(verify_chains_test, verify_chains_test) { EXPECT_TRUE(verify_chains_test()); }
TEST(key_bytes_test, key_bytes_test) { EXPECT_TRUE(key_bytes_test()); }
TEST(serialize_test, serialize_test) { EXPECT_TRUE(serialize_test()); }

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
  int result = RUN_ALL_TESTS();
  return result;
}

