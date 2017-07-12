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

#include <stdio.h>
#include <string.h>

#include <string>

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include <memory>
#include <cmath>

#include <ssl_helpers.h>
#include <agile_crypto_support.h>
#include <openssl/rand.h> 

using std::string;


DEFINE_bool(printall, false, "printall flag");


TEST(ReadWrite, all) {

  string file_name("test_file_1");
  string test_string_in("12345\n");
  string test_string_out;
  string filename("testFile1");
  EXPECT_TRUE(WriteFile(file_name, test_string_in));
  EXPECT_TRUE(ReadFile(file_name, &test_string_out));
  printf("in: ");
  PrintBytes(test_string_in.size(), (byte*)test_string_in.data());
  printf(", out: ");
  PrintBytes(test_string_out.size(), (byte*)test_string_out.data());
  printf("\n");
  EXPECT_TRUE(test_string_in == test_string_out);

}

TEST(MarshalProgramStruct, all) {
  // tao::SavedProgramData pd;
}

TEST(SigningCryptingVerifying, all) {
#ifdef FAKE_RAND_BYTES
  printf("Using fake random numbers\n");
#endif
  tao::CryptoKey ckSigner;
  string type("ecdsap256");

  EXPECT_TRUE(GenerateCryptoKey(type, &ckSigner));
  PrintCryptoKey(ckSigner);

  Signer* s = CryptoKeyToSigner(ckSigner);
  EXPECT_TRUE(s != nullptr);
  string msg("123456");
  string sig;

  EXPECT_TRUE(s->Sign(msg, &sig));
  EXPECT_TRUE(s->Verify(msg, sig));
#if 0
  Verifier* v = VerifierFromSigner(s);
  EXPECT_TRUE(v != nullptr);
  // EXPECT_TRUE(v->Verify(msg, sig));
  // Verifier* VerifierFromCertificate(string& der);

  type = "aes128-ctr-hmacsha256";
  tao::CryptoKey ckCrypter;

  EXPECT_TRUE(GenerateCryptoKey(type, &ckCrypter));
  PrintCryptoKey(ckCrypter);

  Crypter* c= CryptoKeyToCrypter(ckCrypter);
  EXPECT_TRUE(c != nullptr);

  string mac;
  string iv;
  string encrypted;
  string decrypted;
  EXPECT_TRUE(c->Encrypt(msg, &iv, &mac, &encrypted));
  EXPECT_TRUE(c->Decrypt(encrypted, iv, mac, &decrypted));
  EXPECT_TRUE(msg == decrypted);

  tao::CryptoKey* ckC =  CrypterToCryptoKey(c);
  EXPECT_TRUE(ckC != nullptr);
  tao::CryptoKey* ckS = SignerToCryptoKey(s);
  EXPECT_TRUE(ckS != nullptr);
  tao::CryptoKey* ckV = VerifierToCryptoKey(v);
  EXPECT_TRUE(ckV != nullptr);
#endif
}

TEST(Protect_Unprotect, all) {
  string type("aes128-ctr-hmacsha256");
  tao::CryptoKey ckCrypter;

  EXPECT_TRUE(GenerateCryptoKey(type, &ckCrypter));
  PrintCryptoKey(ckCrypter);

  Crypter* c= CryptoKeyToCrypter(ckCrypter);
  EXPECT_TRUE(c != nullptr);
#if 0
  string msg("123456");
  string encrypted;
  string decrypted;
  EXPECT_TRUE(Protect(*c, msg, &encrypted));
  EXPECT_TRUE(Unprotect(*c, encrypted, &decrypted));
  EXPECT_TRUE(msg == decrypted);
#endif
}

TEST(Certs, all) {
#if 0
  tao::CryptoKey ckSigner;
  string type("ecdsap256");

  EXPECT_TRUE(GenerateCryptoKey(type, &ckSigner));
  PrintCryptoKey(ckSigner);

  Signer* s = CryptoKeyToSigner(ckSigner);
  EXPECT_TRUE(s != nullptr);
  string common_name("common_name");
  X509_REQ* req = X509_REQ_new();
  EXPECT_TRUE(GenerateX509CertificateRequest(s->sk_, common_name, true, req));
  
  string issuer_name("issuer_name");
  string keyUsage("");
  string extendedKeyUsage("");
  X509* cert= X509_new();
  EXPECT_TRUE(SignX509Certificate(s->sk_, true, true, issuer_name, keyUsage,
          extendedKeyUsage, int64_t(365 * 86400), s->sk_, req, true, cert));
  // EXPECT_TRUE(VerifyX509CertificateChain(cert, cert));
#endif
}

TEST(KeyBytes, all) {
  tao::CryptoKey ckSigner;
  string type("ecdsap256");

  EXPECT_TRUE(GenerateCryptoKey(type, &ckSigner));
  PrintCryptoKey(ckSigner);

  Signer* s = CryptoKeyToSigner(ckSigner);
  EXPECT_TRUE(s != nullptr);

#if 0
  Verifier* v = VerifierFromSigner(s);
  EXPECT_TRUE(v != nullptr);
  string prinBytes;
  string universal_name;
  EXPECT_TRUE(KeyPrincipalBytes(v, &prinBytes));
  EXPECT_TRUE(UniversalKeyName(v, &universal_name));
#endif
}

TEST(KeyTranslate, All) {

  tao::CryptoKey ck1;
  string type("ecdsap256");

  EXPECT_TRUE(GenerateCryptoKey(type, &ck1));
  PrintCryptoKey(ck1);

  tao::CryptoKey ck2;
  type= "ecdsap384";
  EXPECT_TRUE(GenerateCryptoKey(type, &ck2));
  PrintCryptoKey(ck2);

  tao::CryptoKey ck3;
  type= "ecdsap521";
  EXPECT_TRUE(GenerateCryptoKey(type, &ck3));
  PrintCryptoKey(ck3);

  tao::CryptoKey ck4;
  type= "aes128-ctr-hmacsha256";
  EXPECT_TRUE(GenerateCryptoKey(type, &ck4));
  PrintCryptoKey(ck4);

  tao::CryptoKey ck5;
  type= "aes256-ctr-hmacsha384";
  EXPECT_TRUE(GenerateCryptoKey(type, &ck5));
  PrintCryptoKey(ck5);

  tao::CryptoKey ck6;
  type= "aes256-ctr-hmacsha512";
  EXPECT_TRUE(GenerateCryptoKey(type, &ck6));
  PrintCryptoKey(ck6);
}


int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
  int result = RUN_ALL_TESTS();
  return result;
}

