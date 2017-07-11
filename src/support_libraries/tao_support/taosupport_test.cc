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

#include <agile_crypto_support.h>

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
  tao::CryptoKey ckSigner;
  string type("ecdsap256");

  EXPECT_TRUE(GenerateCryptoKey(type, &ckSigner));
  PrintCryptoKey(ckSigner);

//   Verifier* VerifierFromSigner(Signer* s);
//   Verifier* VerifierFromCertificate(string& der);
//   bool Sign(string& in, string* out);
//   bool Verify(string& msg, string& sig);
//   bool Encrypt(string& in, string* iv, string* mac, string* out);
//   bool Decrypt(string& in, string& iv, string& mac, string* out);
//   Verifier* CryptoKeyToVerifier(tao::CryptoKey& ck);
//   Signer* CryptoKeyToSigner(tao::CryptoKey& ck);
//   Crypter* CryptoKeyToCrypter(tao::CryptoKey& ck);
//   bool GenerateCryptoKey(string& type, tao::CryptoKey* ck);
//   tao::CryptoKey* SignerToCryptoKey(tao::CryptoKey& ck);
//   tao::CryptoKey* VerifierToCryptoKey(tao::CryptoKey& ck);
//   tao::CryptoKey* CrypterToCryptoKey(tao::CryptoKey& ck);
//   bool SerializeECCKeyComponents(EC_KEY* ec_key, string* component);
//   bool DeserializeECCKeyComponents(string component, EC_KEY* ec_key);
}

TEST(Protect_Unprotect, all) {
//  bool Protect(Crypter& crypter, string& in, string* out);
//  bool Unprotect(Crypter& crypter, string& in, string* out);
}

TEST(Certs, all) {
//  bool GenerateX509CertificateRequest(string& key_type, string& common_name,
//            EVP_PKEY* subjectKey, bool sign_request, X509_REQ* req);
//bool SignX509Certificate(EVP_PKEY* signingKey, bool f_isCa, bool f_canSign,
//                         string& signing_issuer,string& keyUsage,
//                         string& extendedKeyUsage,
//                         int64 duration, EVP_PKEY* signedKey,
//                         X509_REQ* req, bool verify_req_sig, X509* cert);
//bool VerifyX509CertificateChain(X509* cacert, X509* cert);
}

TEST(KeyBytes, all) {
// bool KeyPrincipalBytes(Verifier* v, string* out);
// bool UniversalKeyName(Verifier* v, string* out);
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

