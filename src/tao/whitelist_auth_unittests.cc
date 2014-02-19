//  File: whitelist_auth_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Basic tests for the WhitelistAuth class.
//
//  Copyright (c) 2014, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "tao/whitelist_auth.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/keyczar.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/util.h"

using keyczar::Signer;

using tao::Attestation;
using tao::GenerateAttestation;
using tao::GenerateSigningKey;
using tao::ScopedRsa;
using tao::ScopedTempDir;
using tao::SerializePublicKey;
using tao::SignData;
using tao::Statement;
using tao::Tao;
using tao::TaoAuth;
using tao::TaoDomain;

class WhitelistAuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempWhitelistDomain(&temp_dir_, &admin_));

    // Create a whitelist with some test programs.
    ASSERT_TRUE(admin_->Authorize("Test hash 1", TaoAuth::FakeHash, "Name 1"));
    ASSERT_TRUE(admin_->Authorize("Test hash 2", TaoAuth::FakeHash, "Name 2"));
    ASSERT_TRUE(admin_->Authorize("Test hash 3", TaoAuth::FakeHash, "Name 3"));
  }

  ScopedTempDir temp_dir_;
  scoped_ptr<TaoDomain> admin_;
};

TEST_F(WhitelistAuthTest, IsAuthorizedTest) {
  string name;
  EXPECT_TRUE(admin_->IsAuthorized("Test hash 1", TaoAuth::FakeHash, &name));
  EXPECT_EQ("Name 1", name);
  EXPECT_TRUE(admin_->IsAuthorized("Test hash 1", TaoAuth::FakeHash, nullptr));
}

TEST_F(WhitelistAuthTest, IsAuthorizedFailTest) {
  string name;
  EXPECT_FALSE(admin_->IsAuthorized("Evil hash", TaoAuth::FakeHash, &name));
  EXPECT_FALSE(admin_->IsAuthorized("Evil hash", TaoAuth::FakeHash, nullptr));
  EXPECT_FALSE(admin_->IsAuthorized("Evil hash", TaoAuth::Sha256, &name));
  EXPECT_FALSE(admin_->IsAuthorized("Evil hash", TaoAuth::Sha256, nullptr));
  EXPECT_FALSE(admin_->IsAuthorized("Test hash 1", TaoAuth::Sha256, &name));
  EXPECT_FALSE(admin_->IsAuthorized("Test hash 1", TaoAuth::Sha256, nullptr));
}

TEST_F(WhitelistAuthTest, IsAuthorizedPairTest) {
  EXPECT_TRUE(
      admin_->IsAuthorized("Test hash 2", TaoAuth::FakeHash, "Name 2"));
}

TEST_F(WhitelistAuthTest, IsAuthorizedPairFailTest) {
  EXPECT_FALSE(admin_->IsAuthorized("Test hash 2", TaoAuth::FakeHash, "bad"));
  EXPECT_FALSE(admin_->IsAuthorized("Test hash 2", TaoAuth::Sha256, "Name 2"));
}

TEST_F(WhitelistAuthTest, VerifyRootFailTest) {
  // Create an attestation for a program, and check that it passes verification.
  // This should fail even though it's signed by the root key, since
  // WhitelistAuth insists on everything being on the whitelist.
  Statement s;
  s.set_data("test data");
  s.set_hash_alg(TaoAuth::FakeHash);
  s.set_hash("test hash");
  string attestation;
  ASSERT_TRUE(admin_->AttestByRoot(&s, &attestation));

  string output_data;
  EXPECT_FALSE(admin_->VerifyAttestation(attestation, &output_data))
      << "The generated attestation did not pass verification";
}

TEST_F(WhitelistAuthTest, VerifyRootTest) {
  // Create an attestation for a program, and check that it passes verification.
  Statement s;
  s.set_data("test data");
  s.set_hash_alg(TaoAuth::FakeHash);
  s.set_hash("Test hash 2");
  string attestation;
  ASSERT_TRUE(admin_->AttestByRoot(&s, &attestation));

  string output_data;
  EXPECT_TRUE(admin_->VerifyAttestation(attestation, &output_data))
      << "The generated attestation did not pass verification";
}

// Some OpenSSL types for convenience
typedef unsigned char BYTE;
typedef unsigned int UINT32;
typedef unsigned short UINT16;

TEST_F(WhitelistAuthTest, TPMQuoteTest) {
  // Create a fake TPM 1.2 attestation.

  tao::InitializeOpenSSL();

  // Create a fresh OpenSSL RSA key that can be used to sign the quote.
  ScopedRsa rsa(RSA_new());
  BIGNUM *e = BN_new();
  int exp = htonl(65537);
  ASSERT_EQ(BN_bin2bn((BYTE *)&exp, sizeof(exp), e), e)
      << "Could not create an exponent for the RSA key";

  ASSERT_GE(RSA_generate_key_ex(rsa.get(), 2048, e, nullptr), 0)
      << "Could not generate a new RSA key";

  BIO *mem = BIO_new(BIO_s_mem());
  ASSERT_EQ(PEM_write_bio_RSAPublicKey(mem, rsa.get()), 1)
      << "Could not write the RSA to a bio";

  // The key should take up less than 8k in size.
  int len = 8 * 1024;
  scoped_array<char> key_bytes(new char[len]);
  int result = BIO_read(mem, key_bytes.get(), len);
  ASSERT_GE(result, 0) << "Could not read the bytes from the array";
  string data(key_bytes.get(), result);

  // This key must be signed by the root. And "Test hash 1" takes the place of
  // the PCRs in this case.
  Statement rs;
  rs.set_data(data);
  rs.set_hash_alg(TaoAuth::FakeHash);
  rs.set_hash("Test hash 1");
  string attestation;
  ASSERT_TRUE(admin_->AttestByRoot(&rs, &attestation))
      << "Could not attest to the key";

  Attestation a;
  a.set_type(tao::TPM_1_2_QUOTE);
  a.set_cert(attestation);

  Statement s;
  time_t cur_time;
  time(&cur_time);

  s.set_time(cur_time);
  s.set_expiration(cur_time + 10000);
  s.set_data("Test data");
  s.set_hash_alg(TaoAuth::FakeHash);
  s.set_hash("Test hash 2");

  string *serialized_statement = a.mutable_serialized_statement();
  ASSERT_TRUE(s.SerializeToString(serialized_statement))
      << "Could not serialize the statement";

  // Hash the statement with SHA1 for the external data part of the quote.
  BYTE statement_hash[20];
  SHA1(reinterpret_cast<const BYTE *>(a.serialized_statement().data()),
       a.serialized_statement().size(), statement_hash);

  // The quote can be created using a qinfo, which has a header of 8 bytes, and
  // two hashes.  The first hash is the hash of the external data, and the
  // second is the hash of the quote itself. This can be hashed and signed
  // directly by OpenSSL.

  BYTE qinfo[8 + 2 * 20];
  qinfo[0] = 1;
  qinfo[1] = 1;
  qinfo[2] = 0;
  qinfo[3] = 0;
  qinfo[4] = 'Q';
  qinfo[5] = 'U';
  qinfo[6] = 'O';
  qinfo[7] = 'T';

  a.set_quote("Fake quote data");

  SHA1(reinterpret_cast<const BYTE *>(a.quote().data()), a.quote().size(),
       qinfo + 8);
  memcpy(qinfo + 8 + 20, statement_hash, sizeof(statement_hash));

  BYTE quote_hash[20];
  SHA1(qinfo, sizeof(qinfo), quote_hash);
  UINT32 sig_len = 512;  // far more bytes than are actually needed.
  scoped_array<BYTE> sig(new BYTE[sig_len]);
  ASSERT_EQ(RSA_sign(NID_sha1, quote_hash, sizeof(quote_hash), sig.get(),
                     &sig_len, rsa.get()),
            1) << "Could not sign the message";

  string signature(reinterpret_cast<char *>(sig.get()), sig_len);
  a.set_signature(signature);

  string top_attestation;
  EXPECT_TRUE(a.SerializeToString(&top_attestation))
      << "Could not serialize the attestation";

  string top_data;
  EXPECT_TRUE(admin_->VerifyAttestation(top_attestation, &top_data))
      << "The constructed TPM 1.2 Quote did not pass verification";

  string original_data("Test data");
  EXPECT_EQ(top_data, original_data)
      << "The extracted data from the attestation did not match the original";
}

TEST_F(WhitelistAuthTest, IntermediateSignatureTest) {
  // make a chain 3 deep of INTERMEDIATE->INTERMEDIATE->ROOT signatures
  string key_1_path = *temp_dir_ + string("/key1");
  string key_2_path = *temp_dir_ + string("/key2");

  scoped_ptr<Signer> key_1;
  scoped_ptr<Signer> key_2;
  ASSERT_TRUE(GenerateSigningKey(key_1_path, "" /* do not save private key */,
                                 "key 1", "unitpass", &key_1));
  ASSERT_TRUE(GenerateSigningKey(key_1_path, "" /* do not save private key */,
                                 "key 2", "unitpass", &key_2));

  Statement s0;
  s0.set_data(SerializePublicKey(*key_1));
  s0.set_hash_alg(TaoAuth::FakeHash);
  s0.set_hash("Test hash 1");
  string a0;
  EXPECT_TRUE(admin_->AttestByRoot(&s0, &a0)) << "Could not attest to key 2";

  Statement s1;
  s1.set_data(SerializePublicKey(*key_2));
  s1.set_hash_alg(TaoAuth::FakeHash);
  s1.set_hash("Test hash 2");
  string a1;
  EXPECT_TRUE(GenerateAttestation(key_1.get(), a0, &s1, &a1));

  Statement s2;
  s2.set_data("Test data");
  s2.set_hash_alg(TaoAuth::FakeHash);
  s2.set_hash("Test hash 3");
  string a2;
  EXPECT_TRUE(GenerateAttestation(key_2.get(), a1, &s2, &a2));

  string extracted_data;
  EXPECT_TRUE(admin_->VerifyAttestation(a2, &extracted_data))
      << "The top-level attestation did not pass verification";

  EXPECT_EQ(extracted_data, "Test data")
      << "The extracted data did not match the original";
}
