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

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "tao/attestation.pb.h"
#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/whitelist_auth.h"
#include "tao/util.h"

using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::rw::KeysetWriter;
using keyczar::rw::KeysetJSONFileWriter;

using std::ofstream;

using tao::Attestation;
using tao::CreateKey;
using tao::CreatePubECDSAKey;
using tao::CreateECDSAKey;
using tao::CreateTempDir;
using tao::CreateTempPubKey;
using tao::FakeTao;
using tao::HostedProgram;
using tao::KeyczarPublicKey;
using tao::ScopedRsa;
using tao::ScopedTempDir;
using tao::SignData;
using tao::SignedWhitelist;
using tao::Statement;
using tao::Tao;
using tao::Whitelist;
using tao::WhitelistAuth;

class WhitelistAuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempPubKey(&temp_dir_, &policy_key_))
        << "Could not create a temporary public key";

    policy_pk_path_ = *temp_dir_ + string("/policy_pk");
    fake_tao_.reset(new FakeTao(policy_pk_path_));
    ASSERT_TRUE(fake_tao_->Init()) << "Could not initialize the fake tao";

    string whitelist_path = *temp_dir_ + string("/whitelist");

    // Create a whitelist with some test programs.
    Whitelist w;
    HostedProgram *hp = w.add_programs();
    hp->set_name("Test 1");
    hp->set_hash_alg("SHA256");
    hp->set_hash("Test hash 1");

    HostedProgram *linux_tao_hp = w.add_programs();
    linux_tao_hp->set_name("Test 2");
    linux_tao_hp->set_hash_alg("SHA256");
    linux_tao_hp->set_hash("Test hash 2");

    SignedWhitelist sw;
    string *serialized_whitelist = sw.mutable_serialized_whitelist();
    ASSERT_TRUE(w.SerializeToString(serialized_whitelist));

    string *signature = sw.mutable_signature();
    ASSERT_TRUE(policy_key_->Sign(*serialized_whitelist, signature));

    ofstream whitelist_file(whitelist_path.c_str(), ofstream::out);
    ASSERT_TRUE(sw.SerializeToOstream(&whitelist_file));
    whitelist_file.close();

    whitelist_auth_.reset(new WhitelistAuth(whitelist_path, policy_pk_path_));
    ASSERT_TRUE(whitelist_auth_->Init()) << "Could not init WhitelistAuth";
  }

  ScopedTempDir temp_dir_;
  scoped_ptr<Keyczar> policy_key_;
  scoped_ptr<WhitelistAuth> whitelist_auth_;
  scoped_ptr<Tao> fake_tao_;
  string policy_pk_path_;
};

TEST_F(WhitelistAuthTest, IsAuthorizedTest) {
  EXPECT_TRUE(whitelist_auth_->IsAuthorized("Test hash 1"));
}

TEST_F(WhitelistAuthTest, IsAuthorizedFailTest) {
  EXPECT_FALSE(whitelist_auth_->IsAuthorized("Non-authorized program name"));
}

TEST_F(WhitelistAuthTest, IsAuthorizedPairTest) {
  EXPECT_TRUE(whitelist_auth_->IsAuthorized("Test 2", "Test hash 2"));
}

TEST_F(WhitelistAuthTest, IsAuthorizedPairFailTest) {
  EXPECT_FALSE(whitelist_auth_->IsAuthorized("Test 2", "Not the right hash"));
}

TEST_F(WhitelistAuthTest, VerifyRootFailTest) {
  // Create an attestation for a program, and check that it passes verification.
  // This won't work, even though it's signed by the root key, since
  // WhitelistAuth insists on everything being on the whitelist.
  FakeTao ft(policy_pk_path_);
  EXPECT_TRUE(ft.Init()) << "Could not init the FakeTao";
  string hash("test hash");

  string data("test data");
  string attestation;
  EXPECT_TRUE(ft.Attest(hash, data, &attestation)) << "Could not attest";

  string output_data;
  EXPECT_FALSE(whitelist_auth_->VerifyAttestation(attestation, &output_data))
      << "The generated attestation did not pass verification";
}

TEST_F(WhitelistAuthTest, VerifyRootTest) {
  // Create an attestation for a program, and check that it passes verification.
  string hash("Test hash 2");

  string data("test data");
  string attestation;
  EXPECT_TRUE(fake_tao_->Attest(hash, data, &attestation))
      << "Could not attest";

  string output_data;
  EXPECT_TRUE(whitelist_auth_->VerifyAttestation(attestation, &output_data))
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

  ASSERT_GE(RSA_generate_key_ex(rsa.get(), 2048, e, NULL), 0)
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
  string attestation;
  ASSERT_TRUE(fake_tao_->Attest("Test hash 1", data, &attestation))
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
  s.set_hash_alg("SHA256");
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
  EXPECT_TRUE(whitelist_auth_->VerifyAttestation(top_attestation, &top_data))
      << "The constructed TPM 1.2 Quote did not pass verification";

  string original_data("Test data");
  EXPECT_EQ(top_data, original_data)
      << "The extracted data from the attestation did not match the original";
}

TEST_F(WhitelistAuthTest, IntermediateSignatureTest) {
  // make a chain 3 deep of INTERMEDIATE->INTERMEDIATE->ROOT signatures
  string key_1_path = *temp_dir_ + string("/key1");
  string key_2_path = *temp_dir_ + string("/key2");

  EXPECT_EQ(mkdir(key_1_path.c_str(), 0700), 0)
      << "Could not create the first path";
  EXPECT_EQ(mkdir(key_2_path.c_str(), 0700), 0)
      << "Could not create the second path";

  scoped_ptr<Keyczar> key_1;
  scoped_ptr<Keyczar> key_2;
  EXPECT_TRUE(CreateECDSAKey(key_1_path, "key_1", &key_1))
      << "Could not create key 1";
  EXPECT_TRUE(CreateECDSAKey(key_2_path, "key_2", &key_2))
      << "Could not create key 2";

  KeyczarPublicKey kpk_1;
  KeyczarPublicKey kpk_2;

  EXPECT_TRUE(SerializePublicKey(*key_1, &kpk_1)) << "Could not serialize 1";
  EXPECT_TRUE(SerializePublicKey(*key_2, &kpk_2)) << "Could not serialize 2";

  string kpk_1_str;
  string kpk_2_str;
  EXPECT_TRUE(kpk_1.SerializeToString(&kpk_1_str))
      << "Could not serialize kpk 1 to a string";

  EXPECT_TRUE(kpk_2.SerializeToString(&kpk_2_str))
      << "Could not serialize kpk 2 to a string";

  string root_cert;
  EXPECT_TRUE(fake_tao_->Attest("Test hash 1", kpk_1_str, &root_cert))
      << "Could not attest to key 2";

  Attestation a1;
  a1.set_type(tao::INTERMEDIATE);
  a1.set_cert(root_cert);
  Statement s1;
  time_t cur_time;
  time(&cur_time);
  s1.set_time(cur_time);
  s1.set_expiration(cur_time + 10000);
  s1.set_data(kpk_2_str);
  s1.set_hash_alg("SHA256");
  s1.set_hash("Test hash 2");

  string *ser_1 = a1.mutable_serialized_statement();
  EXPECT_TRUE(s1.SerializeToString(ser_1)) << "Could not serialized stat 1";

  string *sig_1 = a1.mutable_signature();
  EXPECT_TRUE(SignData(*ser_1, sig_1, key_1.get())) << "Could not sign key 2";

  string level_2_cert;
  EXPECT_TRUE(a1.SerializeToString(&level_2_cert))
      << "Could not serialize the attestation to key 1";

  string data("Test data");
  Attestation a2;
  a2.set_type(tao::INTERMEDIATE);
  a2.set_cert(level_2_cert);
  Statement s2;
  s2.set_time(cur_time);
  s2.set_expiration(cur_time + 10000);
  s2.set_data(data);
  s2.set_hash_alg("SHA256");
  s2.set_hash("Test hash 1");

  string *ser_2 = a2.mutable_serialized_statement();
  EXPECT_TRUE(s2.SerializeToString(ser_2)) << "Could not serialize stat 2";

  string *sig_2 = a2.mutable_signature();
  EXPECT_TRUE(SignData(*ser_2, sig_2, key_2.get())) << "Could not sign data";

  string top_attestation;
  EXPECT_TRUE(a2.SerializeToString(&top_attestation))
      << "Could not serialize the top attestation";

  string extracted_data;
  EXPECT_TRUE(
      whitelist_auth_->VerifyAttestation(top_attestation, &extracted_data))
      << "The top-level attestation did not pass verification";

  EXPECT_EQ(extracted_data, data)
      << "The extracted data did not match the original";
}
