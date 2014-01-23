//  File: fake_tao_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic FakeTao functionality
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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

#include <gtest/gtest.h>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/keyczar.h>

#include "tao/attestation.pb.h"
#include "tao/fake_tao.h"
#include "tao/tao.h"
#include "tao/util.h"

using keyczar::base::Base64WEncode;
using keyczar::Keyczar;
using tao::Attestation;
using tao::CreateECDSAKey;
using tao::CreateTempPubKey;
using tao::FakeTao;
using tao::KeyczarPublicKey;
using tao::SignData;
using tao::ScopedTempDir;
using tao::Statement;
using tao::Tao;

class FakeTaoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_TRUE(CreateTempPubKey(&temp_dir_, &policy_key_))
        << "Could not create a public key";

    string fake_key_path = *temp_dir_ + "/fake_key";
    string fake_key_attest;
    ASSERT_EQ(mkdir(fake_key_path.c_str(), 0700), 0);
    // Create a key but don't keep it in memory. It just needs to exist on disk
    // for the FakeTao.
    {
      const int AttestationTimeout = 31556926;
      scoped_ptr<Keyczar> fake_key;
      ASSERT_TRUE(CreateECDSAKey(fake_key_path, "fake_key", &fake_key));
      KeyczarPublicKey kpk;
      ASSERT_TRUE(SerializePublicKey(*fake_key, &kpk));
      string serialized_pub_key;
      ASSERT_TRUE(kpk.SerializeToString(&serialized_pub_key));
      Attestation a;
      Statement s;
      time_t cur_time;
      time(&cur_time);
    
      s.set_time(cur_time);
      s.set_expiration(cur_time + AttestationTimeout);
      s.set_data(serialized_pub_key);
      s.set_hash_alg("SHA256");
      s.set_hash("FAKE_PCRS");
    
      string serialized_statement;
      CHECK(s.SerializeToString(&serialized_statement)) << "Could not serialize";
      string sig;
      CHECK(SignData(serialized_statement, Tao::AttestationSigningContext, &sig,
                     policy_key_.get())) << "Could not sign the key";
    
      // There's no cert, since this is signed by the root key
      a.set_type(tao::ROOT);
      a.set_serialized_statement(serialized_statement);
      a.set_signature(sig);
      ASSERT_TRUE(a.SerializeToString(&fake_key_attest));
    }
    
    ASSERT_TRUE(tao_.Init());
    attested_tao_.reset(new FakeTao(fake_key_path, fake_key_attest));
    ASSERT_TRUE(attested_tao_->Init());

  }

  FakeTao tao_;
  scoped_ptr<FakeTao> attested_tao_;
  ScopedTempDir temp_dir_;
  scoped_ptr<Keyczar> policy_key_;
};

TEST_F(FakeTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_.GetRandomBytes(10, &bytes));
  EXPECT_TRUE(tao_.GetRandomBytes(0, &bytes));
  EXPECT_TRUE(attested_tao_->GetRandomBytes(128, &bytes));
}

TEST_F(FakeTaoTest, SealTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));

  string encoded_hash;
  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  string sealed;
  EXPECT_TRUE(tao_.Seal(encoded_hash, bytes, &sealed));

  // Try the same thing with the attested tao.
  EXPECT_TRUE(attested_tao_->GetRandomBytes(128, &bytes));
  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  EXPECT_TRUE(attested_tao_->Seal(encoded_hash, bytes, &sealed));
}

TEST_F(FakeTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));

  string encoded_hash;
  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  string sealed;
  EXPECT_TRUE(tao_.Seal(encoded_hash, bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(tao_.Unseal(encoded_hash, sealed, &unsealed));

  EXPECT_EQ(bytes, unsealed);

  // Try the same thing with the attested tao
  EXPECT_TRUE(attested_tao_->GetRandomBytes(128, &bytes));

  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  EXPECT_TRUE(attested_tao_->Seal(encoded_hash, bytes, &sealed));

  EXPECT_TRUE(attested_tao_->Unseal(encoded_hash, sealed, &unsealed));

  EXPECT_EQ(bytes, unsealed);
}

TEST_F(FakeTaoTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));

  string encoded_hash;
  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  string attestation;
  EXPECT_TRUE(tao_.Attest(encoded_hash, bytes, &attestation));

  // Try the same thing with the attested tao
  EXPECT_TRUE(attested_tao_->GetRandomBytes(128, &bytes));

  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  EXPECT_TRUE(attested_tao_->Attest(encoded_hash, bytes, &attestation));
}
