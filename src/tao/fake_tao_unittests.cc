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
#include "tao/fake_tao.h"

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/base64w.h>

#include "tao/attestation.pb.h"
#include "tao/tao.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using keyczar::base::Base64WEncode;

using tao::FakeTao;
using tao::ScopedTempDir;
using tao::Tao;
using tao::TaoDomain;

class FakeTaoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(tao::CreateTempWhitelistDomain(&temp_dir_, &admin_));

    // create a fake tao with new keys and an attestation
    attested_tao_.reset(new FakeTao());
    ASSERT_TRUE(
        attested_tao_->InitPseudoTPM(*temp_dir_ + "/fake_tpm", *admin_));

    // create a fake tao with temporary keys and no attestation
    tao_.reset(new FakeTao());
    ASSERT_TRUE(tao_->InitTemporaryTPM());
  }

  scoped_ptr<FakeTao> tao_;
  scoped_ptr<FakeTao> attested_tao_;
  ScopedTempDir temp_dir_;
  scoped_ptr<TaoDomain> admin_;
};

TEST_F(FakeTaoTest, FullNameTest) {
  string tao_name;
  EXPECT_TRUE(tao_->GetTaoFullName(&tao_name));
  EXPECT_TRUE(!tao_name.empty());
}

TEST_F(FakeTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 10, &bytes));
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 0, &bytes));
  EXPECT_TRUE(attested_tao_->GetRandomBytes("fake hash", 128, &bytes));
}

TEST_F(FakeTaoTest, SealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));

  string encoded_hash;
  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  string sealed;
  EXPECT_TRUE(
      tao_->Seal(encoded_hash, bytes, Tao::PolicySameProgHash, &sealed));

  // Try the same thing with the attested tao.
  EXPECT_TRUE(attested_tao_->GetRandomBytes("fake hash", 128, &bytes));
  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  EXPECT_TRUE(attested_tao_->Seal(encoded_hash, bytes, Tao::PolicySameProgHash,
                                  &sealed));
}

TEST_F(FakeTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));

  string encoded_hash;
  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  string sealed;
  EXPECT_TRUE(tao_->Seal(encoded_hash, bytes, 0 /* policy */, &sealed));

  string unsealed;
  int policy;
  EXPECT_TRUE(tao_->Unseal(encoded_hash, sealed, &unsealed, &policy));

  EXPECT_EQ(bytes, unsealed);

  // Try the same thing with the attested tao
  EXPECT_TRUE(attested_tao_->GetRandomBytes("fake hash", 128, &bytes));

  EXPECT_TRUE(Base64WEncode(bytes, &encoded_hash));
  EXPECT_TRUE(
      attested_tao_->Seal(encoded_hash, bytes, 0 /* policy */, &sealed));

  EXPECT_TRUE(attested_tao_->Unseal(encoded_hash, sealed, &unsealed, &policy));

  EXPECT_EQ(bytes, unsealed);
}

TEST_F(FakeTaoTest, AttestTest) {
  string key_prin = "Key(\"..stuff..\")";
  string attestation;
  EXPECT_TRUE(tao_->Attest(encoded_hash, key_prin, &attestation));
  EXPECT_TRUE(attested_tao_->Attest(encoded_hash, key_prin, &attestation));
}
