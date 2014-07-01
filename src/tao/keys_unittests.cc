//  File: keys_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Unit tests for key utility functions
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
#include "tao/keys.h"

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/keyczar.h>

#include "tao/soft_tao.h"
#include "tao/util.h"

using std::string;

using tao::CreateTempDir;
// using tao::DeserializePublicKey;
using tao::Keys;
using tao::ScopedTempDir;
// using tao::SerializePublicKey;
using tao::SoftTao;
using tao::Tao;

class TaoKeysTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("keys_test", &temp_dir_));
    keys_.reset(new Keys("unittest",
                         Keys::Signing | Keys::Crypting | Keys::KeyDeriving));
    ASSERT_TRUE(keys_->InitTemporary());
  }
  ScopedTempDir temp_dir_;
  scoped_ptr<Keys> keys_;
};

TEST_F(TaoKeysTest, GenerateTempKeysTest) {
  EXPECT_TRUE(keys_->InitTemporary());
  EXPECT_TRUE(keys_->Verifier() != nullptr);
  EXPECT_TRUE(keys_->Signer() != nullptr);
  EXPECT_TRUE(keys_->Crypter() != nullptr);
  EXPECT_TRUE(keys_->KeyDeriver() != nullptr);
}

TEST_F(TaoKeysTest, GenerateNonHostedKeysTest) {
  keys_.reset(new Keys(*temp_dir_, "unittest",
                       Keys::Signing | Keys::Crypting | Keys::KeyDeriving));
  EXPECT_TRUE(keys_->InitNonHosted("unitpass"));
  EXPECT_TRUE(keys_->Verifier() != nullptr);
  EXPECT_TRUE(keys_->Signer() != nullptr);
  EXPECT_TRUE(keys_->Crypter() != nullptr);
  EXPECT_TRUE(keys_->KeyDeriver() != nullptr);
}

TEST_F(TaoKeysTest, GenerateHostedKeysTest) {
  keys_.reset(new Keys(*temp_dir_, "unittest",
                       Keys::Signing | Keys::Crypting | Keys::KeyDeriving));

  SoftTao tao;
  EXPECT_TRUE(tao.Init());

  string policy = Tao::SealPolicyDefault;
  EXPECT_TRUE(keys_->InitHosted(&tao, policy));
  EXPECT_TRUE(keys_->Verifier() != nullptr);
  EXPECT_TRUE(keys_->Signer() != nullptr);
  EXPECT_TRUE(keys_->Crypter() != nullptr);
  EXPECT_TRUE(keys_->KeyDeriver() != nullptr);
}

TEST_F(TaoKeysTest, SignVerifyDataTest) {
  string message("Test message");
  string context("Test context");
  string signature;
  ASSERT_TRUE(keys_->Sign(message, context, &signature))
      << "Could not sign the test message";
  EXPECT_TRUE(keys_->Verify(message, context, signature))
      << "The signature did not pass verification";
}

/*
TEST_F(TaoKeysTest, SerializeKeyTest) {
  string s;
  ASSERT_TRUE(keys_->SerializePublicKey(&s))  // serializes Signer
      << "Could not serialize the public key";

  scoped_ptr<keyczar::Verifier> public_key;
  ASSERT_TRUE(DeserializePublicKey(s, &public_key))
      << "Could not deserialize the public key";

  // Make sure this is really the public policy key by signing something with
  // the original key and verifying it with the deserialized version.
  string message("Test message");
  string context("Test context");
  string signature;
  ASSERT_TRUE(keys_->Sign(message, context, &signature))
      << "Could not sign the test message";
  EXPECT_TRUE(tao::VerifySignature(*public_key, message, context, signature))
      << "Deserialized key could not verify signature";

  // Serialize again to check serialization of Verifier (not Signer)
  string s2;
  ASSERT_TRUE(SerializePublicKey(*public_key, &s2));
  ASSERT_EQ(s, s2);
}
*/

TEST_F(TaoKeysTest, WrongContextTest) {
  string message("Test message");
  string context("Test context");
  string signature;
  ASSERT_TRUE(keys_->Sign(message, context, &signature))
      << "Could not sign the test message";
  EXPECT_FALSE(keys_->Verify(message, "Wrong context", signature))
      << "Signature with wrong context falsely verified";
}

TEST_F(TaoKeysTest, NoContextTest) {
  string message("Test message");
  string context;
  string signature;
  EXPECT_FALSE(keys_->Sign(message, context, &signature))
      << "Could not sign the test message";
}

TEST_F(TaoKeysTest, LoadKeysTest) {
  keys_.reset(new Keys(*temp_dir_, "unittest",
                       Keys::Signing | Keys::Crypting | Keys::KeyDeriving));
  ASSERT_TRUE(keys_->InitNonHosted("unitpass"));
  EXPECT_TRUE(keys_->HasFreshKeys());

  // sign something
  string message("Test message");
  string context("Test context");
  string signature;
  ASSERT_TRUE(keys_->Sign(message, context, &signature))
      << "Could not sign the test message";

  // crypt something
  string plaintext("Test message");
  string ciphertext, decrypted;
  EXPECT_TRUE(keys_->Crypter()->Encrypt(plaintext, &ciphertext));

  // derive a key
  string material;
  EXPECT_TRUE(keys_->DeriveKey("test", 20, &material));

  // reload then check everything
  keys_.reset(new Keys(*temp_dir_, "unittest",
                       Keys::Signing | Keys::Crypting | Keys::KeyDeriving));
  ASSERT_TRUE(keys_->InitNonHosted("unitpass"));
  EXPECT_TRUE(!keys_->HasFreshKeys());

  EXPECT_TRUE(keys_->Verify(message, context, signature))
      << "Loaded key did not verify signature";

  EXPECT_TRUE(keys_->Crypter()->Decrypt(ciphertext, &decrypted));
  EXPECT_EQ(plaintext, decrypted) << "Loaded key did not decrypt properly";

  string material2;
  EXPECT_TRUE(keys_->DeriveKey("test", 20, &material2));
  EXPECT_EQ(material, material2) << "Loaded key did derive key properly";
}

TEST_F(TaoKeysTest, CopyKeysTest) {
  // sign something
  string message("Test message");
  string context("Test context");
  string signature;
  ASSERT_TRUE(keys_->Sign(message, context, &signature))
      << "Could not sign the test message";

  // crypt something
  string plaintext("Test message");
  string ciphertext, decrypted;
  EXPECT_TRUE(keys_->Crypter()->Encrypt(plaintext, &ciphertext));

  // derive a key
  string material;
  EXPECT_TRUE(keys_->DeriveKey("test", 20, &material));

  // copy then check everything
  keys_.reset(keys_->DeepCopy());
  ASSERT_TRUE(keys_ != nullptr);

  EXPECT_TRUE(keys_->Verify(message, context, signature))
      << "Copied key did not verify signature";

  EXPECT_TRUE(keys_->Crypter()->Decrypt(ciphertext, &decrypted));
  EXPECT_EQ(plaintext, decrypted) << "Copied key did not decrypt properly";

  string material2;
  EXPECT_TRUE(keys_->DeriveKey("test", 20, &material2));
  EXPECT_EQ(material, material2) << "Copied key did derive key properly";
}
