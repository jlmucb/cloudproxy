//  File: cloud_user_manager_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Unit tests for CloudUserManager.
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

#include <fstream>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/file_util.h>

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/util.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::ofstream;

using keyczar::Signer;
using keyczar::Verifier;
using keyczar::base::ReadFileToString;

using cloudproxy::CloudUserManager;
using cloudproxy::SignedSpeaksFor;
using tao::CreateTempWhitelistDomain;
using tao::ScopedTempDir;
using tao::TaoDomain;
using tao::Keys;

class CloudUserManagerTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempWhitelistDomain(&temp_dir_, &admin_));

    // Create two users and matching delegations.
    scoped_ptr<Keys> key;
    string u; 
    string users_path = *temp_dir_ + "/users";

    u = "tmroeder";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &key));
    tmroeder_key_path_ = key->SigningPrivateKeyPath();
    string tmroeder_ssf_path = key->GetPath(CloudUserManager::UserDelegationSuffix);
    ASSERT_TRUE(key->SerializePublicKey(&tmroeder_serialized_key_));
    string serialized_ssf;
    ASSERT_TRUE(ReadFileToString(tmroeder_ssf_path, &serialized_ssf));
    ASSERT_TRUE(tmroeder_ssf_.ParseFromString(serialized_ssf));

    u = "jlm";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &key));
    jlm_key_path_ = key->SigningPrivateKeyPath();
  }

  ScopedTempDir temp_dir_;
  scoped_ptr<TaoDomain> admin_;
  CloudUserManager manager_;
  SignedSpeaksFor tmroeder_ssf_;
  string tmroeder_serialized_key_;
  string tmroeder_key_path_;
  string jlm_key_path_;
};

TEST_F(CloudUserManagerTest, UserKeyTest) {
  string username("tmroeder");
  EXPECT_FALSE(manager_.HasKey(username));
  Verifier *k = nullptr;
  EXPECT_FALSE(manager_.GetKey(username, &k));
  EXPECT_TRUE(manager_.AddSigningKey(username, tmroeder_key_path_, username));
  EXPECT_TRUE(manager_.HasKey(username));
  EXPECT_TRUE(manager_.GetKey(username, &k));

  string username2("jlm");
  EXPECT_FALSE(manager_.HasKey(username2));
  EXPECT_TRUE(manager_.AddSigningKey(username2, jlm_key_path_, username2));
  EXPECT_TRUE(manager_.HasKey(username2));
}

TEST_F(CloudUserManagerTest, SerializedKeyTest) {
  string username("tmroeder");
  EXPECT_TRUE(manager_.AddKey(username, tmroeder_serialized_key_));
  EXPECT_TRUE(manager_.HasKey(username));
  Verifier *k = nullptr;
  EXPECT_TRUE(manager_.GetKey(username, &k));
}

TEST_F(CloudUserManagerTest, SignedSpeaksForTest) {
  string username("tmroeder");
  EXPECT_TRUE(manager_.AddKey(tmroeder_ssf_, admin_->GetPolicyVerifier()));
  EXPECT_TRUE(manager_.HasKey(username));
  Verifier *k = nullptr;
  EXPECT_TRUE(manager_.GetKey(username, &k));
}

TEST_F(CloudUserManagerTest, AuthenticatedTest) {
  string username("tmroeder");
  EXPECT_FALSE(manager_.IsAuthenticated(username));
  manager_.SetAuthenticated(username);
  EXPECT_TRUE(manager_.IsAuthenticated(username));
}
