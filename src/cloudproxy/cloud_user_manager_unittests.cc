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

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/util.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using keyczar::Verifier;
using keyczar::base::ReadFileToString;

using cloudproxy::CloudUserManager;
using cloudproxy::SignedSpeaksFor;
using tao::CreateTempACLsDomain;
using tao::Keys;
using tao::ScopedTempDir;
using tao::TaoDomain;

class CloudUserManagerTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempACLsDomain(&temp_dir_, &admin_));

    // Create two users and matching delegations.
    string u;
    string users_path = *temp_dir_ + "/users";

    u = "tmr";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &tmr_key_));
    string tmr_ssf_path =
        tmr_key_->GetPath(CloudUserManager::UserDelegationSuffix);
    ASSERT_TRUE(tmr_key_->SerializePublicKey(&tmr_serialized_key_));
    string serialized_ssf;
    ASSERT_TRUE(ReadFileToString(tmr_ssf_path, &serialized_ssf));
    ASSERT_TRUE(tmr_ssf_.ParseFromString(serialized_ssf));

    u = "jlm";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &jlm_key_));
  }

  ScopedTempDir temp_dir_;
  scoped_ptr<TaoDomain> admin_;
  CloudUserManager manager_;
  SignedSpeaksFor tmr_ssf_;
  string tmr_serialized_key_;
  scoped_ptr<Keys> tmr_key_;
  scoped_ptr<Keys> jlm_key_;
};

TEST_F(CloudUserManagerTest, UserKeyTest) {
  string username("tmr");
  EXPECT_FALSE(manager_.HasKey(username));
  Verifier *k = nullptr;
  EXPECT_FALSE(manager_.GetKey(username, &k));
  EXPECT_TRUE(manager_.AddSigningKey(username, *tmr_key_->Signer()));
  EXPECT_TRUE(manager_.HasKey(username));
  EXPECT_TRUE(manager_.GetKey(username, &k));

  string username2("jlm");
  EXPECT_FALSE(manager_.HasKey(username2));
  EXPECT_TRUE(manager_.AddSigningKey(username2, *jlm_key_->Signer()));
  EXPECT_TRUE(manager_.HasKey(username2));
}

TEST_F(CloudUserManagerTest, SerializedKeyTest) {
  string username("tmr");
  EXPECT_TRUE(manager_.AddKey(username, tmr_serialized_key_));
  EXPECT_TRUE(manager_.HasKey(username));
  Verifier *k = nullptr;
  EXPECT_TRUE(manager_.GetKey(username, &k));
}

TEST_F(CloudUserManagerTest, SignedSpeaksForTest) {
  string username("tmr");
  EXPECT_TRUE(manager_.AddKey(tmr_ssf_, admin_->GetPolicyVerifier()));
  EXPECT_TRUE(manager_.HasKey(username));
  Verifier *k = nullptr;
  EXPECT_TRUE(manager_.GetKey(username, &k));
}

TEST_F(CloudUserManagerTest, AuthenticatedTest) {
  string username("tmr");
  EXPECT_FALSE(manager_.IsAuthenticated(username));
  manager_.SetAuthenticated(username);
  EXPECT_TRUE(manager_.IsAuthenticated(username));
}
