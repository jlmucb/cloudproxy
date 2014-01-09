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

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/util.h"
#include "tao/util.h"

using cloudproxy::CloudUserManager;
using cloudproxy::CreateUserECDSAKey;
using cloudproxy::SignedSpeaksFor;
using cloudproxy::SpeaksFor;
using keyczar::Keyczar;
using std::ofstream;
using tao::CreateTempPubKey;
using tao::KeyczarPublicKey;
using tao::ScopedTempDir;
using tao::SignData;

class CloudUserManagerTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempPubKey(&temp_dir_, &policy_key_))
        << "Could not create a policy key";

    // Create a user and set up the SignedSpeaksFor for this user.
    string username = "tmroeder";
    scoped_ptr<Keyczar> tmroeder_key;
    tmroeder_key_path_ = *temp_dir_ + string("/") + username;
    ASSERT_EQ(mkdir(tmroeder_key_path_.c_str(), 0700), 0);
    SpeaksFor sf;
    sf.set_subject(username);
    // For these simple tests, we use the username as the password. Very secure.
    EXPECT_TRUE(CreateUserECDSAKey(tmroeder_key_path_, username, username,
                                   &tmroeder_key));

    KeyczarPublicKey kpk;
    EXPECT_TRUE(SerializePublicKey(*tmroeder_key, &kpk));
    string *sf_key = sf.mutable_pub_key();
    EXPECT_TRUE(kpk.SerializeToString(sf_key));
    tmroeder_serialized_key_ = *sf_key;

    string *sf_serialized = ssf.mutable_serialized_speaks_for();
    EXPECT_TRUE(sf.SerializeToString(sf_serialized));

    string *sf_sig = ssf.mutable_signature();
    EXPECT_TRUE(SignData(*sf_serialized,
                         CloudUserManager::SpeaksForSigningContext, sf_sig,
                         policy_key_.get()));

    tmroeder_ssf_path_ = *temp_dir_ + string("/tmroeder_ssf");
    ofstream ssf_file(tmroeder_ssf_path_.c_str());
    ASSERT_TRUE(ssf_file);
    EXPECT_TRUE(ssf.SerializeToOstream(&ssf_file));
    ssf_file.close();

    // Create a second user and set up the SignedSpeaksFor for this user.
    string username2 = "jlm";
    scoped_ptr<Keyczar> jlm_key;
    jlm_key_path_ = *temp_dir_ + string("/") + username2;
    ASSERT_EQ(mkdir(jlm_key_path_.c_str(), 0700), 0);
    SpeaksFor sf2;
    sf2.set_subject(username2);
    // For these simple tests, we use the username as the password. Very secure.
    EXPECT_TRUE(CreateUserECDSAKey(jlm_key_path_, username2, username2,
                                   &jlm_key));

    KeyczarPublicKey kpk2;
    EXPECT_TRUE(SerializePublicKey(*jlm_key, &kpk2));
    string *sf_key2 = sf2.mutable_pub_key();
    EXPECT_TRUE(kpk2.SerializeToString(sf_key2));
    jlm_serialized_key_ = *sf_key2;

    string *sf_serialized2 = ssf2.mutable_serialized_speaks_for();
    EXPECT_TRUE(sf2.SerializeToString(sf_serialized2));

    string *sf_sig2 = ssf2.mutable_signature();
    EXPECT_TRUE(SignData(*sf_serialized2,
                         CloudUserManager::SpeaksForSigningContext, sf_sig2,
                         policy_key_.get()));

    jlm_ssf_path_ = *temp_dir_ + string("/jlm_ssf");
    ofstream ssf_file2(jlm_ssf_path_.c_str());
    ASSERT_TRUE(ssf_file2);
    EXPECT_TRUE(ssf2.SerializeToOstream(&ssf_file2));
    ssf_file2.close();
  }

  ScopedTempDir temp_dir_;
  scoped_ptr<Keyczar> policy_key_;
  CloudUserManager manager_;
  SignedSpeaksFor ssf;
  SignedSpeaksFor ssf2;
  string tmroeder_serialized_key_;
  string tmroeder_key_path_;
  string tmroeder_ssf_path_;
  string jlm_serialized_key_;
  string jlm_key_path_;
  string jlm_ssf_path_;
};

TEST_F(CloudUserManagerTest, UserKeyTest) {
  string username("tmroeder");
  EXPECT_FALSE(manager_.HasKey(username));
  Keyczar *k = nullptr;
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
  Keyczar *k = nullptr;
  EXPECT_TRUE(manager_.GetKey(username, &k));
}

TEST_F(CloudUserManagerTest, SignedSpeaksForTest) {
  string username("tmroeder");
  EXPECT_TRUE(manager_.AddKey(ssf, policy_key_.get()));
  EXPECT_TRUE(manager_.HasKey(username));
  Keyczar *k = nullptr;
  EXPECT_TRUE(manager_.GetKey(username, &k));
}

TEST_F(CloudUserManagerTest, AuthenticatedTest) {
  string username("tmroeder");
  EXPECT_FALSE(manager_.IsAuthenticated(username));
  manager_.SetAuthenticated(username);
  EXPECT_TRUE(manager_.IsAuthenticated(username));
}
