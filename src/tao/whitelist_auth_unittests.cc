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

#include <stdlib.h>

#include <fstream>

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>

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

using tao::CreateKey;
using tao::CreatePubECDSAKey;
using tao::CreateTempDir;
using tao::CreateTempPubKey;
using tao::FakeTao;
using tao::HostedProgram;
using tao::WhitelistAuth;
using tao::ScopedTempDir;
using tao::SignedWhitelist;
using tao::Tao;
using tao::Whitelist;

class WhitelistAuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempPubKey(&temp_dir_, &policy_key_))
      << "Could not create a temporary public key";

    policy_pk_path_ = *temp_dir_ + string("/policy_pk");
    fake_tao_.reset(new FakeTao(policy_pk_path_));
    ASSERT_TRUE(fake_tao_->Init())
      << "Could not initialize the fake tao";

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
  FakeTao ft(policy_pk_path_);
  EXPECT_TRUE(ft.Init()) << "Could not init the FakeTao";
  string hash("Test hash 2");

  string data("test data");
  string attestation;
  EXPECT_TRUE(ft.Attest(hash, data, &attestation)) << "Could not attest";

  string output_data;
  EXPECT_TRUE(whitelist_auth_->VerifyAttestation(attestation, &output_data))
    << "The generated attestation did not pass verification";
}
