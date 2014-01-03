//  File: root_auth_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Basic tests for the RootAuth class.
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

#include <stdlib.h>

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>

#include "tao/fake_tao.h"
#include "tao/root_auth.h"
#include "tao/util.h"

using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::rw::KeysetWriter;
using keyczar::rw::KeysetJSONFileWriter;

using tao::CreateKey;
using tao::FakeTao;
using tao::RootAuth;
using tao::ScopedTempDir;

class RootAuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Get a temporary directory to use for the files.
    string dir_template("/tmp/root_auth_test_XXXXXX");
    scoped_array<char> temp_name(new char[dir_template.size() + 1]);
    memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

    ASSERT_TRUE(mkdtemp(temp_name.get()));
    temp_dir_.reset(new string(temp_name.get()));

    // Create a key in this directory: us it as our fake public key.
    policy_pk_path_ = *temp_dir_ + "/policy_pk";

    // Create the policy key directory so it can be filled by keyczar.
    ASSERT_EQ(mkdir(policy_pk_path_.c_str(), 0700), 0);

    // create the policy key
    FilePath fp(policy_pk_path_);
    scoped_ptr<KeysetWriter> policy_pk_writer(new KeysetJSONFileWriter(fp));
    ASSERT_TRUE(
        CreateKey(policy_pk_writer.get(), KeyType::ECDSA_PRIV,
                  KeyPurpose::SIGN_AND_VERIFY, "policy_pk", &policy_key_));
    policy_key_->set_encoding(Keyczar::NO_ENCODING);

    root_auth_.reset(new RootAuth(policy_pk_path_));
    ASSERT_TRUE(root_auth_->Init()) << "Could not init RootAuth";
  }

  ScopedTempDir temp_dir_;
  scoped_ptr<Keyczar> policy_key_;
  scoped_ptr<RootAuth> root_auth_;
  string policy_pk_path_;
};

TEST_F(RootAuthTest, FailIsAuthorizedProgram) {
  EXPECT_FALSE(root_auth_->IsAuthorized("test program"));
}

TEST_F(RootAuthTest, FailIsAuthorizedProgramAndHash) {
  EXPECT_FALSE(root_auth_->IsAuthorized("test program", "test hash"));
}

TEST_F(RootAuthTest, VerifyTest) {
  // Create an attestation for a program, and check that it passes verification.
  FakeTao ft(policy_pk_path_);
  EXPECT_TRUE(ft.Init()) << "Could not init the FakeTao";
  string hash("test hash");

  string data("test program");
  string attestation;
  EXPECT_TRUE(ft.Attest(hash, data, &attestation)) << "Could not attest";

  string output_data;
  EXPECT_TRUE(root_auth_->VerifyAttestation(attestation, &output_data))
    << "The generated attestation did not pass verification";

  EXPECT_EQ(output_data, data) << "The extracted data did not match";
}
