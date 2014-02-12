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

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/attestation.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using tao::ScopedTempDir;
using tao::TaoAuth;
using tao::TaoDomain;

class RootAuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(tao::CreateTempRootDomain(&temp_dir_, &admin_));
  }

  scoped_ptr<TaoDomain> admin_;
  ScopedTempDir temp_dir_;
};

TEST_F(RootAuthTest, FailIsAuthorizedProgram) {
  EXPECT_FALSE(admin_->IsAuthorized("test hash", TaoAuth::FakeHash, nullptr));
}

TEST_F(RootAuthTest, FailIsAuthorizedProgramAndHash) {
  EXPECT_FALSE(admin_->IsAuthorized("test hash", TaoAuth::FakeHash, "pgm"));
}

TEST_F(RootAuthTest, VerifyTest) {
  // Create an attestation for a program, and check that it passes verification.
  tao::Statement s;
  s.set_data("test program");
  s.set_hash_alg(TaoAuth::FakeHash);
  s.set_hash("test hash");
  string attestation;
  ASSERT_TRUE(admin_->AttestByRoot(&s, &attestation));

  string output_data;
  EXPECT_TRUE(admin_->VerifyAttestation(attestation, &output_data))
      << "The generated attestation did not pass verification";

  EXPECT_EQ(output_data, "test program") << "The extracted data did not match";
}
