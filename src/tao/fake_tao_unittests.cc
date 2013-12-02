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
#include <keyczar/keyczar.h>

#include "tao/fake_tao.h"

using tao::FakeTao;

class FakeTaoTest : public ::testing::Test {
 protected:
  virtual void SetUp() { ASSERT_TRUE(tao_.Init()); }

  FakeTao tao_;
};

TEST_F(FakeTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_.GetRandomBytes(10, &bytes));
  EXPECT_TRUE(tao_.GetRandomBytes(0, &bytes));
}

TEST_F(FakeTaoTest, SealTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(tao_.Seal(bytes, bytes, &sealed));
}

TEST_F(FakeTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(tao_.Seal(bytes, bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(tao_.Unseal(bytes, sealed, &unsealed));

  EXPECT_EQ(bytes, unsealed);
}

TEST_F(FakeTaoTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));

  string attestation;
  EXPECT_TRUE(tao_.Attest(bytes, bytes, &attestation));
}

GTEST_API_ int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
