//  File: linux_tao_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic LinuxTao functionality
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
#include "tao/linux_tao.h"
#include "tao/direct_tao_channel.h"
#include "gtest/gtest.h"

#include <stdlib.h>

using tao::FakeTao;
using tao::LinuxTao;
using tao::DirectTaoChannel;

class LinuxTaoTest : public ::testing::Test {
protected:
  virtual void SetUp() {
    scoped_ptr<FakeTao> ft(new FakeTao());
    ASSERT_TRUE(ft->Init()) << "Could not init the FakeTao";

    scoped_ptr<DirectTaoChannel> channel(new DirectTaoChannel(ft.release()));
    ASSERT_TRUE(channel_->Init()) << "Could not init the channel";

    scoped_ptr<HostedProgramFactory> process_factory(new ProcessFactory());
    scoped_ptr<TaoChannelFactory> channel_factory(new PipeTaoChannelFactory());

    // get a temporary directory to use for the files
    string dir_template("/tmp/linux_tao_test_XXXXXX");
    scoped_array<char> temp_name(new char[dir_template.size() + 1]);
    memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

    ASSERT_TRUE(mkdtemp(temp_name.get()));
    dir_ = temp_name.get();
      

    string secret_path = dir_ + "/linux_tao_secret";
    string key_path = dir_ + "/linux_tao_secret_key";
    string pk_path = dir_ + "/linux_tao_pk";
    string whitelist_path = dir_ + "/whitelist";
    string policy_pk_path = dir_ + "/policy_pk";
    
    // create the whitelist and the policy key

    //tao_.reset(new LinuxTao(
  }

  virtual 

  string dir_;
  scoped_ptr<LinuxTao> tao_;
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
  EXPECT_TRUE(tao_.Seal(bytes, &sealed));
}

TEST_F(FakeTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(tao_.Seal(bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(tao_.Unseal(sealed, &unsealed));

  EXPECT_EQ(bytes, unsealed);
}  

TEST_F(FakeTaoTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  
  string attestation;
  EXPECT_TRUE(tao_.Attest(bytes, &attestation));
}

TEST_F(FakeTaoTest, VerifyAttestTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  
  string attestation;
  EXPECT_TRUE(tao_.Attest(bytes, &attestation));

  string data;
  EXPECT_TRUE(tao_.VerifyAttestation(attestation, &data));

  EXPECT_EQ(data, bytes);
}
