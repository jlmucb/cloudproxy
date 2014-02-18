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

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/file_util.h>

#include "tao/direct_tao_child_channel.h"
#include "tao/fake_program_factory.h"
#include "tao/fake_tao.h"
#include "tao/fake_tao_channel.h"
#include "tao/hosted_program_factory.h"
#include "tao/hosted_programs.pb.h"
#include "tao/linux_tao.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using keyczar::base::WriteStringToFile;

using tao::DirectTaoChildChannel;
using tao::FakeProgramFactory;
using tao::FakeTao;
using tao::FakeTaoChannel;
using tao::HostedProgramFactory;
using tao::LinuxTao;
using tao::ScopedTempDir;
using tao::TaoAuth;
using tao::TaoChannel;
using tao::TaoDomain;

class LinuxTaoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    scoped_ptr<TaoDomain> admin;
    ASSERT_TRUE(tao::CreateTempWhitelistDomain(&temp_dir_, &admin));

    admin->GetConfig()->SetString(TaoDomain::JSONTaoCAHost, "");
    admin->SaveConfig();

    // Set up the files for the test.
    string keys_path = *temp_dir_ + "/linux_tao_keys";

    test_binary_path_ = *temp_dir_ + "/test_binary";
    string test_binary_contents = "This is a fake test binary to be hashed\n";
    test_binary_digest_ = "IMCalSHSXc41HN-roIPa9wIl5vXA1wVxLHRXceb-Scc";
    ASSERT_TRUE(WriteStringToFile(test_binary_path_, test_binary_contents));

    scoped_ptr<FakeTao> ft(new FakeTao());
    ASSERT_TRUE(ft->Init()) << "Could not init the FakeTao";

    string fake_linux_tao_hash("This is not a real hash");
    scoped_ptr<DirectTaoChildChannel> channel(
        new DirectTaoChildChannel(ft.release(), fake_linux_tao_hash));
    ASSERT_TRUE(channel->Init()) << "Could not init the channel";

    scoped_ptr<HostedProgramFactory> program_factory(new FakeProgramFactory());
    scoped_ptr<TaoChannel> child_channel(new FakeTaoChannel());
    ASSERT_TRUE(child_channel->Init());

    // Create a whitelist with a dummy hosted program, since we don't want the
    // LinuxTao to start any hosted programs during this test.
    ASSERT_TRUE(admin->AuthorizeProgram(test_binary_path_));
    ASSERT_TRUE(
        admin->Authorize(fake_linux_tao_hash, TaoAuth::FakeHash, "LinuxTao"));

    tao_.reset(
        new LinuxTao(keys_path, channel.release(), child_channel.release(),
                     program_factory.release(), admin.release()));
    ASSERT_TRUE(tao_->Init());
  }

  ScopedTempDir temp_dir_;
  string test_binary_path_;
  string test_binary_digest_;
  string child_hash_;
  scoped_ptr<LinuxTao> tao_;
};

TEST_F(LinuxTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_->GetRandomBytes(10, &bytes));
  EXPECT_TRUE(tao_->GetRandomBytes(0, &bytes));
}

TEST_F(LinuxTaoTest, FailSealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));
  string sealed;
  string fake_hash("[This is also not a hash]");
  EXPECT_FALSE(tao_->Seal(fake_hash, bytes, &sealed));
}

TEST_F(LinuxTaoTest, FailUnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  string unsealed;
  string fake_hash("[This is also not a hash]");
  EXPECT_FALSE(tao_->Unseal(fake_hash, bytes, &unsealed));
}

TEST_F(LinuxTaoTest, FailAttestTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  string attestation;
  string fake_hash("[This is also not a hash]");
  EXPECT_FALSE(tao_->Attest(fake_hash, bytes, &attestation));
}

TEST_F(LinuxTaoTest, SealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  list<string> args;
  string identifier;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args, &identifier));

  EXPECT_TRUE(!identifier.empty());

  string sealed;
  EXPECT_TRUE(tao_->Seal(test_binary_digest_, bytes, &sealed));
}

TEST_F(LinuxTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  list<string> args;
  string identifier;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args, &identifier));

  EXPECT_TRUE(!identifier.empty());

  string sealed;
  EXPECT_TRUE(tao_->Seal(test_binary_digest_, bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(tao_->Unseal(test_binary_digest_, sealed, &unsealed));
  EXPECT_EQ(unsealed, bytes);
}

TEST_F(LinuxTaoTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  list<string> args;
  string identifier;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args, &identifier));
  EXPECT_TRUE(!identifier.empty());

  string attestation;
  EXPECT_TRUE(tao_->Attest(test_binary_digest_, bytes, &attestation));
}
