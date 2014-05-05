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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/values.h>

#include "tao/direct_tao_child_channel.h"
#include "tao/fake_program_factory.h"
#include "tao/fake_tao.h"
#include "tao/fake_tao_channel.h"
#include "tao/hosted_program_factory.h"
#include "tao/hosted_programs.pb.h"
#include "tao/linux_tao.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using keyczar::base::Base64WEncode;

using tao::DirectTaoChildChannel;
using tao::FakeProgramFactory;
using tao::FakeTao;
using tao::FakeTaoChannel;
using tao::HostedProgramFactory;
using tao::LinuxTao;
using tao::ScopedTempDir;
using tao::Sha256FileHash;
using tao::Tao;
using tao::TaoAuth;
using tao::TaoChannel;
using tao::TaoDomain;

DECLARE_string(program);  // defined in process_factory_unittests.cc

class LinuxTaoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    scoped_ptr<TaoDomain> admin;
    ASSERT_TRUE(tao::CreateTempWhitelistDomain(&temp_dir_, &admin));

    admin->GetConfig()->SetString(TaoDomain::JSONTaoCAHost, "");
    admin->SaveConfig();

    // Set up the files for the test.
    string keys_path = *temp_dir_ + "/linux_tao_keys";

    test_binary_path_ = FLAGS_program;

    string test_binary_proghash, test_binary_progdigest;
    ASSERT_TRUE(Sha256FileHash(test_binary_path_, &test_binary_proghash));
    Base64WEncode(test_binary_proghash, &test_binary_progdigest);
    string test_binary_argdigest =
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    test_binary_name_ = "Program(1, \"" + test_binary_path_ + "\", \"" +
                        test_binary_progdigest + "\", \"" +
                        test_binary_argdigest + "\")";

    scoped_ptr<FakeTao> ft(new FakeTao());
    ASSERT_TRUE(ft->InitTemporaryTPM()) << "Could not init the FakeTao";

    ft->GetTaoFullName(&fake_tao_name_);

    string fake_linux_tao_hash("PCRs(\"fake\")");
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

    tao_.reset(new LinuxTao(keys_path, channel.release(),
                            child_channel.release(), program_factory.release(),
                            admin.release()));
    ASSERT_TRUE(tao_->Init());
  }

  ScopedTempDir temp_dir_;
  string test_binary_path_;
  string test_binary_name_;
  scoped_ptr<LinuxTao> tao_;
  string fake_tao_name_;
};

TEST_F(LinuxTaoTest, FullNameTest) {
  string tao_name;
  EXPECT_TRUE(tao_->GetTaoFullName(&tao_name));
  EXPECT_TRUE(tao_name.length() > fake_tao_name_.length() + 2);
  EXPECT_EQ(fake_tao_name_, tao_name.substr(0, fake_tao_name_.length()));
  EXPECT_EQ("::", tao_name.substr(fake_tao_name_.length(), 2));
}

TEST_F(LinuxTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 10, &bytes));
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 0, &bytes));
}

TEST_F(LinuxTaoTest, FailSealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));
  string sealed;
  string fake_hash("[This is also not a hash]");
  EXPECT_FALSE(tao_->Seal(fake_hash, bytes, Tao::PolicySameProgHash, &sealed));
}

TEST_F(LinuxTaoTest, FailUnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));

  string unsealed;
  string fake_hash("[This is also not a hash]");
  int policy;
  EXPECT_FALSE(tao_->Unseal(fake_hash, bytes, &unsealed, &policy));
}

TEST_F(LinuxTaoTest, FailAttestTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));

  string attestation;
  string fake_hash("[This is also not a hash]");
  EXPECT_FALSE(tao_->Attest(fake_hash, bytes, &attestation));
}

TEST_F(LinuxTaoTest, SealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));

  list<string> args;
  string child_name;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args, &child_name));

  EXPECT_TRUE(!child_name.empty());

  string sealed;
  EXPECT_TRUE(
      tao_->Seal(test_binary_name_, bytes, Tao::PolicySameProgHash, &sealed));
}

TEST_F(LinuxTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));

  list<string> args;
  string child_name;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args, &child_name));

  EXPECT_TRUE(!child_name.empty());

  string sealed;
  EXPECT_TRUE(
      tao_->Seal(test_binary_name_, bytes, Tao::PolicySameProgHash, &sealed));

  string unsealed;
  int policy;
  EXPECT_TRUE(tao_->Unseal(test_binary_name_, sealed, &unsealed, &policy));
  EXPECT_EQ(unsealed, bytes);
  EXPECT_TRUE(policy == Tao::PolicySameProgHash);
}

TEST_F(LinuxTaoTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes("fake hash", 128, &bytes));

  list<string> args;
  string child_name;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args, &child_name));
  EXPECT_TRUE(!child_name.empty());

  string attestation;
  EXPECT_TRUE(tao_->Attest(test_binary_name_, bytes, &attestation));
}
