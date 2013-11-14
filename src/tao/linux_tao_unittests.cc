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

#include "tao/direct_tao_channel.h"
#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/hosted_program_factory.h"
#include "tao/linux_tao.h"
#include "tao/pipe_tao_channel.h"
#include "tao/pipe_tao_channel_factory.h"
#include "tao/process_factory.h"
#include "tao/util.h"
#include "gtest/gtest.h"

#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_file_reader.h>

#include <stdlib.h>

#include <fstream>

using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::Signer;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetWriter;

using std::ofstream;

using tao::CreateKey;
using tao::DirectTaoChannel;
using tao::FakeTao;
using tao::HostedProgramFactory;
using tao::LinuxTao;
using tao::PipeTaoChannelFactory;
using tao::ProcessFactory;
using tao::SignedWhitelist;
using tao::Tao;
using tao::TaoChannelFactory;
using tao::Whitelist;


class LinuxTaoTest : public ::testing::Test {
protected:
  virtual void SetUp() {
    scoped_ptr<FakeTao> ft(new FakeTao());
    ASSERT_TRUE(ft->Init()) << "Could not init the FakeTao";

    scoped_ptr<DirectTaoChannel> channel(new DirectTaoChannel(ft.release()));
    ASSERT_TRUE(channel->Init()) << "Could not init the channel";

    scoped_ptr<HostedProgramFactory> program_factory(new ProcessFactory());
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
    
    // create the policy key
    FilePath fp(policy_pk_path);
    scoped_ptr<KeysetWriter> policy_pk_writer(new KeysetJSONFileWriter(fp));
    ASSERT_TRUE(CreateKey(policy_pk_writer.get(), KeyType::ECDSA_PRIV, KeyPurpose::SIGN_AND_VERIFY, "policy_pk", &policy_key_));
    
    // Create an empty whitelist, since we don't want the LinuxTao to
    // start any hosted programs during this test. Then write it to
    // the temp filename above.
    Whitelist w;
    SignedWhitelist sw;
    string *serialized_whitelist = sw.mutable_serialized_whitelist();
    ASSERT_TRUE(w.SerializeToString(serialized_whitelist));

    string *signature = sw.mutable_signature();
    ASSERT_TRUE(policy_key_->Sign(*serialized_whitelist, signature));

    ofstream whitelist_file(whitelist_path.c_str(), ofstream::out);
    ASSERT_TRUE(sw.SerializeToOstream(&whitelist_file));

    tao_.reset(new LinuxTao(secret_path, key_path, pk_path, whitelist_path, policy_pk_path,
			    channel.release(), channel_factory.release(), program_factory.release()));
    ASSERT_TRUE(tao_->Init());
  }

  // TODO(tmroeder): clean up the temporary directory of keys and
  // secrets. Use TearDown and recursively delete all the files.

  string dir_;
  scoped_ptr<LinuxTao> tao_;
  scoped_ptr<Keyczar> policy_key_;
};

TEST_F(LinuxTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_->GetRandomBytes(10, &bytes));
  EXPECT_TRUE(tao_->GetRandomBytes(0, &bytes));
}
