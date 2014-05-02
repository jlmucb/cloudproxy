//  File: pipe_tao_channel_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic PipeTaoChannel with a fake Tao
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
#include "tao/pipe_tao_channel.h"

#include <list>
#include <string>
#include <thread>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/base64w.h>

#include "tao/fake_tao.h"
#include "tao/pipe_tao_channel_params.pb.h"
#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/unix_domain_socket_tao_admin_channel.h"
#include "tao/unix_fd_tao_child_channel.h"
#include "tao/util.h"

using std::thread;

using tao::CreateTempDir;
using tao::FakeTao;
using tao::PipeTaoChannel;
using tao::PipeTaoChannelParams;
using tao::ScopedFd;
using tao::ScopedTempDir;
using tao::Tao;
using tao::TaoChildChannelParams;
using tao::UnixDomainSocketTaoAdminChannel;
using tao::UnixFdTaoChildChannel;

class PipeTaoChannelTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("pipe_tao_channel_test", &temp_dir_));

    domain_socket_ = *temp_dir_ + "/domain_socket";

    // Get pipes from the PipeTaoChannel.
    tao_channel_.reset(new PipeTaoChannel(domain_socket_));
    ASSERT_TRUE(tao_channel_->Init()) << "Could not set up the channel";

    tao_.reset(new FakeTao());
    ASSERT_TRUE(tao_->InitTemporaryTPM()) << "Could not initialize the Tao";

    string child_name("Fake hash");
    string params;
    ASSERT_TRUE(tao_channel_->AddChildChannel(child_name, &params))
        << "Could not add a child to the channel";

    // Take apart the params to get the pipes for the child.
    TaoChildChannelParams tccp;
    ASSERT_TRUE(tccp.ParseFromString(params)) << "Could not parse the params";
    PipeTaoChannelParams ptcp;
    ASSERT_TRUE(ptcp.ParseFromString(tccp.params()))
        << "Could not get the pipes";

    readfd_.reset(new int(ptcp.readfd()));
    writefd_.reset(new int(ptcp.writefd()));

    // The listening thread will continue until sent a stop message.
    listener_.reset(
        new thread(&PipeTaoChannel::Listen, tao_channel_.get(), tao_.get()));

    child_channel_.reset(new UnixFdTaoChildChannel(*readfd_, *writefd_));
  }

  virtual void TearDown() {
    scoped_ptr<UnixDomainSocketTaoAdminChannel> chan(
        new UnixDomainSocketTaoAdminChannel(domain_socket_));
    ASSERT_TRUE(chan->Init());
    ASSERT_TRUE(chan->Shutdown());
    if (listener_->joinable()) {
      listener_->join();
    }
  }

  ScopedFd readfd_;
  ScopedFd writefd_;
  ScopedTempDir temp_dir_;
  scoped_ptr<FakeTao> tao_;
  scoped_ptr<PipeTaoChannel> tao_channel_;
  scoped_ptr<thread> listener_;
  string domain_socket_;
  scoped_ptr<UnixFdTaoChildChannel> child_channel_;
};

TEST_F(PipeTaoChannelTest, CreationTest) {
  scoped_ptr<UnixDomainSocketTaoAdminChannel> chan(
      new UnixDomainSocketTaoAdminChannel(domain_socket_));
  ASSERT_TRUE(chan->Init());
  string path = "/fake/program";
  list<string> args;
  string child_name;
  ASSERT_TRUE(chan->StartHostedProgram(path, args, &child_name));
}

TEST_F(PipeTaoChannelTest, RandomTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(16, &bytes))
      << "Could not get random bytes from the host tao";
}

TEST_F(PipeTaoChannelTest, SealTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(child_channel_->Seal(bytes, Tao::PolicySameProgHash, &sealed));
}

TEST_F(PipeTaoChannelTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(child_channel_->Seal(bytes, Tao::PolicySameProgHash, &sealed));

  string unsealed;
  int policy;
  EXPECT_TRUE(child_channel_->Unseal(sealed, &unsealed, &policy));

  EXPECT_EQ(bytes, unsealed);
  EXPECT_TRUE(policy == Tao::PolicySameProgHash);
}

TEST_F(PipeTaoChannelTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string attestation;
  EXPECT_TRUE(child_channel_->Attest(bytes, &attestation));
}
