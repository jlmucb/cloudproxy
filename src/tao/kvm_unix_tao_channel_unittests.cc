//  File: kvm_unix_tao_channel_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic KvmUnixTaoChannel with a fake Tao
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
#include "tao/kvm_unix_tao_channel.h"

#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>

#include <list>
#include <string>
#include <thread>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/base64w.h>

#include "tao/fake_tao.h"
#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"
#include "tao/unix_domain_socket_tao_admin_channel.h"
#include "tao/unix_fd_tao_child_channel.h"
#include "tao/util.h"

using std::list;
using std::string;
using std::thread;

using tao::CreateTempDir;
using tao::FakeTao;
using tao::KvmUnixTaoChannel;
using tao::ScopedFd;
using tao::ScopedTempDir;
using tao::UnixDomainSocketTaoAdminChannel;
using tao::UnixFdTaoChildChannel;

class KvmUnixTaoChannelTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("kvm_unix_tao_test", &temp_dir_));

    domain_socket_ = *temp_dir_ + "/domain_socket";

    // Pass the channel a /dev/pts entry that you can talk to and pretend to be
    // the Tao communicating with it.
    master_fd_.reset(new int(-1));
    *master_fd_ = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    ASSERT_NE(*master_fd_, -1) << "Could not open a new psuedo-terminal";

    // Prepare the child pts to be opened.
    ASSERT_EQ(grantpt(*master_fd_), 0) << "Could not grant permissions for pts";
    ASSERT_EQ(unlockpt(*master_fd_), 0) << "Could not unlock the pts";

    // Set the pty into raw mode so it doesn't echo the characters.
    struct termios t;
    tcgetattr(*master_fd_, &t);
    cfmakeraw(&t);
    tcsetattr(*master_fd_, TCSANOW, &t);

    char *child_path = ptsname(*master_fd_);
    ASSERT_NE(child_path, nullptr) << "Could not get the name of the child pts";

    string child_pts(child_path);

    tao_channel_.reset(new KvmUnixTaoChannel(domain_socket_));
    ASSERT_TRUE(tao_channel_->Init()) << "Could not set up the channel";

    tao_.reset(new FakeTao());
    ASSERT_TRUE(tao_->InitTemporaryTPM()) << "Could not initialize the Tao";

    string child_name("Fake hash");
    string params;
    ASSERT_TRUE(tao_channel_->AddChildChannel(child_name, &params))
        << "Could not add a child to the channel";
    ASSERT_TRUE(tao_channel_->UpdateChildParams(child_name, child_path))
        << "Could not update the channel with the new child parameters";

    // The listening thread will continue until sent a stop message.
    listener_.reset(
        new thread(&KvmUnixTaoChannel::Listen, tao_channel_.get(), tao_.get()));

    child_channel_.reset(new UnixFdTaoChildChannel(*master_fd_, *master_fd_));
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

  ScopedFd master_fd_;
  ScopedTempDir temp_dir_;
  scoped_ptr<FakeTao> tao_;
  scoped_ptr<KvmUnixTaoChannel> tao_channel_;
  scoped_ptr<thread> listener_;
  string domain_socket_;
  scoped_ptr<UnixFdTaoChildChannel> child_channel_;
};

TEST_F(KvmUnixTaoChannelTest, CreationTest) {
  scoped_ptr<UnixDomainSocketTaoAdminChannel> chan(
      new UnixDomainSocketTaoAdminChannel(domain_socket_));
  ASSERT_TRUE(chan->Init());
  string path = "/fake/program";
  list<string> args;
  string child_name;
  ASSERT_TRUE(chan->StartHostedProgram(path, args, &child_name));
}

TEST_F(KvmUnixTaoChannelTest, RandomTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(16, &bytes))
      << "Could not get random bytes from the host tao";
}

TEST_F(KvmUnixTaoChannelTest, SealTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(child_channel_->Seal(bytes, 0 /* policy */, &sealed));
}

TEST_F(KvmUnixTaoChannelTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(child_channel_->Seal(bytes, 0 /* policy */, &sealed));

  string unsealed;
  int policy;
  EXPECT_TRUE(child_channel_->Unseal(sealed, &unsealed, &policy));
  EXPECT_EQ(policy, 0);

  EXPECT_EQ(bytes, unsealed);
}

TEST_F(KvmUnixTaoChannelTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string attestation;
  EXPECT_TRUE(child_channel_->Attest(bytes, &attestation));
}
