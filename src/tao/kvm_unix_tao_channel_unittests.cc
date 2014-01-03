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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>

#include <thread>

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>

#include "tao/fake_tao.h"
#include "tao/kvm_unix_tao_channel.h"
#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"
#include "tao/unix_fd_tao_child_channel.h"
#include "tao/util.h"

using std::thread;

using tao::ConnectToUnixDomainSocket;
using tao::FakeTao;
using tao::KvmUnixTaoChannel;
using tao::ScopedFd;
using tao::ScopedTempDir;
using tao::StartHostedProgramArgs;
using tao::Tao;
using tao::TaoChannel;
using tao::TaoChannelRPC;
using tao::UnixFdTaoChildChannel;

class KvmUnixTaoChannelTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Get a temporary directory to use for the files.
    string dir_template("/tmp/kvm_unix_tao_test_XXXXXX");
    scoped_array<char> temp_name(new char[dir_template.size() + 1]);
    memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

    ASSERT_TRUE(mkdtemp(temp_name.get()));
    temp_dir_.reset(new string(temp_name.get()));

    creation_socket_ = *temp_dir_ + string("/creation_socket");
    stop_socket_ = *temp_dir_ + string("/stop_socket");

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

    tao_channel_.reset(new KvmUnixTaoChannel(creation_socket_, stop_socket_));
    ASSERT_TRUE(tao_channel_->Init()) << "Could not set up the sockets";

    tao_.reset(new FakeTao());
    ASSERT_TRUE(tao_->Init()) << "Could not initialize the Tao";

    string child_hash("Fake hash");
    string params;
    ASSERT_TRUE(tao_channel_->AddChildChannel(child_hash, &params))
        << "Could not add a child to the channel";
    ASSERT_TRUE(tao_channel_->UpdateChildParams(child_hash, child_path))
        << "Could not update the channel with the new child parameters";

    // The listening thread will continue until sent a stop message.
    listener_.reset(
        new thread(&KvmUnixTaoChannel::Listen, tao_channel_.get(), tao_.get()));

    child_channel_.reset(new UnixFdTaoChildChannel(*master_fd_, *master_fd_));
  }

  virtual void TearDown() {
    ScopedFd sock(new int(-1));
    ASSERT_TRUE(ConnectToUnixDomainSocket(stop_socket_, sock.get()));

    // It doesn't matter what message we write to the stop socket. Any message
    // on this socket causes it to stop. It doesn't even read the message.
    int msg = 0;
    ssize_t bytes_written = write(*sock, &msg, sizeof(msg));
    if (bytes_written != sizeof(msg)) {
      PLOG(ERROR) << "Could not write a message to the stop socket";
      return;
    }

    if (listener_->joinable()) {
      listener_->join();
    }
  }

  ScopedFd master_fd_;
  ScopedTempDir temp_dir_;
  scoped_ptr<Tao> tao_;
  scoped_ptr<KvmUnixTaoChannel> tao_channel_;
  scoped_ptr<thread> listener_;
  string creation_socket_;
  string stop_socket_;
  scoped_ptr<UnixFdTaoChildChannel> child_channel_;
};

TEST_F(KvmUnixTaoChannelTest, CreationTest) {
  // Pass a process creation message to the channel.
  ScopedFd sock(new int(-1));
  EXPECT_TRUE(ConnectToUnixDomainSocket(creation_socket_, sock.get()))
      << "Could not connect to the socket " << creation_socket_;

  TaoChannelRPC rpc;
  rpc.set_rpc(tao::START_HOSTED_PROGRAM);
  StartHostedProgramArgs *shpa = rpc.mutable_start();
  shpa->set_path("Fake Program");
  EXPECT_TRUE(SendMessage(*sock, rpc))
      << "Could not send the message to the socket";
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
  EXPECT_TRUE(child_channel_->Seal(bytes, &sealed));
}

TEST_F(KvmUnixTaoChannelTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(child_channel_->Seal(bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(child_channel_->Unseal(sealed, &unsealed));

  EXPECT_EQ(bytes, unsealed);
}

TEST_F(KvmUnixTaoChannelTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string attestation;
  EXPECT_TRUE(child_channel_->Attest(bytes, &attestation));
}
