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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

#include <thread>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/base64w.h>

#include "tao/fake_tao.h"
#include "tao/pipe_tao_channel.h"
#include "tao/pipe_tao_channel_params.pb.h"
#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/unix_fd_tao_child_channel.h"
#include "tao/util.h"

using std::thread;

using tao::ConnectToUnixDomainSocket;
using tao::CreateTempDir;
using tao::FakeTao;
using tao::PipeTaoChannel;
using tao::PipeTaoChannelParams;
using tao::ScopedFd;
using tao::ScopedTempDir;
using tao::StartHostedProgramArgs;
using tao::Tao;
using tao::TaoChannel;
using tao::TaoChannelRPC;
using tao::TaoChildChannelParams;
using tao::UnixFdTaoChildChannel;

class PipeTaoChannelTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("pipe_tao_channel_test", &temp_dir_));

    creation_socket_ = *temp_dir_ + string("/creation_socket");
    stop_socket_ = *temp_dir_ + string("/stop_socket");

    // Get pipes from the PipeTaoChannel.
    tao_channel_.reset(new PipeTaoChannel(creation_socket_, stop_socket_));
    ASSERT_TRUE(tao_channel_->Init()) << "Could not set up the sockets";

    tao_.reset(new FakeTao());
    ASSERT_TRUE(tao_->InitTemporaryTPM()) << "Could not initialize the Tao";

    string child_hash("Fake hash");
    string params;
    ASSERT_TRUE(tao_channel_->AddChildChannel(child_hash, &params))
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

  ScopedFd readfd_;
  ScopedFd writefd_;
  ScopedTempDir temp_dir_;
  scoped_ptr<FakeTao> tao_;
  scoped_ptr<PipeTaoChannel> tao_channel_;
  scoped_ptr<thread> listener_;
  string creation_socket_;
  string stop_socket_;
  scoped_ptr<UnixFdTaoChildChannel> child_channel_;
};

TEST_F(PipeTaoChannelTest, CreationTest) {
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

TEST_F(PipeTaoChannelTest, RandomTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(16, &bytes))
      << "Could not get random bytes from the host tao";
}

TEST_F(PipeTaoChannelTest, SealTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(child_channel_->Seal(bytes, &sealed));
}

TEST_F(PipeTaoChannelTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(child_channel_->Seal(bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(child_channel_->Unseal(sealed, &unsealed));

  EXPECT_EQ(bytes, unsealed);
}

TEST_F(PipeTaoChannelTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(child_channel_->GetRandomBytes(128, &bytes));
  string attestation;
  EXPECT_TRUE(child_channel_->Attest(bytes, &attestation));
}
