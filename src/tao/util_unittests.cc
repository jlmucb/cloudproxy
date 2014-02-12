//  File: util_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Unit tests for the utility functions
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
#include "tao/util.h"

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/file_util.h>

#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"

using keyczar::base::WriteStringToFile;

using tao::ConnectToUnixDomainSocket;
using tao::CreateTempDir;
using tao::CreateTempRootDomain;
using tao::CreateTempWhitelistDomain;
using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::HashVM;
using tao::OpenTCPSocket;
using tao::OpenUnixDomainSocket;
using tao::PipeTaoChildChannel;
using tao::RegisterKnownChannels;
using tao::ScopedFd;
using tao::ScopedTempDir;
using tao::TaoChildChannel;
using tao::TaoChildChannelParams;
using tao::TaoChildChannelRegistry;
using tao::TaoDomain;

TEST(TaoUtilTest, HashVMTest) {
  ScopedTempDir temp_dir;
  ASSERT_TRUE(CreateTempDir("hashvm_test", &temp_dir));
  ASSERT_TRUE(WriteStringToFile(*temp_dir + "/vm_template", "vm template"));
  string name("test vm");
  ASSERT_TRUE(WriteStringToFile(*temp_dir + "/kernel", "dummy kernel"));
  ASSERT_TRUE(WriteStringToFile(*temp_dir + "/initrd", "dummy initrd"));
  string hash;
  ASSERT_TRUE(HashVM(*temp_dir + "/vm_template", name, *temp_dir + "/kernel",
                     *temp_dir + "/initrd", &hash))
      << "Could not hash the parameters";

  string correct_hash = "a-SuzE8aBiekrpc-LnTISYH4WpeSLikaBkCtYMUe5dA";

  EXPECT_EQ(correct_hash, hash)
      << "The hash value computed by HashVM did not match expectations";
}

TEST(TaoUtilTest, RegistryTest) {
  TaoChildChannelRegistry registry;
  EXPECT_TRUE(RegisterKnownChannels(&registry))
      << "Could not register known channels with the registry";

  // Make sure you can instantiate at least one of them.
  TaoChildChannelParams tccp;
  tccp.set_channel_type(PipeTaoChildChannel::ChannelType());
  tccp.set_params("dummy params");

  string serialized;
  EXPECT_TRUE(tccp.SerializeToString(&serialized))
      << "Could not serialize the params";

  // This works because the constructor of PipeTaoChildChannel doesn't try to
  // interpret the parameter it gets. That happens in Init(), which we don't
  // call.
  TaoChildChannel *channel = registry.Create(serialized);
  EXPECT_TRUE(channel != nullptr);
}

TEST(TaoUtilTest, SocketTest) {
  ScopedFd sock(new int(-1));

  // Passing 0 as the port means you get an auto-assigned port.
  EXPECT_TRUE(OpenTCPSocket("localhost", "0", sock.get()))
      << "Could not create and bind a TCP socket";
}

TEST(TaoUtilTest, CreateDomainTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<TaoDomain> admin;
  ASSERT_TRUE(CreateTempWhitelistDomain(&temp_dir, &admin));
  ASSERT_TRUE(CreateTempRootDomain(&temp_dir, &admin));
}

TEST(TaoUtilTest, SealOrUnsealSecretTest) {
  ScopedTempDir temp_dir;
  ASSERT_TRUE(CreateTempDir("seal_or_unseal_test", &temp_dir));
  string seal_path = *temp_dir + string("/sealed_secret");

  scoped_ptr<FakeTao> ft(new FakeTao());
  EXPECT_TRUE(ft->InitTemporaryTPM()) << "Could not Init the tao";
  string fake_hash("fake hash");

  DirectTaoChildChannel channel(ft.release(), fake_hash);

  string secret("Fake secret");
  EXPECT_TRUE(SealOrUnsealSecret(channel, seal_path, &secret))
      << "Could not seal the secret";

  string unsealed_secret;
  EXPECT_TRUE(SealOrUnsealSecret(channel, seal_path, &unsealed_secret))
      << "Could not unseal the secret";

  EXPECT_EQ(secret, unsealed_secret)
      << "The unsealed secret did not match the original secret";
}

TEST(TaoUtilTest, SendAndReceiveMessageTest) {
  int fd[2];
  EXPECT_EQ(pipe(fd), 0) << "Could not create a pipe pair";
  TaoChildChannelParams tccp;
  tccp.set_channel_type("FakeChannel");
  tccp.set_params("Fake Params");

  EXPECT_TRUE(SendMessage(fd[1], tccp)) << "Could not send the message";

  TaoChildChannelParams received_tccp;
  EXPECT_TRUE(ReceiveMessage(fd[0], &received_tccp))
      << "Could not receive the message";

  EXPECT_EQ(received_tccp.params(), tccp.params())
      << "The received params don't match the original params";

  EXPECT_EQ(received_tccp.channel_type(), tccp.channel_type())
      << "The received channel type doesn't match the original channel type";
}

TEST(TaoUtilTest, SocketUtilTest) {
  ScopedTempDir temp_dir;
  EXPECT_TRUE(CreateTempDir("socket_util_test", &temp_dir))
      << "Could not create a temporary directory";

  string socket_path = *temp_dir + string("/socket");
  {
    // In a sub scope to make sure the sockets get closed before the temp
    // directory is deleted.
    ScopedFd sock(new int(-1));
    EXPECT_TRUE(OpenUnixDomainSocket(socket_path, sock.get()))
        << "Could not open a Unix domain socket";
    ScopedFd client_sock(new int(-1));
    EXPECT_TRUE(ConnectToUnixDomainSocket(socket_path, client_sock.get()))
        << "Could not connect to the Unix domain socket";
  }
}
