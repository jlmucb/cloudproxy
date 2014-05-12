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
//#include <keyczar/base/file_util.h>

//#include "tao/direct_tao_child_channel.h"
//#include "tao/pipe_tao_child_channel.h"
#include "tao/soft_tao.h"
//#include "tao/tao_child_channel_params.pb.h"
//#include "tao/tao_child_channel_registry.h"
//#include "tao/tao_domain.h"

using std::string;

//using tao::ConnectToUnixDomainSocket;
//using tao::CreateTempACLsDomain;
using tao::CreateTempDir;
//using tao::DirectTaoChildChannel;
using tao::OpenTCPSocket;
using tao::GetTCPSocketInfo;
using tao::ConnectToTCPServer;
using tao::OpenUnixDomainSocket;
//using tao::PipeTaoChildChannel;
//using tao::RegisterKnownChannels;
using tao::ScopedFd;
using tao::ScopedTempDir;
using tao::SoftTao;
using tao::Statement;
using tao::Tao;
//using tao::TaoChildChannel;
//using tao::TaoChildChannelParams;
//using tao::TaoChildChannelRegistry;
// using tao::TaoDomain;

/*
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
*/

TEST(TaoUtilTest, SocketTest) {
  ScopedFd server_sock(new int(-1));
  ScopedFd client_sock(new int(-1));

  // Passing 0 as the port means you get an auto-assigned port.
  ASSERT_TRUE(OpenTCPSocket("localhost", "0", server_sock.get()))
      << "Could not create and bind a TCP socket";
  ASSERT_GE(*server_sock, 0);

  string host, port;
  ASSERT_TRUE(GetTCPSocketInfo(*server_sock, &host, &port));

  ASSERT_TRUE(ConnectToTCPServer("localhost", port, client_sock.get()));
  ASSERT_GE(*client_sock, 0);
}

/*
TEST(TaoUtilTest, CreateDomainTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<TaoDomain> admin;
  ASSERT_TRUE(CreateTempACLsDomain(&temp_dir, &admin));
}
*/

TEST(TaoUtilTest, SealAndUnsealSecretTest) {
  ScopedTempDir temp_dir;
  ASSERT_TRUE(CreateTempDir("seal_or_unseal_test", &temp_dir));
  string seal_path = *temp_dir + string("/sealed_secret");

  SoftTao tao;
  EXPECT_TRUE(tao.InitWithTemporaryKeys());

  string secret;
  string policy = Tao::SealPolicyDefault;
  EXPECT_TRUE(MakeSealedSecret(tao, seal_path, policy, 10, &secret));

  string unsealed_secret;
  EXPECT_TRUE(GetSealedSecret(tao, seal_path, policy, &unsealed_secret));

  EXPECT_EQ(secret, unsealed_secret)
      << "The unsealed secret did not match the original secret";
}

TEST(TaoUtilTest, SendAndReceiveMessageTest) {
  int fd[2];
  EXPECT_EQ(pipe(fd), 0) << "Could not create a pipe pair";
  ScopedFd send_fd(new int(fd[1]));
  ScopedFd recv_fd(new int(fd[0]));
  Statement msg;
  msg.set_issuer("Alice");
  msg.set_delegate("Bob");
  msg.set_time(1);
  msg.set_expiration(2);

  EXPECT_TRUE(SendMessage(*send_fd, msg)) << "Could not send the message";

  Statement received_msg;
  bool eof = true;
  EXPECT_TRUE(ReceiveMessage(*recv_fd, &received_msg, &eof) && !eof)
      << "Could not receive the message";

  EXPECT_EQ(received_msg.issuer(), "Alice");
  EXPECT_EQ(received_msg.delegate(), "Bob");
  EXPECT_EQ(received_msg.time(), 1);
  EXPECT_EQ(received_msg.expiration(), 2);

  send_fd.reset(new int(-1));
  EXPECT_TRUE(ReceiveMessage(*recv_fd, &received_msg, &eof) && eof)
    << "Was expecting EOF";
}

/*
TEST(TaoUtilTest, SocketUtilTest) {
  ScopedTempDir temp_dir;
  EXPECT_TRUE(CreateTempDir("socket_util_test", &temp_dir))
      << "Could not create a temporary directory";

  string socket_path = *temp_dir + string("/socket");
  {
    // In a sub scope to make sure the sockets get closed before the temp
    // directory is deleted.
    ScopedFd server_sock(new int(-1));
    EXPECT_TRUE(OpenUnixDomainSocket(socket_path, server_sock.get()))
        << "Could not open a Unix domain socket";
    ASSERT_GE(*server_sock, 0);

    ScopedFd client_sock(new int(-1));
    EXPECT_TRUE(ConnectToUnixDomainSocket(socket_path, client_sock.get()))
        << "Could not connect to the Unix domain socket";
    ASSERT_GE(*client_sock, 0);
  }
}
*/
