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

#include "tao/soft_tao.h"

using namespace tao;  // NOLINT

/*
TEST(UtilTest, RegistryTest) {
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

TEST(UtilTest, SocketTest) {
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
TEST(UtilTest, CreateDomainTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<TaoDomain> admin;
  ASSERT_TRUE(CreateTempACLsDomain(&temp_dir, &admin));
}
*/

TEST(UtilTest, SealAndUnsealSecretTest) {
  ScopedTempDir temp_dir;
  ASSERT_TRUE(CreateTempDir("seal_or_unseal_test", &temp_dir));
  string seal_path = *temp_dir + string("/sealed_secret");

  SoftTao tao;
  EXPECT_TRUE(tao.Init());

  string secret;
  string policy = Tao::SealPolicyDefault;
  EXPECT_TRUE(MakeSealedSecret(&tao, seal_path, policy, 10, &secret));

  string unsealed_secret;
  EXPECT_TRUE(GetSealedSecret(&tao, seal_path, policy, &unsealed_secret));

  EXPECT_EQ(secret, unsealed_secret)
      << "The unsealed secret did not match the original secret";
}

void shouldNotBeNull(int *x) {
  ASSERT_NE(x, nullptr);
  if (x != nullptr) *x += 1;
}
typedef scoped_ptr_malloc<int, CallUnlessNull<int, shouldNotBeNull>>
    ScopedIntPtr;

TEST(UtilTest, CallUnlessNullTest) {
  int x = 42, y = 123;
  ScopedIntPtr p(&x);
  p.release();
  EXPECT_EQ(42, x);
  p.reset(&x);
  EXPECT_EQ(42, x);
  p.reset(&y);
  EXPECT_EQ(43, x);
  p.reset(nullptr);
  EXPECT_EQ(124, y);
  p.release();
}

TEST(UtilTest, SelfPipeTest) {
  EXPECT_GT(0, GetSelfPipeSignalFd(-1, 0 /* no flags */));
  int fd = GetSelfPipeSignalFd(SIGUSR1, 0 /* no flags */);
  EXPECT_LE(0, fd);
  kill(getpid(), SIGUSR1);
  char b;
  EXPECT_EQ(1, read(fd, &b, 1));
  EXPECT_EQ(SIGUSR1, unsigned(b));
  EXPECT_TRUE(ReleaseSelfPipeSignalFd(fd));
  EXPECT_FALSE(ReleaseSelfPipeSignalFd(0));
}

TEST(UtilTest, ShaTest) {
  string txt =
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
  string h;
  EXPECT_TRUE(bytesFromHex(txt, &h));

  string hash;
  EXPECT_TRUE(Sha256("hello", &hash));
  EXPECT_EQ(h, hash);

  ScopedTempDir temp_dir;
  EXPECT_TRUE(CreateTempDir("util_test", &temp_dir));
  EXPECT_TRUE(WriteStringToFile(*temp_dir + "/hello.txt", "hello"));
  EXPECT_TRUE(Sha256FileHash(*temp_dir + "/hello.txt", &hash));
  EXPECT_EQ(h, hash);
}

TEST(UtilTest, ReadWriteTest) {
  string s;
  string path;
  {
    ScopedTempDir temp_dir;
    EXPECT_TRUE(CreateTempDir("util_test", &temp_dir));
    path = *temp_dir + "/hello.txt";

    EXPECT_TRUE(WriteStringToFile(path, "hello"));
    EXPECT_TRUE(ReadFileToString(path, &s));
    EXPECT_EQ("hello", s);

    EXPECT_TRUE(WriteStringToFile(path, "foo"));
    EXPECT_TRUE(ReadFileToString(path, &s));
    EXPECT_EQ("foo", s);
  }
  EXPECT_FALSE(ReadFileToString(path, &s));
}

TEST(UtilTest, HexTest) {
  string txt;
  EXPECT_TRUE(bytesFromHex("0122f00d", &txt));
  ASSERT_EQ(4, txt.size());
  EXPECT_EQ(0x01, (unsigned char)(txt[0]));
  EXPECT_EQ(0x22, (unsigned char)(txt[1]));
  EXPECT_EQ(0xf0, (unsigned char)(txt[2]));
  EXPECT_EQ(0x0d, (unsigned char)(txt[3]));

  EXPECT_TRUE(bytesFromHex("ABCDef01", &txt));
  ASSERT_EQ(4, txt.size());
  EXPECT_EQ(0xab, (unsigned char)(txt[0]));
  EXPECT_EQ(0xcd, (unsigned char)(txt[1]));
  EXPECT_EQ(0xef, (unsigned char)(txt[2]));
  EXPECT_EQ(0x01, (unsigned char)(txt[3]));

  EXPECT_EQ("abcdef01", bytesToHex(txt));
  EXPECT_FALSE(bytesFromHex("01234", &txt));
  EXPECT_FALSE(bytesFromHex("01g3", &txt));
}
