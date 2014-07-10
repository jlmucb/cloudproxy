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
#define BUFFERSIZE 2048
#include <b64/encode.h>
#include <b64/decode.h>
#include <modp_b64w.h>

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
  unique_ptr<TaoDomain> admin;
  ASSERT_TRUE(CreateTempACLsDomain(&temp_dir, &admin));
}
*/

static const char *str2char(const string &s) {
  return s.empty() ? nullptr : &*s.begin();
}
static char *str2char(string *s) { return s->empty() ? nullptr : &*s->begin(); }

bool libb64_encode(const string &in, string *out) {
  base64::base64_encodestate ctx;
  base64::base64_init_encodestate(&ctx);
  int max_n = in.size() * 2;
  out->resize(max_n);
  int n =
      base64::base64_encode_block(str2char(in), in.size(), str2char(out), &ctx);
  n += base64::base64_encode_blockend(str2char(out) + n, &ctx);
  EXPECT_LE(n, max_n);
  out->resize(n);
  return true;
}

bool libb64_decode(const string &in, string *out) {
  base64::base64_decodestate ctx;
  base64::base64_init_decodestate(&ctx);
  int max_n = in.size();
  out->resize(max_n);
  int n =
      base64::base64_decode_block(str2char(in), in.size(), str2char(out), &ctx);
  EXPECT_LE(n, max_n);
  out->resize(n);
  return true;
}

bool modp_encode(const string &in, string *out) {
  out->assign(modp::b64w_encode(str2char(in), in.size()));
  // const char *s = str2char(in);
  // size_t len = in.size();
  // std::string x(modp_b64w_encode_len(len), '\0');
  // int d =
  //     modp_b64w_encode(const_cast<char *>(x.data()), s,
  //     static_cast<int>(len));
  // x.erase(d, std::string::npos);
  // out->assign(x);
  // std::cout << "encoded size is " << out->size() << " (d = " << d << ")\n";
  return true;
}

bool modp_decode(const string &in, string *out) {
  out->assign(modp::b64w_decode(str2char(in), in.size()));
  // std::cout << "decoded size is " << out->size() << "\n";
  return true;
}

void quick_rand(int n, string *s) {
  const long m = 4294967296, a = 1103515245, c = 12345;
  long x = 0xf00d;
  std::cout << "Generating " << n << " bytes of data\n";
  s->resize(n);
  for (int i = 0; i < n; i++) {
    x = (a * x + c) % m;
    (*s)[i++] = (x & 0xff);
  }
}

#include <sys/time.h>
long long current_timestamp() {
  struct timeval te;
  gettimeofday(&te, NULL);  // get current time
  long long milliseconds =
      te.tv_sec * 1000LL + te.tv_usec / 1000;  // caculate milliseconds
  // printf("milliseconds: %lld\n", milliseconds);
  return milliseconds;
}

void btest(const string &data) {
  std::cout << "Encoding '" << data << "'\n";
  string b1, b2, b3, d1, d2, d3;

  EXPECT_TRUE(Base64WEncode(data, &b1));
  EXPECT_TRUE(Base64WDecode(b1, &d1));
  EXPECT_EQ(data, d1);

  EXPECT_TRUE(modp_encode(data, &b2));
  EXPECT_EQ(b1, b2);
  EXPECT_TRUE(modp_decode(b2, &d2));
  EXPECT_EQ(data, d2);

  // EXPECT_TRUE(libb64_encode(data, &b3));
  // EXPECT_EQ(b1, b3);
  // EXPECT_TRUE(libb64_decode(b3, &d3));
  // EXPECT_EQ(data, d3);
}

TEST(UtilTest, Base64Test) {
  btest("Hello World!");  // 12 -> 16
  btest("Hello World");   // 11 -> 15
  btest("Hello Worl");    // 10 -> 14
  btest("Hello Wor");     // 9 -> 12
  btest("Hello Wo");      // 8 -> 11

  int test_size = 128 * 1024 * 1024;
  string data;
  quick_rand(test_size, &data);

  int n = 10;

  string b;
  EXPECT_TRUE(Base64WEncode(data, &b));

  long long t_s, t_e;

  // // Try libb64
  // std::cout << "=== libb64 ===\n";
  // std::cout << "Encoding " << data.size() << " bytes of data\n";
  // {
  //   string b_new;
  //   EXPECT_TRUE(libb64_encode(data, &b_new));
  // }
  // std::cout << "Encoding " << data.size() << " bytes of data (" << n
  //           << " times)\n";
  // t_s = current_timestamp();
  // for (int i = 0; i < n; i++) {
  //   string b_new;
  //   EXPECT_TRUE(libb64_encode(data, &b_new));
  // }
  // t_e = current_timestamp();
  // std::cout << "Elapsed: " << (t_e - t_s) << "\n";
  // std::cout << "Decoding " << b.size() << " bytes of data\n";
  // {
  //   string d_new;
  //   EXPECT_TRUE(libb64_decode(b, &d_new));
  // }
  // std::cout << "Decoding " << b.size() << " bytes of data (" << n
  //           << " times)\n";
  // t_s = current_timestamp();
  // for (int i = 0; i < n; i++) {
  //   string d_new;
  //   EXPECT_TRUE(libb64_decode(b, &d_new));
  // }
  // t_e = current_timestamp();
  // std::cout << "Elapsed: " << (t_e - t_s) << "\n";

  // Try modp
  std::cout << "=== modp ===\n";
  std::cout << "Encoding " << data.size() << " bytes of data\n";
  {
    string b_new;
    EXPECT_TRUE(modp_encode(data, &b_new));
  }
  std::cout << "Encoding " << data.size() << " bytes of data (" << n
            << " times)\n";
  t_s = current_timestamp();
  for (int i = 0; i < n; i++) {
    string b_new;
    EXPECT_TRUE(modp_encode(data, &b_new));
  }
  t_e = current_timestamp();
  std::cout << "Elapsed: " << (t_e - t_s) << "\n";
  std::cout << "Decoding " << b.size() << " bytes of data\n";
  {
    string d_new;
    EXPECT_TRUE(modp_decode(b, &d_new));
  }
  std::cout << "Decoding " << b.size() << " bytes of data (" << n
            << " times)\n";
  t_s = current_timestamp();
  for (int i = 0; i < n; i++) {
    string d_new;
    EXPECT_TRUE(modp_decode(b, &d_new));
  }
  t_e = current_timestamp();
  std::cout << "Elapsed: " << (t_e - t_s) << "\n";

  // Try keyczar
  std::cout << "=== keyczar ===\n";
  std::cout << "Encoding " << data.size() << " bytes of data\n";
  {
    string b_new;
    EXPECT_TRUE(Base64WEncode(data, &b_new));
  }
  std::cout << "Encoding " << data.size() << " bytes of data (" << n
            << " times)\n";
  t_s = current_timestamp();
  for (int i = 0; i < n; i++) {
    string b_new;
    EXPECT_TRUE(Base64WEncode(data, &b_new));
  }
  t_e = current_timestamp();
  std::cout << "Elapsed: " << (t_e - t_s) << "\n";
  std::cout << "Decoding " << b.size() << " bytes of data\n";
  {
    string d_new;
    EXPECT_TRUE(Base64WDecode(b, &d_new));
  }
  std::cout << "Decoding " << b.size() << " bytes of data (" << n
            << " times)\n";
  t_s = current_timestamp();
  for (int i = 0; i < n; i++) {
    string d_new;
    EXPECT_TRUE(Base64WDecode(b, &d_new));
  }
  t_e = current_timestamp();
  std::cout << "Elapsed: " << (t_e - t_s) << "\n";
  std::cout << "Done\n";

  std::cout << "Done\n";
}

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
