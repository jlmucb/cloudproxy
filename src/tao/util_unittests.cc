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

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/base64w.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>

#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/util.h"

using keyczar::base::Base64WEncode;
using keyczar::CryptoFactory;
using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::Keyset;
using keyczar::KeyType;
using keyczar::MessageDigestImpl;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetWriter;
using keyczar::Signer;
using keyczar::Verifier;

using tao::ConnectToUnixDomainSocket;
using tao::CopyPublicKeyset;
using tao::CreateKey;
using tao::CreatePubECDSAKey;
using tao::CreateTempDir;
using tao::CreateTempPubKey;
using tao::DeserializePublicKey;
using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::HashVM;
using tao::KeyczarPublicKey;
using tao::OpenTCPSocket;
using tao::OpenUnixDomainSocket;
using tao::PipeTaoChildChannel;
using tao::RegisterKnownChannels;
using tao::ScopedFd;
using tao::ScopedTempDir;
using tao::SerializePublicKey;
using tao::SignData;
using tao::Tao;
using tao::TaoChildChannel;
using tao::TaoChildChannelParams;
using tao::TaoChildChannelRegistry;
using tao::VerifySignature;

TEST(TaoUtilTest, HashVMTest) {
  string dummy_template("vm template");
  string name("test vm");
  string dummy_kernel("dummy kernel");
  string dummy_initrd("dummy_initrd");
  string hash;
  ASSERT_TRUE(HashVM(dummy_template, name, dummy_kernel, dummy_initrd, &hash))
      << "Could not hash the parameters";

  MessageDigestImpl *sha256 = CryptoFactory::SHA256();
  EXPECT_TRUE(sha256 != nullptr) << "Could not get SHA-256";

  // Recompute the hash here to make sure it's computed correctly.
  string template_hash;
  EXPECT_TRUE(sha256->Digest(dummy_template, &template_hash))
      << "Could not hash the template";

  string name_hash;
  EXPECT_TRUE(sha256->Digest(name, &name_hash)) << "Could not hash the name";

  string kernel_hash;
  EXPECT_TRUE(sha256->Digest(dummy_kernel, &kernel_hash))
      << "Could not hash the kernel";

  string initrd_hash;
  EXPECT_TRUE(sha256->Digest(dummy_initrd, &initrd_hash))
      << "Could not hash the initrd";

  string hash_input;
  hash_input.append(template_hash);
  hash_input.append(name_hash);
  hash_input.append(kernel_hash);
  hash_input.append(initrd_hash);

  string composite_hash;
  EXPECT_TRUE(sha256->Digest(hash_input, &composite_hash))
      << "Could not compute the composite hash";

  string encoded_hash;
  EXPECT_TRUE(Base64WEncode(composite_hash, &encoded_hash))
      << "Could not encode the hash";

  EXPECT_EQ(encoded_hash, hash)
      << "The computed hash value did not match the value computed by HashVM";
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

TEST(TaoUtilTest, CreateKeyTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_key;
  EXPECT_TRUE(CreateTempPubKey(&temp_dir, &policy_key))
      << "Could not create a key";
}

TEST(TaoUtilTest, SerializeKeyTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_key;
  EXPECT_TRUE(CreateTempPubKey(&temp_dir, &policy_key))
      << "Could not create a key";

  KeyczarPublicKey kpk;
  EXPECT_TRUE(SerializePublicKey(*policy_key, &kpk))
      << "Could not serialize the public key";
}

TEST(TaoUtilTest, DeserializeKeyTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_key;
  EXPECT_TRUE(CreateTempPubKey(&temp_dir, &policy_key))
      << "Could not create a key";

  KeyczarPublicKey kpk;
  EXPECT_TRUE(SerializePublicKey(*policy_key, &kpk))
      << "Could not serialize the public key";

  Keyset *keyset = nullptr;
  EXPECT_TRUE(DeserializePublicKey(kpk, &keyset))
      << "Could not deserialize the public policy key";
  scoped_ptr<Keyczar> public_policy_key(new Verifier(keyset));
  public_policy_key->set_encoding(Keyczar::NO_ENCODING);

  // Make sure this is really the public policy key by signing something with
  // the original key and verifying it with the deserialized version.

  string message("Test message");
  string signature;
  EXPECT_TRUE(policy_key->Sign(message, &signature))
      << "Could not sign the message";

  EXPECT_TRUE(public_policy_key->Verify(message, signature))
      << "The signature did not pass verification";
}

TEST(TaoUtilTest, SignDataTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_key;
  EXPECT_TRUE(CreateTempPubKey(&temp_dir, &policy_key))
      << "Could not create a key";

  string message("Test message");
  string signature;
  EXPECT_TRUE(SignData(message, &signature, policy_key.get()))
      << "Could not sign the test message";
}

TEST(TaoUtilTest, VerifyDataTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_key;
  EXPECT_TRUE(CreateTempPubKey(&temp_dir, &policy_key))
      << "Could not create a key";

  string message("Test message");
  string signature;
  EXPECT_TRUE(SignData(message, &signature, policy_key.get()))
      << "Could not sign the test message";

  EXPECT_TRUE(VerifySignature(message, signature, policy_key.get()))
      << "The signature did not pass verification";
}

TEST(TaoUtilTest, CopyPublicKeysetTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_key;
  EXPECT_TRUE(CreateTempPubKey(&temp_dir, &policy_key))
      << "Could not create a key";

  Keyset *keyset = nullptr;
  EXPECT_TRUE(CopyPublicKeyset(*policy_key, &keyset))
      << "Could not copy the keyset";

  scoped_ptr<Keyczar> pub_key(new Verifier(keyset));
  pub_key->set_encoding(Keyczar::NO_ENCODING);

  // Make sure that the copied keyset can verify a signature.
  string message("Test message");
  string signature;
  EXPECT_TRUE(SignData(message, &signature, policy_key.get()))
      << "Could not sign the test message";

  EXPECT_TRUE(VerifySignature(message, signature, pub_key.get()))
      << "The signature did not pass verification";
}

TEST(TaoUtilTest, SealOrUnsealSecretTest) {
  ScopedTempDir temp_dir;
  EXPECT_TRUE(CreateTempDir("seal_or_unseal_test", &temp_dir))
      << "Could not create the temp directory";
  string seal_path = *temp_dir + string("/sealed_secret");
  scoped_ptr<Tao> ft(new FakeTao());
  EXPECT_TRUE(ft->Init()) << "Could not Init the tao";
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
