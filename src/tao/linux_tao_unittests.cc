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

#include <ftw.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_file_reader.h>

#include "tao/direct_tao_child_channel.h"
#include "tao/fake_program_factory.h"
#include "tao/fake_tao.h"
#include "tao/fake_tao_channel.h"
#include "tao/hosted_programs.pb.h"
#include "tao/hosted_program_factory.h"
#include "tao/linux_tao.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::Signer;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetWriter;

using std::ofstream;

using tao::CreateKey;
using tao::DirectTaoChildChannel;
using tao::FakeProgramFactory;
using tao::FakeTao;
using tao::FakeTaoChannel;
using tao::HostedProgram;
using tao::HostedProgramFactory;
using tao::LinuxTao;
using tao::ScopedTempDir;
using tao::SignedWhitelist;
using tao::Tao;
using tao::TaoChannel;
using tao::TaoChildChannel;
using tao::Whitelist;
using tao::WhitelistAuth;

class LinuxTaoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Get a temporary directory to use for the files.
    string dir_template("/tmp/linux_tao_test_XXXXXX");
    scoped_array<char> temp_name(new char[dir_template.size() + 1]);
    memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

    ASSERT_TRUE(mkdtemp(temp_name.get()));
    temp_dir_.reset(new string(temp_name.get()));

    // Set up the files for the test.
    string secret_path = *temp_dir_ + "/linux_tao_secret";
    string key_path = *temp_dir_ + "/linux_tao_secret_key";
    string pk_path = *temp_dir_ + "/linux_tao_pk";
    string whitelist_path = *temp_dir_ + "/whitelist";
    string policy_pk_path = *temp_dir_ + "/policy_pk";

    string test_binary_contents = "This is a fake test binary to be hashed";
    test_binary_path_ = *temp_dir_ + "/test_binary";

    // Create the policy key directory so it can be filled by keyczar.
    ASSERT_EQ(mkdir(policy_pk_path.c_str(), 0700), 0);

    // create the policy key
    FilePath fp(policy_pk_path);
    scoped_ptr<KeysetWriter> policy_pk_writer(new KeysetJSONFileWriter(fp));
    ASSERT_TRUE(
        CreateKey(policy_pk_writer.get(), KeyType::ECDSA_PRIV,
                  KeyPurpose::SIGN_AND_VERIFY, "policy_pk", &policy_key_));
    policy_key_->set_encoding(Keyczar::NO_ENCODING);

    scoped_ptr<FakeTao> ft(new FakeTao(policy_pk_path));
    ASSERT_TRUE(ft->Init()) << "Could not init the FakeTao";

    string fake_linux_tao_hash("This is not a real hash");
    scoped_ptr<DirectTaoChildChannel> channel(
        new DirectTaoChildChannel(ft.release(), fake_linux_tao_hash));
    ASSERT_TRUE(channel->Init()) << "Could not init the channel";

    scoped_ptr<HostedProgramFactory> program_factory(new FakeProgramFactory());
    scoped_ptr<TaoChannel> child_channel(new FakeTaoChannel());

    string test_binary_digest;
    keyczar::MessageDigestImpl *sha256 = keyczar::CryptoFactory::SHA256();
    CHECK(sha256->Digest(test_binary_contents, &test_binary_digest))
        << "Could not compute a SHA-256 hash over the file "
        << test_binary_path_;

    CHECK(keyczar::base::Base64WEncode(test_binary_digest, &child_hash_))
        << " Could not encode the digest under base64w";

    ofstream test_binary_file(test_binary_path_.c_str(), ofstream::out);
    test_binary_file << test_binary_contents;
    test_binary_file.close();

    // Create a whitelist with a dummy hosted program, since we don't
    // want the LinuxTao to start any hosted programs during this
    // test. Then write it to the temp filename above.
    string empty;
    Whitelist w;
    HostedProgram *hp = w.add_programs();
    hp->set_name(test_binary_path_);
    hp->set_hash_alg("SHA256");
    hp->set_hash(empty);

    HostedProgram *linux_tao_hp = w.add_programs();
    linux_tao_hp->set_name("LinuxTao");
    linux_tao_hp->set_hash_alg("SHA256");
    linux_tao_hp->set_hash(empty);

    SignedWhitelist sw;
    string *serialized_whitelist = sw.mutable_serialized_whitelist();
    ASSERT_TRUE(w.SerializeToString(serialized_whitelist));

    string *signature = sw.mutable_signature();
    ASSERT_TRUE(policy_key_->Sign(*serialized_whitelist, signature));

    ofstream whitelist_file(whitelist_path.c_str(), ofstream::out);
    ASSERT_TRUE(sw.SerializeToOstream(&whitelist_file));
    whitelist_file.close();

    scoped_ptr<WhitelistAuth> whitelist_auth(
        new WhitelistAuth(whitelist_path, policy_pk_path));
    ASSERT_TRUE(whitelist_auth->Init());

    tao_.reset(new LinuxTao(secret_path, key_path, pk_path, policy_pk_path,
                            channel.release(), child_channel.release(),
                            program_factory.release(), whitelist_auth.release(),
                            "" /* no tcca host */, "" /* no tcca port */));
    ASSERT_TRUE(tao_->Init());
  }

  // TODO(tmroeder): clean up the temporary directory of keys and
  // secrets. Use TearDown and recursively delete all the files.
  virtual void TearDown() {
    if (nftw(temp_dir_->c_str(), remove_entry, 10 /* nopenfd */, FTW_DEPTH) < 0) {
      PLOG(ERROR) << "Could not recursively delete the temp directory";
    }
  }

  ScopedTempDir temp_dir_;
  string test_binary_path_;
  string child_hash_;
  scoped_ptr<LinuxTao> tao_;
  scoped_ptr<Keyczar> policy_key_;
};

TEST_F(LinuxTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_->GetRandomBytes(10, &bytes));
  EXPECT_TRUE(tao_->GetRandomBytes(0, &bytes));
}

TEST_F(LinuxTaoTest, FailSealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));
  string sealed;
  string fake_hash("This is also not a hash");
  EXPECT_FALSE(tao_->Seal(fake_hash, bytes, &sealed));
}

TEST_F(LinuxTaoTest, FailUnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  string unsealed;
  string fake_hash("This is also not a hash");
  EXPECT_FALSE(tao_->Unseal(fake_hash, bytes, &unsealed));
}

TEST_F(LinuxTaoTest, FailAttestTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  string attestation;
  string fake_hash("This is also not a hash");
  EXPECT_FALSE(tao_->Attest(fake_hash, bytes, &attestation));
}

TEST_F(LinuxTaoTest, SealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  list<string> args;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args));

  string sealed;
  string empty;
  EXPECT_TRUE(tao_->Seal(empty, bytes, &sealed));
}

TEST_F(LinuxTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  list<string> args;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args));

  string sealed;
  string empty;
  EXPECT_TRUE(tao_->Seal(empty, bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(tao_->Unseal(empty, sealed, &unsealed));
  EXPECT_EQ(unsealed, bytes);
}

TEST_F(LinuxTaoTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(tao_->GetRandomBytes(128, &bytes));

  list<string> args;
  EXPECT_TRUE(tao_->StartHostedProgram(test_binary_path_, args));

  string attestation;
  string empty;
  EXPECT_TRUE(tao_->Attest(empty, bytes, &attestation));
}

GTEST_API_ int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
