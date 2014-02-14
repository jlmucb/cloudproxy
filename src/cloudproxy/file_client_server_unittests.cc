//  File: file_client_server_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Basic tests for the FileClient and FileServer classes.
//
//  Copyright (c) 2014, Google Inc.  All rights reserved.
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
#include "cloudproxy/file_client.h"
#include "cloudproxy/file_server.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <sstream>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <openssl/rand.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/attestation.pb.h"
#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/keys.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::ifstream;
using std::ofstream;
using std::stringstream;

using keyczar::CryptoFactory;
using keyczar::RandImpl;

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::CloudUserManager;
using cloudproxy::FileClient;
using cloudproxy::FileServer;
using cloudproxy::ScopedSSL;
using cloudproxy::SignedACL;
using cloudproxy::SignedSpeaksFor;
using tao::CreateTempWhitelistDomain;
using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::ScopedTempDir;
using tao::SignData;
using tao::TaoDomain;
using tao::Keys;

class FileClientTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CHECK(CreateTempWhitelistDomain(&temp_dir_, &admin_));

    // Create a whitelist with some test programs.
    ASSERT_TRUE(admin_->Authorize("Test hash 1", TaoDomain::Sha256, "Test 1"));
    ASSERT_TRUE(admin_->Authorize("Test hash 2", TaoDomain::Sha256, "Test 2"));
    ASSERT_TRUE(admin_->Authorize("FAKE_TPM", TaoDomain::FakeHash, "BogusTPM"));

    // set up file client
    string client_keys = *temp_dir_ + string("/client_keys");
    string server_addr("localhost");
    string server_port("11223");
    client_file_path_ = *temp_dir_ + string("/client_files");
    ASSERT_EQ(mkdir(client_file_path_.c_str(), 0700), 0);

    // create a fake tao with new keys, attestation, and a direct channel to it
    scoped_ptr<FakeTao> fake_tao;
    fake_tao.reset(new FakeTao());
    ASSERT_TRUE(fake_tao->InitTemporaryTPM(*admin_));

    // create file client
    file_client_.reset(new FileClient(
        client_file_path_, client_keys,
        new DirectTaoChildChannel(fake_tao->DeepCopy(), "Test hash 1"),
        admin_->DeepCopy()));

    // set up file server
    string server_keys = *temp_dir_ + string("/server_keys");

    // ACL for the server.
    ACL acl;
    Action *a1 = acl.add_permissions();
    a1->set_subject("tmroeder");
    a1->set_verb(cloudproxy::ADMIN);

    Action *a2 = acl.add_permissions();
    a2->set_subject("jlm");
    a2->set_verb(cloudproxy::CREATE);
    a2->set_object("/files");

    SignedACL sacl;
    string *ser = sacl.mutable_serialized_acls();
    EXPECT_TRUE(acl.SerializeToString(ser)) << "Could not serialize ACL";

    string *sig = sacl.mutable_signature();
    EXPECT_TRUE(SignData(*ser, CloudAuth::ACLSigningContext, sig,
                         admin_->GetPolicySigner()))
        << "Could not sign the serialized ACL with the policy key";

    string signed_acl_path = *temp_dir_ + string("/signed_acl");
    ofstream acl_file(signed_acl_path.c_str(), ofstream::out);
    ASSERT_TRUE(acl_file) << "Could not open " << signed_acl_path;

    EXPECT_TRUE(sacl.SerializeToOstream(&acl_file))
        << "Could not write the signed ACL to a file";

    acl_file.close();

    // Set up directories for the FileServer to store its files and metadata
    string server_enc_dir = *temp_dir_ + string("/enc_files");
    ASSERT_EQ(mkdir(server_enc_dir.c_str(), 0700), 0);

    string server_meta_dir = *temp_dir_ + string("/meta_files");
    ASSERT_EQ(mkdir(server_meta_dir.c_str(), 0700), 0);

    // create file server
    file_server_.reset(new FileServer(
        server_enc_dir, server_meta_dir, server_keys, signed_acl_path,
        server_addr, server_port,
        new DirectTaoChildChannel(fake_tao.release(), "Test hash 2"),
        admin_->DeepCopy()));

    server_thread_.reset(new thread(&FileServer::Listen, file_server_.get(),
                                    true /* stop after one connection */));

    // Create two users and matching delegations.
    scoped_ptr<Keys> key;
    string u; 
    string users_path = *temp_dir_ + "/users";

    u = "tmroeder";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &key));
    tmroeder_key_path_ = key->SigningPrivateKeyPath();
    tmroeder_ssf_path_ = key->GetPath(CloudUserManager::UserDelegationSuffix);

    u = "jlm";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &key));
    jlm_key_path_ = key->SigningPrivateKeyPath();
    jlm_ssf_path_ = key->GetPath(CloudUserManager::UserDelegationSuffix);

    // Create files filled with random data.
    small_file_obj_name_ = "small";
    small_file_ = client_file_path_ + string("/") + small_file_obj_name_;
    string small_data;
    RandImpl *rand = CryptoFactory::Rand();
    // 2 KB file
    ASSERT_TRUE(rand->RandBytes(2 * 1000, &small_data));
    ofstream small_file_out(small_file_.c_str());
    ASSERT_TRUE(small_file_out);
    small_file_out << small_data;
    small_file_out.close();

    medium_file_obj_name_ = "medium";
    medium_file_ = client_file_path_ + string("/") + medium_file_obj_name_;

    // 20 MB file
    int med_len = 20 * 1000 * 1000;
    scoped_array<unsigned char> med(new unsigned char[med_len]);
    ASSERT_EQ(RAND_bytes(med.get(), med_len), 1);
    string medium_data(reinterpret_cast<char *>(med.get()), med_len);
    ofstream medium_file_out(medium_file_.c_str());
    ASSERT_TRUE(medium_file_out);
    medium_file_out << medium_data;
    medium_file_out.close();

    ASSERT_TRUE(file_client_->Connect(server_addr, server_port, &ssl_));
  }

  virtual void TearDown() {
    if (file_client_.get()) {
      EXPECT_TRUE(file_client_->Close(ssl_.get(), false));
    }

    if (server_thread_->joinable()) {
      server_thread_->join();
    }
  }

  scoped_ptr<TaoDomain> admin_;
  scoped_ptr<thread> server_thread_;
  scoped_ptr<FileClient> file_client_;
  scoped_ptr<FileServer> file_server_;
  ScopedTempDir temp_dir_;
  ScopedSSL ssl_;
  SignedSpeaksFor ssf;
  SignedSpeaksFor ssf2;
  string tmroeder_key_path_;
  string tmroeder_ssf_path_;
  string jlm_key_path_;
  string jlm_ssf_path_;
  string small_file_;
  string small_file_obj_name_;
  string medium_file_;
  string medium_file_obj_name_;
  string client_file_path_;
};

bool CompareFiles(const string &orig_file_name, const string &new_file_name) {
  // Compare the two files to make sure they're identical.
  ifstream orig_file(orig_file_name);
  if (!orig_file) {
    return false;
  }

  ifstream new_file(new_file_name);
  if (!new_file) {
    return false;
  }

  stringstream orig_buf;
  orig_buf << orig_file.rdbuf();

  stringstream new_buf;
  new_buf << new_file.rdbuf();

  return (orig_buf.str().compare(new_buf.str()) == 0);
}

// All of the user and connection management is handled by the parent classes,
// so we don't need to test it again here. The differences are in the object
// handling: CloudClient and CloudServer have nop routines for READ and WRITE,
// and CREATE and DESTROY act differently, too.

TEST_F(FileClientTest, CreateTest) {
  string username("tmroeder");
  EXPECT_TRUE(file_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      file_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(file_client_->Create(ssl_.get(), username, small_file_obj_name_));
}

TEST_F(FileClientTest, DestroyTest) {
  string username("tmroeder");
  EXPECT_TRUE(file_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      file_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(file_client_->Create(ssl_.get(), username, small_file_obj_name_));
  EXPECT_TRUE(
      file_client_->Destroy(ssl_.get(), username, small_file_obj_name_));
}

TEST_F(FileClientTest, SmallWriteTest) {
  string username("tmroeder");
  string output_obj("small_out");
  EXPECT_TRUE(file_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      file_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(file_client_->Create(ssl_.get(), username, small_file_obj_name_));
  EXPECT_TRUE(file_client_->Write(ssl_.get(), username, small_file_obj_name_,
                                  small_file_obj_name_));
  EXPECT_TRUE(file_client_->Read(ssl_.get(), username, small_file_obj_name_,
                                 output_obj));
  EXPECT_TRUE(
      file_client_->Destroy(ssl_.get(), username, small_file_obj_name_));

  EXPECT_TRUE(
      CompareFiles(small_file_, client_file_path_ + string("/") + output_obj));
}

TEST_F(FileClientTest, MediumWriteTest) {
  string username("tmroeder");
  string output_obj("medium_out");
  EXPECT_TRUE(file_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      file_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(
      file_client_->Create(ssl_.get(), username, medium_file_obj_name_));
  EXPECT_TRUE(file_client_->Write(ssl_.get(), username, medium_file_obj_name_,
                                  medium_file_obj_name_));
  EXPECT_TRUE(file_client_->Read(ssl_.get(), username, medium_file_obj_name_,
                                 output_obj));
  EXPECT_TRUE(
      file_client_->Destroy(ssl_.get(), username, medium_file_obj_name_));

  EXPECT_TRUE(
      CompareFiles(medium_file_, client_file_path_ + string("/") + output_obj));
}
