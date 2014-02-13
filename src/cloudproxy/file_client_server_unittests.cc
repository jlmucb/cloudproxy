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
#include <keyczar/rw/keyset_file_writer.h>
#include <openssl/rand.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/attestation.pb.h"
#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::ifstream;
using std::ofstream;
using std::stringstream;

using keyczar::CryptoFactory;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::RandImpl;
using keyczar::Signer;
using keyczar::base::ScopedSafeString;
using keyczar::rw::KeysetJSONFileWriter;

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::CloudUserManager;
using cloudproxy::FileClient;
using cloudproxy::FileServer;
using cloudproxy::ScopedSSL;
using cloudproxy::SignedACL;
using cloudproxy::SignedSpeaksFor;
using cloudproxy::SpeaksFor;
using tao::CreateTempWhitelistDomain;
using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::GenerateSigningKey;
using tao::ScopedTempDir;
using tao::SerializePublicKey;
using tao::SignData;
using tao::TaoChildChannel;
using tao::TaoDomain;

class FileClientTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CHECK(CreateTempWhitelistDomain(&temp_dir_, &admin_));

    // Create a whitelist with some test programs.
    ASSERT_TRUE(admin_->Authorize("Test hash 1", TaoDomain::Sha256, "Test 1"));
    ASSERT_TRUE(admin_->Authorize("Test hash 2", TaoDomain::Sha256, "Test 2"));

    // set up file client
    string client_keys = *temp_dir_ + string("/client_keys");
    string server_addr("localhost");
    string server_port("11223");
    client_file_path_ = *temp_dir_ + string("/client_files");
    ASSERT_EQ(mkdir(client_file_path_.c_str(), 0700), 0);

    // create a fake tao with new keys, attestation, and a direct channel to it
    scoped_ptr<FakeTao> fake_tao;
    fake_tao.reset(new FakeTao(admin_->GetPolicyPrivateKeyPath(), "temppass"));
    ASSERT_TRUE(fake_tao->Init());
    direct_channel_.reset(
        new DirectTaoChildChannel(fake_tao.release(), "Test hash 1"));

    // create file client
    file_client_.reset(new FileClient(client_file_path_, client_keys,
                                      "clientpass", admin_->DeepCopy()));

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
        server_enc_dir, server_meta_dir, server_keys, "serverpass",
        signed_acl_path, server_addr, server_port, admin_->DeepCopy()));

    server_thread_.reset(new thread(&FileServer::Listen, file_server_.get(),
                                    direct_channel_.get(),
                                    true /* stop after one connection */));

    // Create a user and set up the SignedSpeaksFor for this user.
    string username = "tmroeder";
    scoped_ptr<Signer> tmroeder_key;
    tmroeder_key_path_ = *temp_dir_ + string("/") + username;
    ASSERT_EQ(mkdir(tmroeder_key_path_.c_str(), 0700), 0);
    SpeaksFor sf;
    sf.set_subject(username);
    // For these simple tests, we use the username as the password. Very secure.
    EXPECT_TRUE(GenerateSigningKey(
        keyczar::KeyType::RSA_PRIV, tmroeder_key_path_,
        "" /* do not save private key */, username, username, &tmroeder_key));
    sf.set_pub_key(SerializePublicKey(*tmroeder_key));

    string *sf_serialized = ssf.mutable_serialized_speaks_for();
    EXPECT_TRUE(sf.SerializeToString(sf_serialized));

    string *sf_sig = ssf.mutable_signature();
    EXPECT_TRUE(
        SignData(*sf_serialized, CloudUserManager::SpeaksForSigningContext,
                 sf_sig, admin_->GetPolicySigner()));

    tmroeder_ssf_path_ = *temp_dir_ + string("/tmroeder_ssf");
    ofstream ssf_file(tmroeder_ssf_path_.c_str());
    ASSERT_TRUE(ssf_file);
    EXPECT_TRUE(ssf.SerializeToOstream(&ssf_file));
    ssf_file.close();

    // Create a second user and set up the SignedSpeaksFor for this user.
    string username2 = "jlm";
    scoped_ptr<Signer> jlm_key;
    jlm_key_path_ = *temp_dir_ + string("/") + username2;
    ASSERT_EQ(mkdir(jlm_key_path_.c_str(), 0700), 0);
    SpeaksFor sf2;
    sf2.set_subject(username2);
    // For these simple tests, we use the username as the password. Very secure.
    EXPECT_TRUE(GenerateSigningKey(keyczar::KeyType::RSA_PRIV, jlm_key_path_,
                                   "" /* do not save private key */, username2,
                                   username2, &jlm_key));
    sf2.set_pub_key(SerializePublicKey(*jlm_key));

    string *sf_serialized2 = ssf2.mutable_serialized_speaks_for();
    EXPECT_TRUE(sf2.SerializeToString(sf_serialized2));

    string *sf_sig2 = ssf2.mutable_signature();
    EXPECT_TRUE(
        SignData(*sf_serialized2, CloudUserManager::SpeaksForSigningContext,
                 sf_sig2, admin_->GetPolicySigner()));

    jlm_ssf_path_ = *temp_dir_ + string("/jlm_ssf");
    ofstream ssf_file2(jlm_ssf_path_.c_str());
    ASSERT_TRUE(ssf_file2);
    EXPECT_TRUE(ssf2.SerializeToOstream(&ssf_file2));
    ssf_file2.close();

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

    ASSERT_TRUE(file_client_->Connect(*direct_channel_, server_addr,
                                      server_port, &ssl_));
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
  scoped_ptr<TaoChildChannel> direct_channel_;
  scoped_ptr<Signer> server_key_;
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
