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

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/file_client.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/file_server.h"
#include "cloudproxy/util.h"
#include "tao/attestation.pb.h"
#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/tao_auth.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::CloudUserManager;
using cloudproxy::FileClient;
using cloudproxy::FileServer;
using cloudproxy::CreateUserECDSAKey;
using cloudproxy::ScopedEvpPkey;
using cloudproxy::ScopedSSL;
using cloudproxy::SignedACL;
using cloudproxy::SpeaksFor;
using cloudproxy::SignedSpeaksFor;
using cloudproxy::WriteECDSAKey;
using keyczar::CryptoFactory;
using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::Keyset;
using keyczar::KeyType;
using keyczar::RandImpl;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::base::ScopedSafeString;
using std::ifstream;
using std::ofstream;
using std::stringstream;
using tao::CopyPublicKeyset;
using tao::CreateECDSAKey;
using tao::CreateKey;
using tao::CreateTempPubKey;
using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::HostedProgram;
using tao::KeyczarPublicKey;
using tao::SealOrUnsealSecret;
using tao::ScopedTempDir;
using tao::SignData;
using tao::SignedWhitelist;
using tao::Tao;
using tao::TaoAuth;
using tao::TaoChildChannel;
using tao::Whitelist;
using tao::WhitelistAuth;

class FileClientTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempPubKey(&temp_dir_, &policy_key_))
        << "Could not create a policy key";

    // Export a public version of the keyset to policy_pub_key_path
    string policy_key_path = *temp_dir_ + string("/policy_pk");
    string policy_pub_key_path = *temp_dir_ + string("/pub_policy_key");
    ASSERT_EQ(mkdir(policy_pub_key_path.c_str(), 0700), 0);
    KeysetJSONFileWriter writer(policy_pub_key_path);
    ASSERT_TRUE(policy_key_->keyset()->PublicKeyExport(writer));

    // Export the keyczar key to an encrypted PEM file.
    string policy_pub_key_pem = *temp_dir_ + string("/pub_policy.pem");
    string dummy_password("dummy_password");
    string policy_key_pem = *temp_dir_ + string("/policy.key");
    ASSERT_TRUE(policy_key_->keyset()->ExportPrivateKey(policy_key_pem,
                                                        &dummy_password));

    // Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
    // So, they need to be added again.
    OpenSSL_add_all_algorithms();
    // Now import the OpenSSL key and write its public counterpart.
    const char *dp = "dummy_password";
    BIO *ec_file = BIO_new(BIO_s_file());
    BIO_read_filename(ec_file, policy_key_pem.c_str());
    EC_KEY *pk = PEM_read_bio_ECPrivateKey(ec_file, NULL, NULL, (void *)dp);
    ASSERT_TRUE(pk != nullptr);
    BIO_free(ec_file);
    ScopedEvpPkey pk_evp(EVP_PKEY_new());
    ASSERT_TRUE(EVP_PKEY_assign_EC_KEY(pk_evp.get(), pk));

    // This call from tao/util.h creates a self-signed X.509 certificate for the
    // key. It also writes a version of the private key, which we will put in a
    // dummy location for the purposes of this test.
    string dummy_private = *temp_dir_ + string("/dummy_private.key");
    ASSERT_TRUE(WriteECDSAKey(pk_evp, dummy_private, policy_pub_key_pem,
                              dummy_password, "US", "Google", "Policy Key"));

    string whitelist_path = *temp_dir_ + string("/whitelist");

    // Create a whitelist with some test programs.
    Whitelist w;
    HostedProgram *hp = w.add_programs();
    hp->set_name("Test 1");
    hp->set_hash_alg("SHA256");
    hp->set_hash("Test hash 1");

    HostedProgram *linux_tao_hp = w.add_programs();
    linux_tao_hp->set_name("Test 2");
    linux_tao_hp->set_hash_alg("SHA256");
    linux_tao_hp->set_hash("Test hash 2");

    SignedWhitelist sw;
    string *serialized_whitelist = sw.mutable_serialized_whitelist();
    ASSERT_TRUE(w.SerializeToString(serialized_whitelist));

    string *signature = sw.mutable_signature();
    ASSERT_TRUE(SignData(*serialized_whitelist,
                         WhitelistAuth::WhitelistSigningContext,
                         signature, policy_key_.get()));

    ofstream whitelist_file(whitelist_path.c_str(), ofstream::out);
    ASSERT_TRUE(sw.SerializeToOstream(&whitelist_file));
    whitelist_file.close();

    string client_dir = *temp_dir_ + string("/client");
    ASSERT_EQ(mkdir(client_dir.c_str(), 0700), 0);

    string client_tls_cert = client_dir + string("/cert");
    string client_tls_key = client_dir + string("/key");
    string client_secret_path = client_dir + string("/secret");
    string server_addr("localhost");
    string server_port("11223");

    fake_tao_.reset(new FakeTao(policy_key_path));
    EXPECT_TRUE(fake_tao_->Init());
    direct_channel_.reset(
        new DirectTaoChildChannel(fake_tao_.release(), "Test hash 1"));
    ScopedSafeString client_secret(new string());
    ASSERT_TRUE(SealOrUnsealSecret(*direct_channel_, client_secret_path,
                                   client_secret.get()));

    whitelist_auth_.reset(
        new WhitelistAuth(whitelist_path, policy_pub_key_path));
    ASSERT_TRUE(whitelist_auth_->Init());

    client_file_path_ = *temp_dir_ + string("/client_files");
    ASSERT_EQ(mkdir(client_file_path_.c_str(), 0700), 0);

    file_client_.reset(new FileClient(client_file_path_,
        client_tls_cert, client_tls_key, *client_secret, policy_pub_key_path,
        policy_pub_key_pem, whitelist_auth_.release()));

    string server_dir = *temp_dir_ + string("/server");
    ASSERT_EQ(mkdir(server_dir.c_str(), 0700), 0);

    string server_tls_cert = server_dir + string("/cert");
    string server_tls_key = server_dir + string("/key");
    string server_secret_path = server_dir + string("/secret");
    ScopedSafeString server_secret(new string());
    ASSERT_TRUE(SealOrUnsealSecret(*direct_channel_, server_secret_path,
                                   server_secret.get()));

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
                         policy_key_.get()))
        << "Could not sign the serialized ACL with the policy key";

    string signed_acl_path = *temp_dir_ + string("/signed_acl");
    ofstream acl_file(signed_acl_path.c_str(), ofstream::out);
    ASSERT_TRUE(acl_file) << "Could not open " << signed_acl_path;

    EXPECT_TRUE(sacl.SerializeToOstream(&acl_file))
        << "Could not write the signed ACL to a file";

    acl_file.close();

    // Start a server to listen for client connections.
    server_whitelist_auth_.reset(
        new WhitelistAuth(whitelist_path, policy_pub_key_path));
    ASSERT_TRUE(server_whitelist_auth_->Init());

    // Set up directories for the FileServer to store its files and metadata
    string server_enc_dir = *temp_dir_ + string("/enc_files");
    ASSERT_EQ(mkdir(server_enc_dir.c_str(), 0700), 0);

    string server_meta_dir = *temp_dir_ + string("/meta_files");
    ASSERT_EQ(mkdir(server_meta_dir.c_str(), 0700), 0);

    string file_server_key = *temp_dir_ + string("/file_server_key");
    ASSERT_EQ(mkdir(file_server_key.c_str(), 0700), 0);
    KeysetJSONFileWriter server_key_writer(file_server_key);
    ASSERT_TRUE(CreateKey(&server_key_writer, KeyType::HMAC,
                          KeyPurpose::SIGN_AND_VERIFY,
                          "file_server_key", &server_key_));
    server_key_->set_encoding(Keyczar::NO_ENCODING);

    file_server_.reset(new FileServer(server_enc_dir, server_meta_dir,
        server_tls_cert, server_tls_key, *server_secret, policy_pub_key_path,
        policy_pub_key_pem, signed_acl_path, file_server_key, server_addr,
        server_port, server_whitelist_auth_.release()));

    scoped_ptr<FakeTao> server_fake_tao(new FakeTao(policy_key_path));
    EXPECT_TRUE(server_fake_tao->Init());
    server_direct_channel_.reset(
        new DirectTaoChildChannel(server_fake_tao.release(), "Test hash 2"));

    server_thread_.reset(new thread(&FileServer::Listen, file_server_.get(),
                                    direct_channel_.get(),
                                    true /* stop after one connection */));

    // Create a user and set up the SignedSpeaksFor for this user.
    string username = "tmroeder";
    scoped_ptr<Keyczar> tmroeder_key;
    tmroeder_key_path_ = *temp_dir_ + string("/") + username;
    ASSERT_EQ(mkdir(tmroeder_key_path_.c_str(), 0700), 0);
    SpeaksFor sf;
    sf.set_subject(username);
    // For these simple tests, we use the username as the password. Very secure.
    EXPECT_TRUE(CreateUserECDSAKey(tmroeder_key_path_, username, username,
                                   &tmroeder_key));

    KeyczarPublicKey kpk;
    EXPECT_TRUE(SerializePublicKey(*tmroeder_key, &kpk));
    string *sf_key = sf.mutable_pub_key();
    EXPECT_TRUE(kpk.SerializeToString(sf_key));

    string *sf_serialized = ssf.mutable_serialized_speaks_for();
    EXPECT_TRUE(sf.SerializeToString(sf_serialized));

    string *sf_sig = ssf.mutable_signature();
    EXPECT_TRUE(SignData(*sf_serialized,
                         CloudUserManager::SpeaksForSigningContext, sf_sig,
                         policy_key_.get()));

    tmroeder_ssf_path_ = *temp_dir_ + string("/tmroeder_ssf");
    ofstream ssf_file(tmroeder_ssf_path_.c_str());
    ASSERT_TRUE(ssf_file);
    EXPECT_TRUE(ssf.SerializeToOstream(&ssf_file));
    ssf_file.close();

    // Create a second user and set up the SignedSpeaksFor for this user.
    string username2 = "jlm";
    scoped_ptr<Keyczar> jlm_key;
    jlm_key_path_ = *temp_dir_ + string("/") + username2;
    ASSERT_EQ(mkdir(jlm_key_path_.c_str(), 0700), 0);
    SpeaksFor sf2;
    sf2.set_subject(username2);
    // For these simple tests, we use the username as the password. Very secure.
    EXPECT_TRUE(CreateUserECDSAKey(jlm_key_path_, username2, username2,
                                   &jlm_key));

    KeyczarPublicKey kpk2;
    EXPECT_TRUE(SerializePublicKey(*jlm_key, &kpk2));
    string *sf_key2 = sf2.mutable_pub_key();
    EXPECT_TRUE(kpk2.SerializeToString(sf_key2));

    string *sf_serialized2 = ssf2.mutable_serialized_speaks_for();
    EXPECT_TRUE(sf2.SerializeToString(sf_serialized2));

    string *sf_sig2 = ssf2.mutable_signature();
    EXPECT_TRUE(SignData(*sf_serialized2,
                         CloudUserManager::SpeaksForSigningContext, sf_sig2,
                         policy_key_.get()));

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
    ASSERT_TRUE(rand->RandBytes(2*1000, &small_data));
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

  scoped_ptr<thread> server_thread_;
  scoped_ptr<FileClient> file_client_;
  scoped_ptr<FileServer> file_server_;
  scoped_ptr<TaoAuth> server_whitelist_auth_;
  scoped_ptr<TaoAuth> whitelist_auth_;
  scoped_ptr<Tao> fake_tao_;
  scoped_ptr<TaoChildChannel> server_direct_channel_;
  scoped_ptr<TaoChildChannel> direct_channel_;
  scoped_ptr<Keyczar> policy_key_;
  scoped_ptr<Keyczar> policy_pub_key_;
  scoped_ptr<Keyczar> server_key_;
  ScopedTempDir temp_dir_;
  ScopedSSL ssl_;
  SignedSpeaksFor ssf;
  SignedSpeaksFor ssf2;
  string ser_ssf_;
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
  EXPECT_TRUE(file_client_->Destroy(ssl_.get(), username, small_file_obj_name_));
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
  EXPECT_TRUE(file_client_->Destroy(ssl_.get(), username, small_file_obj_name_));

  EXPECT_TRUE(CompareFiles(small_file_,
                           client_file_path_ + string("/") + output_obj));
}

TEST_F(FileClientTest, MediumWriteTest) {
  string username("tmroeder");
  string output_obj("medium_out");
  EXPECT_TRUE(file_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      file_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(file_client_->Create(ssl_.get(), username, medium_file_obj_name_));
  EXPECT_TRUE(file_client_->Write(ssl_.get(), username, medium_file_obj_name_,
                                  medium_file_obj_name_));
  EXPECT_TRUE(file_client_->Read(ssl_.get(), username, medium_file_obj_name_,
                                 output_obj));
  EXPECT_TRUE(file_client_->Destroy(ssl_.get(), username, medium_file_obj_name_));

  EXPECT_TRUE(CompareFiles(medium_file_,
                           client_file_path_ + string("/") + output_obj));
}
