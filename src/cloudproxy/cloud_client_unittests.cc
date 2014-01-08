//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Basic tests for the CloudClient class.
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

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_client.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/cloud_server.h"
#include "cloudproxy/util.h"
#include "tao/attestation.pb.h"
#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::CloudClient;
using cloudproxy::CloudServer;
using cloudproxy::CreateUserECDSAKey;
using cloudproxy::ScopedEvpPkey;
using cloudproxy::ScopedSSL;
using cloudproxy::SignedACL;
using cloudproxy::SpeaksFor;
using cloudproxy::SignedSpeaksFor;
using cloudproxy::WriteECDSAKey;
using keyczar::Keyczar;
using keyczar::Keyset;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::base::ScopedSafeString;
using std::ofstream;
using tao::CopyPublicKeyset;
using tao::CreateECDSAKey;
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

class CloudClientTest : public ::testing::Test {
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
    EC_KEY *pk = PEM_read_bio_ECPrivateKey(ec_file, NULL, NULL, (void*)dp);
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
    ASSERT_TRUE(policy_key_->Sign(*serialized_whitelist, signature));

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
    direct_channel_.reset(new DirectTaoChildChannel(fake_tao_.release(),
                                                    "Test hash 1"));
    ScopedSafeString client_secret(new string());
    ASSERT_TRUE(SealOrUnsealSecret(*direct_channel_, client_secret_path,
                                   client_secret.get()));

    whitelist_auth_.reset(new WhitelistAuth(whitelist_path,
                                            policy_pub_key_path));
    ASSERT_TRUE(whitelist_auth_->Init());

    cloud_client_.reset(new CloudClient(client_tls_cert, client_tls_key,
                                        *client_secret,
                                        policy_pub_key_path,
                                        policy_pub_key_pem, 
                                        whitelist_auth_.release()));

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
    EXPECT_TRUE(SignData(*ser, sig, policy_key_.get()))
      << "Could not sign the serialized ACL with the policy key";

    string signed_acl_path = *temp_dir_ + string("/signed_acl");
    ofstream acl_file(signed_acl_path.c_str(), ofstream::out);
    ASSERT_TRUE(acl_file) << "Could not open " << signed_acl_path;

    EXPECT_TRUE(sacl.SerializeToOstream(&acl_file))
      << "Could not write the signed ACL to a file";

    acl_file.close();

    // Start a server to listen for client connections.
    server_whitelist_auth_.reset(new WhitelistAuth(whitelist_path,
                                            policy_pub_key_path));
    ASSERT_TRUE(server_whitelist_auth_->Init());

    cloud_server_.reset(new CloudServer(server_tls_cert, server_tls_key,
                                        *server_secret, policy_pub_key_path,
                                        policy_pub_key_pem,
                                        signed_acl_path, server_addr,
                                        server_port,
                                        server_whitelist_auth_.release()));

    scoped_ptr<FakeTao> server_fake_tao(new FakeTao(policy_key_path));
    EXPECT_TRUE(server_fake_tao->Init());
    server_direct_channel_.reset(new DirectTaoChildChannel(server_fake_tao.release(), "Test hash 2"));

    server_thread_.reset(new thread(&CloudServer::Listen, cloud_server_.get(),
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
    EXPECT_TRUE(SignData(*sf_serialized, sf_sig, policy_key_.get()));

    tmroeder_ssf_path_ = *temp_dir_ + string("/tmroeder_ssf");
    ofstream ssf_file(tmroeder_ssf_path_.c_str());
    ASSERT_TRUE(ssf_file);
    EXPECT_TRUE(ssf.SerializeToOstream(&ssf_file));
    ssf_file.close();

    ASSERT_TRUE(cloud_client_->Connect(*direct_channel_, server_addr,
                                       server_port, &ssl_));
  }

  virtual void TearDown() {
    if (cloud_client_.get()) {
      EXPECT_TRUE(cloud_client_->Close(ssl_.get(), false));
    }

    if (server_thread_->joinable()) {
      server_thread_->join();
    }
  }

  scoped_ptr<thread> server_thread_;
  scoped_ptr<CloudClient> cloud_client_;
  scoped_ptr<CloudServer> cloud_server_;
  scoped_ptr<TaoAuth> server_whitelist_auth_;
  scoped_ptr<TaoAuth> whitelist_auth_;
  scoped_ptr<Tao> fake_tao_;
  scoped_ptr<TaoChildChannel> server_direct_channel_;
  scoped_ptr<TaoChildChannel> direct_channel_;
  scoped_ptr<Keyczar> policy_key_;
  scoped_ptr<Keyczar> policy_pub_key_;
  ScopedTempDir temp_dir_;
  ScopedSSL ssl_;
  SignedSpeaksFor ssf;
  string ser_ssf_;
  string tmroeder_key_path_;
  string tmroeder_ssf_path_;
};

TEST_F(CloudClientTest, UserTest) {
  string username("tmroeder");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_,
                                     username));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
}

TEST_F(CloudClientTest, CreateTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_,
                                     username));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, DestroyTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_,
                                     username));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, WriteTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_,
                                     username));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Read(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Write(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

