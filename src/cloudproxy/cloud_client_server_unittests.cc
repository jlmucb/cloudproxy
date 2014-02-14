//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Basic tests for the CloudClient and CloudServer classes.
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
#include "cloudproxy/cloud_client.h"
#include "cloudproxy/cloud_server.h"

#include <fstream>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/attestation.pb.h"
#include "tao/direct_tao_child_channel.h"
#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/keys.h"
#include "tao/tao_auth.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::ofstream;


using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::CloudClient;
using cloudproxy::CloudServer;
using cloudproxy::CloudUserManager;
using cloudproxy::ScopedSSL;
using cloudproxy::SignedACL;
using tao::CreateTempWhitelistDomain;
using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::Keys;
using tao::ScopedTempDir;
using tao::SignData;
using tao::TaoDomain;

class CloudClientTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CHECK(CreateTempWhitelistDomain(&temp_dir_, &admin_));

    // Create a whitelist with some test programs.
    ASSERT_TRUE(admin_->Authorize("Test hash 1", TaoDomain::Sha256, "Test 1"));
    ASSERT_TRUE(admin_->Authorize("Test hash 2", TaoDomain::Sha256, "Test 2"));
    ASSERT_TRUE(admin_->Authorize("FAKE_TPM", TaoDomain::FakeHash, "BogusTPM"));

    // set up cloud client
    string client_keys = *temp_dir_ + string("/client_keys");
    string server_addr("localhost");
    string server_port("11223");

    // create a fake tao with new keys, attestation, and a direct channel to it
    scoped_ptr<FakeTao> fake_tao;
    fake_tao.reset(new FakeTao());
    ASSERT_TRUE(fake_tao->InitTemporaryTPM(*admin_));

    // create cloud client
    cloud_client_.reset(new CloudClient(
        client_keys,
        new DirectTaoChildChannel(fake_tao->DeepCopy(), "Test hash 1"),
        admin_->DeepCopy()));

    // set up cloud server
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
    
    // Start a server to listen for client connections.
    cloud_server_.reset(new CloudServer(
        server_keys, signed_acl_path, server_addr, server_port,
        new DirectTaoChildChannel(fake_tao.release(), "Test hash 2"),
        admin_->DeepCopy()));

    server_thread_.reset(new thread(&CloudServer::Listen, cloud_server_.get(),
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

    // Hopefully the CLoudServer thread has had enough time to Listen()
    ASSERT_TRUE(cloud_client_->Connect(server_addr, server_port, &ssl_));

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
  ScopedTempDir temp_dir_;
  scoped_ptr<TaoDomain> admin_;
  ScopedSSL ssl_;
  string tmroeder_key_path_;
  string tmroeder_ssf_path_;
  string jlm_key_path_;
  string jlm_ssf_path_;
};

TEST_F(CloudClientTest, UserTest) {
  string username("tmroeder");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
}

TEST_F(CloudClientTest, UserFailTest) {
  string username("unknown user");
  EXPECT_FALSE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
}

TEST_F(CloudClientTest, UserDirFailTest) {
  string username("tmroeder");
  string dir("Not the right directory");
  EXPECT_FALSE(cloud_client_->AddUser(username, dir, username));
}

TEST_F(CloudClientTest, UserPwdFailTest) {
  string username("tmroeder");
  string password("Wrong password");
  EXPECT_FALSE(cloud_client_->AddUser(username, tmroeder_key_path_, password));
}

TEST_F(CloudClientTest, CreateTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, UnauthFailTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_FALSE(cloud_client_->Create(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, DestroyTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, DestroyFailTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_FALSE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, ReadTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Read(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, ReadFailTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_FALSE(cloud_client_->Read(ssl_.get(), username, obj, obj));
}

TEST_F(CloudClientTest, WriteFailTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_FALSE(cloud_client_->Write(ssl_.get(), username, obj, obj));
}

TEST_F(CloudClientTest, WriteTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, tmroeder_key_path_, username));
  EXPECT_TRUE(
      cloud_client_->Authenticate(ssl_.get(), username, tmroeder_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Read(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Write(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, InsufficientPrivilegeTest) {
  string username("jlm");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, jlm_key_path_, username));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, jlm_ssf_path_));
  EXPECT_FALSE(cloud_client_->Create(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, SimplePrivilegeTest) {
  string username("jlm");
  string obj("/files");
  EXPECT_TRUE(cloud_client_->AddUser(username, jlm_key_path_, username));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, jlm_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
}
