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

#include <thread>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/file_util.h>

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

using std::thread;

using keyczar::base::WriteStringToFile;

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::CloudClient;
using cloudproxy::CloudServer;
using cloudproxy::CloudUserManager;
using cloudproxy::ScopedSSL;
using cloudproxy::SignedACL;
using tao::CreateTempACLsDomain;
using tao::DirectTaoChildChannel;
using tao::FakeTao;
using tao::Keys;
using tao::ScopedTempDir;
using tao::SignData;
using tao::TaoDomain;

class CloudClientTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CHECK(CreateTempACLsDomain(&temp_dir_, &admin_));

    // Create ACLs for some test programs.
    ASSERT_TRUE(admin_->Authorize(
        "::TrustedOS::"
        "Program(1, \"Test1Path\", \"Test1ProgHash\", \"Test1ArgHash\")",
        "Execute", list<string>{}));
    ASSERT_TRUE(admin_->Authorize(
        "::TrustedOS::"
        "Program(2, \"Test2Path\", \"Test2ProgHash\", \"Test2ArgHash\")",
        "Execute", list<string>{}));

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
        0 /* policy */, admin_->DeepCopy()));
    ASSERT_TRUE(cloud_client_->Init());

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
    EXPECT_TRUE(SignData(*admin_->GetPolicySigner(), *ser,
                         CloudAuth::ACLSigningContext, sig))
        << "Could not sign the serialized ACL with the policy key";

    string signed_acl_path = *temp_dir_ + string("/signed_acl");
    string serialized_acl;
    EXPECT_TRUE(sacl.SerializeToString(&serialized_acl))
        << "Could not serialized the signed ACL";
    ASSERT_TRUE(WriteStringToFile(signed_acl_path, serialized_acl));

    // Start a server to listen for client connections.
    cloud_server_.reset(new CloudServer(
        server_keys, signed_acl_path, server_addr, server_port,
        new DirectTaoChildChannel(fake_tao.release(), "Test hash 2"),
        0 /* policy */, admin_->DeepCopy()));
    ASSERT_TRUE(cloud_server_->Init());

    server_thread_.reset(new thread(&CloudServer::Listen, cloud_server_.get(),
                                    true /* stop after one connection */));

    // Create two users and matching delegations.
    string u;
    string users_path = *temp_dir_ + "/users";

    u = "tmroeder";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &tmr_key_));
    tmr_ssf_path_ = tmr_key_->GetPath(CloudUserManager::UserDelegationSuffix);

    u = "jlm";
    ASSERT_TRUE(CloudUserManager::MakeNewUser(
        users_path, u, u, *admin_->GetPolicySigner(), &jlm_key_));
    jlm_ssf_path_ = jlm_key_->GetPath(CloudUserManager::UserDelegationSuffix);

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
  string tmr_ssf_path_;
  string jlm_ssf_path_;
  scoped_ptr<Keys> tmr_key_;
  scoped_ptr<Keys> jlm_key_;
};

TEST_F(CloudClientTest, UserTest) {
  string username("tmroeder");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
}

TEST_F(CloudClientTest, UserFailTest) {
  string username("wrong user");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_FALSE(
      cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
}

TEST_F(CloudClientTest, CreateTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
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
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, DestroyFailTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
  EXPECT_FALSE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, ReadTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Read(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, ReadFailTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
  EXPECT_FALSE(cloud_client_->Read(ssl_.get(), username, obj, obj));
}

TEST_F(CloudClientTest, WriteFailTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
  EXPECT_FALSE(cloud_client_->Write(ssl_.get(), username, obj, obj));
}

TEST_F(CloudClientTest, WriteTest) {
  string username("tmroeder");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, *tmr_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, tmr_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
  EXPECT_TRUE(cloud_client_->Read(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Write(ssl_.get(), username, obj, obj));
  EXPECT_TRUE(cloud_client_->Destroy(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, InsufficientPrivilegeTest) {
  string username("jlm");
  string obj("test_obj");
  EXPECT_TRUE(cloud_client_->AddUser(username, *jlm_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, jlm_ssf_path_));
  EXPECT_FALSE(cloud_client_->Create(ssl_.get(), username, obj));
}

TEST_F(CloudClientTest, SimplePrivilegeTest) {
  string username("jlm");
  string obj("/files");
  EXPECT_TRUE(cloud_client_->AddUser(username, *jlm_key_->Signer()));
  EXPECT_TRUE(cloud_client_->Authenticate(ssl_.get(), username, jlm_ssf_path_));
  EXPECT_TRUE(cloud_client_->Create(ssl_.get(), username, obj));
}
