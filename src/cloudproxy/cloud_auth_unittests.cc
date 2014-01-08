//  File: cloud_auth_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Basic tests for the CloudAuth class.
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

#include <fstream>

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/util.h"
#include "tao/fake_tao.h"
#include "tao/util.h"

using cloudproxy::CloudAuth;
using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::SignedACL;

using keyczar::Keyczar;

using std::ofstream;

using tao::CreateTempPubKey;
using tao::ScopedTempDir;
using tao::SignData;

class CloudAuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_TRUE(CreateTempPubKey(&temp_dir_, &policy_public_key_))
        << "Could not create a public key";

    // Set up a simple ACL to query.
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
    EXPECT_TRUE(SignData(*ser, sig, policy_public_key_.get()))
        << "Could not sign the serialized ACL with the policy key";

    string signed_whitelist_path = *temp_dir_ + string("/signed_whitelist");
    ofstream whitelist_file(signed_whitelist_path.c_str(), ofstream::out);
    ASSERT_TRUE(whitelist_file) << "Could not open " << signed_whitelist_path;

    EXPECT_TRUE(sacl.SerializeToOstream(&whitelist_file))
        << "Could not write the signed whitelist to a file";

    whitelist_file.close();

    cloud_auth_.reset(
        new CloudAuth(signed_whitelist_path, policy_public_key_.get()));
  }

  scoped_ptr<CloudAuth> cloud_auth_;
  scoped_ptr<Keyczar> policy_public_key_;
  ScopedTempDir temp_dir_;
};

TEST_F(CloudAuthTest, AdminTest) {
  // Admin privileges should allow tmroeder to perform any operation.
  EXPECT_TRUE(cloud_auth_->Permitted("tmroeder", cloudproxy::CREATE, "/files"));
  EXPECT_TRUE(
      cloud_auth_->Permitted("tmroeder", cloudproxy::DESTROY, "/files"));
  EXPECT_TRUE(cloud_auth_->Permitted("tmroeder", cloudproxy::READ, "/files_2"));
  EXPECT_TRUE(cloud_auth_->Permitted("tmroeder", cloudproxy::WRITE, "/asdf"));
}

TEST_F(CloudAuthTest, UnknownUserTest) {
  EXPECT_FALSE(
      cloud_auth_->Permitted("unknown_user", cloudproxy::CREATE, "/files"));
  EXPECT_FALSE(
      cloud_auth_->Permitted("unknown_user", cloudproxy::DESTROY, "/files"));
  EXPECT_FALSE(
      cloud_auth_->Permitted("unknown_user", cloudproxy::READ, "/files_2"));
  EXPECT_FALSE(
      cloud_auth_->Permitted("unknown_user", cloudproxy::WRITE, "/asdf"));
}

TEST_F(CloudAuthTest, LimitedUserTest) {
  // A user with limited permissions should only be allowed those permissions.
  EXPECT_TRUE(cloud_auth_->Permitted("jlm", cloudproxy::CREATE, "/files"));
  EXPECT_FALSE(cloud_auth_->Permitted("jlm", cloudproxy::DESTROY, "/files"));
  EXPECT_FALSE(cloud_auth_->Permitted("jlm", cloudproxy::READ, "/files"));
  EXPECT_FALSE(cloud_auth_->Permitted("jlm", cloudproxy::WRITE, "/files"));
}

TEST_F(CloudAuthTest, AddPermissionsTest) {
  // Permissions can be added to the ACL
  EXPECT_FALSE(
      cloud_auth_->Permitted("unknown_user", cloudproxy::CREATE, "/files"));
  EXPECT_TRUE(cloud_auth_->Insert("jlm", cloudproxy::DESTROY, "/files"));
  EXPECT_TRUE(cloud_auth_->Permitted("jlm", cloudproxy::DESTROY, "/files"));
}

TEST_F(CloudAuthTest, DeletePermissionsTest) {
  EXPECT_TRUE(cloud_auth_->Permitted("jlm", cloudproxy::CREATE, "/files"));
  EXPECT_TRUE(cloud_auth_->Delete("jlm", cloudproxy::CREATE, "/files"));
  EXPECT_FALSE(cloud_auth_->Permitted("jlm", cloudproxy::CREATE, "/files"));
}

TEST_F(CloudAuthTest, DeletePermissionsFailTest) {
  // You can't delete permissions that aren't there.
  EXPECT_FALSE(cloud_auth_->Delete("jlm", cloudproxy::READ, "/files"));
  EXPECT_FALSE(cloud_auth_->Delete("jlm", cloudproxy::CREATE, "/files_2"));
  EXPECT_FALSE(cloud_auth_->Delete("tmroeder", cloudproxy::CREATE, "/files"));
}

TEST_F(CloudAuthTest, SerializeTest) {
  string serialized_auth;
  EXPECT_TRUE(cloud_auth_->Serialize(&serialized_auth));
}
