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

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/file_util.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/util.h"
#include "tao/fake_tao.h"
#include "tao/util.h"

using keyczar::base::WriteStringToFile;

using cloudproxy::CloudAuth;
using tao::CreateTempWhitelistDomain;
using tao::ScopedTempDir;
using tao::TaoDomain;

class CloudAuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempWhitelistDomain(&temp_dir_, &admin_));

    // Set up a simple ACL to query.
    string acl =
        "permissions { subject: \"tmroeder\" verb: ADMIN }\n"
        "permissions { subject: \"jlm\" verb: CREATE object: \"/files\" }\n";

    string acl_path = *temp_dir_ + "/acls";
    string acl_sig_path = *temp_dir_ + "/acls_sig";
    ASSERT_TRUE(WriteStringToFile(acl_path, acl));

    ASSERT_TRUE(
        CloudAuth::SignACL(admin_->GetPolicySigner(), acl_path, acl_sig_path));

    cloud_auth_.reset(new CloudAuth(acl_sig_path, admin_->GetPolicyVerifier()));
  }

  scoped_ptr<CloudAuth> cloud_auth_;
  scoped_ptr<TaoDomain> admin_;
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
