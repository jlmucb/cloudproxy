//  File: util_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Tests for CloudProxy utility functions.
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
#include "tao/util.h"

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/file_util.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/tao_domain.h"

using keyczar::base::WriteStringToFile;

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::ExtractACL;
using cloudproxy::ScopedSSLCtx;
using cloudproxy::SetUpSSLClientCtx;
using cloudproxy::SetUpSSLServerCtx;
using cloudproxy::SignedACL;
using tao::CreateSelfSignedX509;
using tao::CreateTempDir;
using tao::CreateTempWhitelistDomain;
using tao::Keys;
using tao::ScopedTempDir;
using tao::SignData;
using tao::TaoDomain;

TEST(CloudProxyUtilTest, X509SSLTest) {
  ScopedTempDir temp_dir;
  ASSERT_TRUE(CreateTempDir("cloud_proxy_util_test", &temp_dir));

  scoped_ptr<Keys> key(new Keys(*temp_dir, "test client key", Keys::Signing));
  ASSERT_TRUE(key->InitNonHosted("dummy_password"));
  ASSERT_TRUE(
      key->CreateSelfSignedX509("US", "Washington", "Google", "testclient"));

  ScopedSSLCtx ctx;
  EXPECT_TRUE(SetUpSSLServerCtx(*key, &ctx));
  EXPECT_TRUE(SetUpSSLClientCtx(*key, &ctx));
}

TEST(CloudProxyUtilTest, ExtractACLTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<TaoDomain> admin;
  ASSERT_TRUE(CreateTempWhitelistDomain(&temp_dir, &admin));

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
  EXPECT_TRUE(SignData(*admin->GetPolicySigner(), *ser,
                       CloudAuth::ACLSigningContext, sig))
      << "Could not sign the serialized ACL with the policy key";

  string signed_acl_path = *temp_dir + string("/signed_acl");
  string serialized_acl;
  EXPECT_TRUE(sacl.SerializeToString(&serialized_acl))
      << "Could not serialized the signed ACL";
  ASSERT_TRUE(WriteStringToFile(signed_acl_path, serialized_acl));

  string acl_out;
  EXPECT_TRUE(
      ExtractACL(signed_acl_path, admin->GetPolicyVerifier(), &acl_out));
  ACL deserialized_acl;
  EXPECT_TRUE(deserialized_acl.ParseFromString(acl_out));
}
