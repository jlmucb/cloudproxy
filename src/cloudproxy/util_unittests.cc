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

#include <fstream>
#include <sstream>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/tao_domain.h"

using std::ifstream;
using std::ofstream;
using std::stringstream;

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CloudAuth;
using cloudproxy::ExtractACL;
using cloudproxy::ScopedSSLCtx;
using cloudproxy::SetUpSSLCTX;
using cloudproxy::SignedACL;
using tao::CreateSelfSignedX509;
using tao::CreateTempDir;
using tao::CreateTempWhitelistDomain;
using tao::GenerateSigningKey;
using tao::ScopedEvpPkey;
using tao::ScopedFile;
using tao::ScopedTempDir;
using tao::SerializeX509;
using tao::SignData;
using tao::TaoDomain;

TEST(CloudProxyUtilTest, X509Test) {
  ScopedTempDir temp_dir;
  ASSERT_TRUE(CreateTempDir("cloud_proxy_util_test", &temp_dir));

  string priv_key_path = *temp_dir + "/cloudclient_private.key";
  string pub_key_path = *temp_dir + "/cloudclient_public.key";
  string tls_cert_path = *temp_dir + "/cloudclient.cert";
  scoped_ptr<keyczar::Signer> key;
  EXPECT_TRUE(GenerateSigningKey(priv_key_path, pub_key_path, "test client key",
                                 "dummy_password", &key));
  EXPECT_TRUE(CreateSelfSignedX509(key.get(), "US", "Washington", "Google",
                                   "testclient", tls_cert_path));

  ScopedFile x509_file(fopen(tls_cert_path.c_str(), "r"));
  ASSERT_TRUE(x509_file.get() != nullptr);
  X509 *x = nullptr;
  PEM_read_X509(x509_file.get(), &x, nullptr, nullptr);
  ASSERT_TRUE(x != nullptr);

  string serialized_x509;
  EXPECT_TRUE(SerializeX509(x, &serialized_x509));

  // Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
  // So, they need to be added again. Typical error is:
  // * 336236785:SSL routines:SSL_CTX_new:unable to load ssl2 md5 routines
  // This needs to be done as close to SSL_CTX_new as possible.
  OpenSSL_add_all_algorithms();
  ScopedSSLCtx ctx(SSL_CTX_new(TLSv1_2_client_method()));

  EXPECT_TRUE(SetUpSSLCTX(ctx.get(), tls_cert_path, key.get()));
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
  EXPECT_TRUE(SignData(*ser, CloudAuth::ACLSigningContext, sig,
                       admin->GetPolicySigner()))
      << "Could not sign the serialized ACL with the policy key";

  string signed_acl_path = *temp_dir + string("/signed_acl");
  ofstream acl_file(signed_acl_path.c_str(), ofstream::out);
  ASSERT_TRUE(acl_file) << "Could not open " << signed_acl_path;

  EXPECT_TRUE(sacl.SerializeToOstream(&acl_file))
      << "Could not write the signed acl to a file";

  acl_file.close();

  string acl_out;
  EXPECT_TRUE(
      ExtractACL(signed_acl_path, admin->GetPolicyVerifier(), &acl_out));
  ACL deserialized_acl;
  EXPECT_TRUE(deserialized_acl.ParseFromString(acl_out));
}
