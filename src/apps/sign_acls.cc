//  File: sign_acls.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An app that reads and signs a file containing an ACL
//  protobuf
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

#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

using cloudproxy::CloudAuth;
using tao::SignData;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "cppolicy", "A password for the policy private key");

DEFINE_string(acl_file, "acls", "The name of the acl protobuf file to sign");
DEFINE_string(acl_sig_file, "acls_sig", "The name of the signature file");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  google::ParseCommandLineFlags(&argc, &argv, true);
  // load the acl protobuf file
  string acl;
  CHECK(ReadFileToString(FLAGS_acl_file, &acl))
      << "Could not read any bytes from the acls file";

  // sign this serialized data with admin policy key
  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass));
  CHECK(admin.get() != nullptr) << "Could not load configuration";
  string sig;
  CHECK(SignData(acl, CloudAuth::ACLSigningContext, &sig,
                 admin->GetPolicySigner())) << "Could not sign acl file";

  cloudproxy::SignedACL sacl;
  sacl.set_serialized_acls(acl);
  sacl.set_signature(sig);

  string serialized;
  CHECK(sacl.SerializeToString(&serialized)) << "Could not serialize the"
                                                " signed ACLs";

  CHECK(WriteStringToFile(FLAGS_acl_sig_file, serialized));
  return 0;
}
