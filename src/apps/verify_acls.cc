//  File: verify_acls.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An app that verifies a SignedACL protobuf file
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
#include <google/protobuf/text_format.h>
#include <keyczar/base/scoped_ptr.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/tao_domain.h"

using std::string;

using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(acl_sig_file, "acls_sig", "The name of the signature file");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  // get the public key for verification
  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  string serialized_acl;
  CHECK(cloudproxy::ExtractACL(FLAGS_acl_sig_file, admin->GetPolicyVerifier(),
                               &serialized_acl))
      << "Could not verify and load the ACL file";

  string text;
  cloudproxy::ACL acls;
  acls.ParseFromString(serialized_acl);
  google::protobuf::TextFormat::PrintToString(acls, &text);
  LOG(INFO) << "The ACLs are: " << text;
  return 0;
}
