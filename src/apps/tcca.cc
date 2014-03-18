//  File: tcca.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A Tao Certificate Authority
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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/tao_ca.h"
#include "tao/tao_ca_server.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using tao::InitializeApp;
using tao::TaoCA;
using tao::TaoCAServer;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "", "A password for the policy private key");
DEFINE_bool(stop, false, "Request shutdown of existing server");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  {
    TaoDomain *a = TaoDomain::Load(FLAGS_config_path, "");
    delete a;
  }
  {
    TaoDomain *a = TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass);
    delete a;
  }

  scoped_ptr<TaoDomain> admin(
      TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  if (FLAGS_stop) {
    TaoCA ca(admin.get());
    CHECK(ca.Shutdown()) << "Could not shut down Tao CA Server";
  } else {
    CHECK(!FLAGS_policy_pass.empty()) << "TaoCAServer requires policy password";

    TaoCAServer ca(admin.release());
    CHECK(ca.Init()) << "Could not initialize Tao CA Server";
    CHECK(ca.Listen()) << "Could not listen on Tao CA Server";
    CHECK(ca.Destroy()) << "Could not destroy Tao CA Server";
  }

  return 0;
}
