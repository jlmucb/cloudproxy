//  File: tao_admin.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Produces an attestation for a keyczar key
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
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/file_util.h>

#include "tao/fake_tao.h"
#include "tao/hosted_programs.pb.h"
#include "tao/tao_domain.h"
#include "tao/whitelist_auth.h"

using std::getline;
using std::string;
using std::stringstream;

using keyczar::base::ReadFileToString;

using tao::FakeTao;
using tao::TaoAuth;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "", "A password for the policy private key");

DEFINE_string(init, "",
              "Initialize a new configuration using the given template");
DEFINE_string(name, "test tao", "Name for a new configuration");
DEFINE_string(commonname, "tao", "x509 Common Name for a new configuration");
DEFINE_string(country, "US", "x509 Country for a new configuration");
DEFINE_string(org, "Google", "x509 Organization for a new configuration");

DEFINE_string(
    whitelist, "",
    "Comma separated list of program or hash:alg:name values to whitelist");

DEFINE_string(make_fake_tpm, "",
              "Directory to store a new and attested fake tpm");

// In-place replacement of all occurrences in s of x with y
void StringReplaceAll(const string &x, const string &y, string *s) {
  for (size_t i = s->find(x); i != string::npos; i = s->find(x, i + x.length()))
    s->replace(i, x.length(), y);
}

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  scoped_ptr<TaoDomain> admin;

  bool did_work = false;

  if (!FLAGS_init.empty()) {
    VLOG(0) << "Initializing new configuration in " << FLAGS_config_path;
    VLOG(0) << "  using template " << FLAGS_init;
    string initial_config;
    CHECK(ReadFileToString(FLAGS_init, &initial_config));
    StringReplaceAll("<NAME>", FLAGS_name, &initial_config);
    StringReplaceAll("<COMMONNAME>", FLAGS_commonname, &initial_config);
    StringReplaceAll("<COUNTRY>", FLAGS_country, &initial_config);
    StringReplaceAll("<ORGANIZATION>", FLAGS_org, &initial_config);
    admin.reset(TaoDomain::Create(initial_config, FLAGS_config_path,
                                  FLAGS_policy_pass));
    CHECK_NOTNULL(admin.get());
    did_work = true;
  } else {
    VLOG(0) << "Loading configuration from " << FLAGS_config_path;
    admin.reset(TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass));
    CHECK_NOTNULL(admin.get());
  }

  if (!FLAGS_whitelist.empty()) {
    stringstream principals(FLAGS_whitelist);
    string principal;
    while (getline(principals, principal, ',')) {  // split on commas
      string hash, alg, name;
      stringstream ss(principal);
      if (getline(ss, hash, ':') && getline(ss, alg, ':') &&
          getline(ss, name) && ss.eof()) {
        VLOG(0) << "Adding principal to whitelist: " << principal;
        CHECK(admin->Authorize(hash, alg, name));
      } else {
        VLOG(0) << "Adding program to whitelist: " << principal;
        CHECK(admin->AuthorizeProgram(principal));
      }
    }
    did_work = true;
  }

  if (!FLAGS_make_fake_tpm.empty()) {
    string path = admin->GetPath(FLAGS_make_fake_tpm);
    VLOG(0) << "Initializing fake tpm in " << path;
    scoped_ptr<FakeTao> ft(new FakeTao());
    if (!ft->InitPseudoTPM(path, *admin)) return 1;
    did_work = true;
  }

  if (!did_work) {
    VLOG(0) << "  name: " << admin->GetName();
    VLOG(0) << "  policy key: ";
    VLOG(0) << "    public: " << admin->GetPolicyKeys()->SigningPublicKeyPath();
    VLOG(0)
        << "    private: " << admin->GetPolicyKeys()->SigningPrivateKeyPath();
    VLOG(0) << "  tao ca: " << admin->GetTaoCAHost() << ":"
            << admin->GetTaoCAPort();
    VLOG(0) << "  auth type: " << admin->GetAuthType();
    // TODO(kwalsh) Rewrite without dynamic cast once there is a convention for
    // objects to print themselves in a user-friendly format. Perhaps each
    // TaoAuth (or other) object should be able to print itself to an ostream?
    // WhitelistAuth *w = dynamic_cast<WhitelistAuth *>(admin);
    // if (w != nullptr) {
    //   for (int i = 0; i w->WhitelistCount(); i++) {
    //     string hash, alg, name;
    //     w->WhitelistEntry(i, &hash, &alg, &name);
    //     VLOG(0) << "  " << hash << ":" << alg << ":" << name;
    //   }
    // }
  }

  return 0;
}
