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
#include <cstdio>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

//#include "cloudproxy/cloud_auth.h"
//#include "cloudproxy/cloud_user_manager.h"
//#include "tao/acl_guard.h"
#include "tao/linux_process_factory.h"
//#include "tao/hosted_programs.pb.h"
#include "tao/keys.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::getline;
using std::string;
using std::stringstream;
using std::list;

//using cloudproxy::CloudAuth;
//using cloudproxy::CloudUserManager;
using tao::Keys;
using tao::LinuxProcessFactory;
using tao::ReadFileToString;
using tao::TaoDomain;
using tao::Term;
using tao::elideString;
using tao::unique_ptr;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "", "A password for the policy private key");

DEFINE_string(init, "",
              "Initialize a new configuration using the given template");
DEFINE_string(name, "test tao", "Name for a new configuration");
DEFINE_string(commonname, "Linux Tao",
              "x509 Common Name for a new configuration");
DEFINE_string(country, "US", "x509 Country for a new configuration");
DEFINE_string(state, "Washington", "x509 State for a new configuration");
DEFINE_string(org, "(not really) Google",
              "x509 Organization for a new configuration");


DEFINE_string(canexecute, "",
              "Comma-separated list of paths of programs "
              "to be authorized to execute");
DEFINE_string(host, "",
              "The principal name of the host where programs will execute.");

//DEFINE_string(canclaim, "",
//              "Comma-separated list of name:subprin pairs "
//              "to be authorized for claiming policy subprincipal names");
// DEFINE_bool(clear_acls, false,
//            "Remove all ACL entries before adding new ones");


//DEFINE_string(newusers, "", "Comma separated list of user names to create");
//DEFINE_string(user_keys, "user_keys", "Directory for storing new user keys");

//DEFINE_string(signacl, "", "A text-based ACL file to sign");
//DEFINE_string(acl_sig_path, "acls_sig", "Location for storing signed ACL file");

// In-place replacement of all occurrences in s of x with y
void StringReplaceAll(const string &x, const string &y, string *s) {
  for (size_t i = s->find(x); i != string::npos; i = s->find(x, i + x.length()))
    s->replace(i, x.length(), y);
}

int main(int argc, char **argv) {
  string usage = "Administrative utility for TaoDomain.\nUsage:\n  ";
  google::SetUsageMessage(usage + argv[0] + " [options]");
  tao::InitializeApp(&argc, &argv, true);

  scoped_ptr<TaoDomain> admin;

  bool did_work = false;

  if (!FLAGS_init.empty()) {
    printf("Initializing new configuration in: %s\n", FLAGS_config_path.c_str());
    string initial_config;
    CHECK(ReadFileToString(FLAGS_init, &initial_config));
    StringReplaceAll("<NAME>", FLAGS_name, &initial_config);
    StringReplaceAll("<COMMONNAME>", FLAGS_commonname, &initial_config);
    StringReplaceAll("<COUNTRY>", FLAGS_country, &initial_config);
    StringReplaceAll("<STATE>", FLAGS_state, &initial_config);
    StringReplaceAll("<ORGANIZATION>", FLAGS_org, &initial_config);
    admin.reset(TaoDomain::Create(initial_config, FLAGS_config_path,
                                  FLAGS_policy_pass));
    CHECK_NOTNULL(admin.get());
    did_work = true;
  } else {
    printf("Loading configuration from: %s\n", FLAGS_config_path.c_str());
    admin.reset(TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass));
    CHECK_NOTNULL(admin.get());
  }

  if (!FLAGS_canexecute.empty()) {
    // TODO(kwalsh) For host, we could deserialize Tao from env var then call
    // GetTaoName(), then append policy prin. Or assume linuxhost and call
    // GetTaoName for that.
    string host = FLAGS_host;
    CHECK(!host.empty());
    // TODO(kwalsh) We assume LinuxHost and LinuxProcessFactory here.
    // string policy_subprin;
    //CHECK(admin->GetSubprincipalName(&policy_subprin));
    //host += "::" + policy_subprin;
    LinuxProcessFactory factory;
    string child_subprin;
    stringstream paths(FLAGS_canexecute);
    string path;
    while (getline(paths, path, ',')) {  // split on commas
      int next_id = 0; // assume no IDs.
      CHECK(factory.MakeHostedProgramSubprin(next_id, path, &child_subprin));

      printf("Authorizing program to execute:\n"
             "  path: %s\n"
             "  host: %s\n"
             "  name: ::%s\n",
             path.c_str(), elideString(host).c_str(),
             elideString(child_subprin).c_str());
      CHECK(admin->Authorize(host+"::"+child_subprin, "Execute", list<unique_ptr<Term>>{}));
    }
    did_work = true;
  }

//  if (!FLAGS_newusers.empty()) {
//    stringstream names(FLAGS_newusers);
//    string name;
//    while (getline(names, name, ',')) {  // split on commas
//      string password = name;            // such security, wow
//      scoped_ptr<tao::Keys> key;
//      CHECK(CloudUserManager::MakeNewUser(FLAGS_user_keys, name, password,
//                                          *admin->GetPolicySigner(), &key));
//    }
//    did_work = true;
//  }

//  if (!FLAGS_signacl.empty()) {
//    CHECK(CloudAuth::SignACL(admin->GetPolicySigner(), FLAGS_signacl,
//                             FLAGS_acl_sig_path));
//    did_work = true;
//  }

  if (!did_work) {
    VLOG(0) << "  name: " << admin->GetName();
    VLOG(0) << "  policy key: ";
    VLOG(0) << "    public: " << admin->GetPolicyKeys()->SigningPublicKeyPath();
    VLOG(0) << "    private: "
            << admin->GetPolicyKeys()->SigningPrivateKeyPath();
    VLOG(0) << "  tao ca: " << admin->GetTaoCAHost() << ":"
            << admin->GetTaoCAPort();
    VLOG(0) << "  auth type: " << admin->GetAuthType();
    VLOG(0) << admin->DebugString();
  }

  return 0;
}
