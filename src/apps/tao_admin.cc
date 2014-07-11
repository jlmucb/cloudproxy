//  File: tao_admin.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Interface for various Tao setup and admin operations.
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
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/keys.h"
#include "tao/linux_process_factory.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::list;
using std::string;

// using cloudproxy::CloudAuth;
// using cloudproxy::CloudUserManager;
using tao::LinuxProcessFactory;
using tao::ReadFileToString;
using tao::TaoDomain;
using tao::elideString;

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

DEFINE_string(canexecute, "", "Path of a program to be authorized to execute");
DEFINE_string(retractcanexecute, "",
              "Path of a program to retract authorization to execute");
DEFINE_string(host, "",
              "The principal name of the host where programs will execute.");

DEFINE_string(add, "", "A policy rule to be added");
DEFINE_string(retract, "", "A policy rule to be retracted");
DEFINE_bool(clear, false, "Clear all policy rules before other changes");
DEFINE_string(query, "", "A policy query to be checked");

DEFINE_string(getprogramhash, "", "Path of program to be hashed");

DEFINE_bool(quiet, false, "Be more quiet");
DEFINE_bool(show, false, "Show info when done");

// DEFINE_string(canclaim, "",
//              "Comma-separated list of name:subprin pairs "
//              "to be authorized for claiming policy subprincipal names");
// DEFINE_bool(clear_acls, false,
//            "Remove all ACL entries before adding new ones");

// DEFINE_string(newusers, "", "Comma separated list of user names to create");
// DEFINE_string(user_keys, "user_keys", "Directory for storing new user keys");

// DEFINE_string(signacl, "", "A text-based ACL file to sign");
// DEFINE_string(acl_sig_path, "acls_sig", "Location for storing signed ACL
// file");

// In-place replacement of all occurrences in s of x with y
void StringReplaceAll(const string &x, const string &y, string *s) {
  for (size_t i = s->find(x); i != string::npos; i = s->find(x, i + x.length()))
    s->replace(i, x.length(), y);
}

string getEnvString(const string &name) {
  const char *p = getenv(name.c_str());
  if (p == nullptr)
    return "";
  else
    return string(p);
}

void handleCanExecute(TaoDomain *admin, const string &path, bool retract) {
  // TODO(kwalsh) For host, we could deserialize Tao from env var then call
  // GetTaoName(), then append policy prin. Or assume linuxhost and call
  // GetTaoName for that.
  string host = FLAGS_host;
  if (host.empty()) {
    host = getEnvString("GOOGLE_TAO_LINUX");
  }
  // if (host.empty()) {
  //   host = getEnvString("GOOGLE_TAO_TPM");
  //   string pcrs = getEnvString("GOOGLE_TAO_PCRS");
  //   if (!host.empty() &&  !pcrs.empty()) {
  //     host += "::" + pcrs;
  //   }
  // }
  CHECK(!host.empty());
  // TODO(kwalsh) We assume LinuxHost and LinuxProcessFactory here.
  // string policy_subprin;
  // CHECK(admin->GetSubprincipalName(&policy_subprin));
  // host += "::" + policy_subprin;
  LinuxProcessFactory factory;
  string child_subprin;
  int next_id = 0;  // assume no IDs.
  CHECK(factory.MakeHostedProgramSubprin(next_id, path, &child_subprin));

  if (retract) {
    if (!FLAGS_quiet)
      printf(
          "Retracting program authorization to execute:\n"
          "  path: %s\n"
          "  host: %s\n"
          "  name: ::%s\n",
          path.c_str(), elideString(host).c_str(),
          elideString(child_subprin).c_str());
    CHECK(
        admin->Retract(host + "::" + child_subprin, "Execute", list<string>{}));
  } else {
    if (!FLAGS_quiet)
      printf(
          "Authorizing program to execute:\n"
          "  path: %s\n"
          "  host: %s\n"
          "  name: ::%s\n",
          path.c_str(), elideString(host).c_str(),
          elideString(child_subprin).c_str());
    CHECK(admin->Authorize(host + "::" + child_subprin, "Execute",
                           list<string>{}));
  }
}

int main(int argc, char **argv) {
  string usage = "Administrative utility for TaoDomain.\nUsage:\n  ";
  google::SetUsageMessage(usage + argv[0] + " [options]");
  tao::InitializeApp(&argc, &argv, true);

  std::unique_ptr<TaoDomain> admin;

  bool did_work = false;

  if (!FLAGS_init.empty()) {
    if (!FLAGS_quiet)
      printf("Initializing new configuration in: %s\n",
             FLAGS_config_path.c_str());
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
    if (!FLAGS_quiet)
      printf("Loading configuration from: %s\n", FLAGS_config_path.c_str());
    admin.reset(TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass));
    CHECK_NOTNULL(admin.get());
  }

  if (FLAGS_clear) {
    if (!FLAGS_quiet) printf("Clearing all policy rules.\n");
    CHECK(admin->Clear());
  }

  if (!FLAGS_canexecute.empty()) {
    handleCanExecute(admin.get(), FLAGS_canexecute, false /* do not retract */);
    did_work = true;
  }

  if (!FLAGS_retractcanexecute.empty()) {
    handleCanExecute(admin.get(), FLAGS_retractcanexecute,
                     true /* do retract */);
    did_work = true;
  }

  if (!FLAGS_add.empty()) {
    if (!FLAGS_quiet) printf("Adding policy rule: %s\n", FLAGS_add.c_str());
    CHECK(admin->AddRule(FLAGS_add));
    did_work = true;
  }

  if (!FLAGS_retract.empty()) {
    if (!FLAGS_quiet)
      printf("Retracting policy rule: %s\n", FLAGS_retract.c_str());
    CHECK(admin->AddRule(FLAGS_retract));
    did_work = true;
  }

  if (!FLAGS_query.empty()) {
    if (!FLAGS_quiet)
      printf("Querying policy guard: %s\n", FLAGS_query.c_str());
    bool ok = admin->AddRule(FLAGS_query);
    if (ok) {
      printf("Policy supports query\n");
    } else {
      printf("Policy rejects query\n");
    }
    did_work = true;
  }

  if (!FLAGS_getprogramhash.empty()) {
    LinuxProcessFactory factory;
    string child_subprin;
    string path = FLAGS_getprogramhash;
    int next_id = 0;  // assume no IDs.
    CHECK(factory.MakeHostedProgramSubprin(next_id, path, &child_subprin));
    printf("%s\n", child_subprin.c_str());
    did_work = true;
  }

  //  if (!FLAGS_newusers.empty()) {
  //    stringstream names(FLAGS_newusers);
  //    string name;
  //    while (getline(names, name, ',')) {  // split on commas
  //      string password = name;            // such security, wow
  //      unique_ptr<tao::Keys> key;
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

  if (FLAGS_show || !did_work) {
    printf("  name: %s\n", admin->GetName().c_str());
    printf("  policy key:\n");
    printf("    certificate: %s\n", admin->GetPolicyKeys()->X509Path().c_str());
    printf("    key: %s\n", admin->GetPolicyKeys()->PBESignerPath().c_str());
    if (admin->GetConfig()->has_tao_ca()) {
      printf("  tao ca: %s:%s\n", admin->GetConfig()->tao_ca().host().c_str(),
             admin->GetConfig()->tao_ca().port().c_str());
    } else {
      printf("  tao ca: -\n");
    }
    printf("  auth type: %s\n", admin->GetConfig()->guard_type().c_str());
    printf("%s\n", admin->DebugString().c_str());
  }

  return 0;
}
