//  File: soft_tao.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Administration tool for SoftTao.
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
#include "tao/soft_tao.h"
#include "tao/util.h"

using std::string;

using tao::CreateDirectory;
using tao::DirectoryExists;
using tao::Keys;
using tao::SoftTao;
using tao::Tao;

DEFINE_string(path, "soft_tao",
              "A path in which to store SoftTao keys and settings.");
DEFINE_string(pass, "", "A password for the SoftTao keys.");
DEFINE_bool(create, false, "Create a new SoftTao key and settings.");
DEFINE_bool(show, true, "Show the current SoftTao key and settings.");

int main(int argc, char **argv) {
  string usage = "Administrative utility for SoftTao.\nUsage:\n  ";
  google::SetUsageMessage(usage + argv[0] + " [options]");
  tao::InitializeApp(&argc, &argv, true);

  string path = FLAGS_path;
  string pass = FLAGS_pass;
  CHECK(!pass.empty());

  scoped_ptr<Keys> keys;

  if (FLAGS_create) {
    CHECK(!DirectoryExists(FilePath(path)));
    CHECK(CreateDirectory(FilePath(path)));

    printf("Creating new SoftTao key...\n");
    keys.reset(new Keys(path, "soft_tao", Keys::Signing | Keys::Crypting));
    CHECK(keys->InitNonHosted(pass));
    printf("SoftTao key and settings are in: %s/*\n", path.c_str());
  } else {
    keys.reset(new Keys(path, "soft_tao", Keys::Signing | Keys::Crypting));
    CHECK(keys->InitNonHosted(pass));
  }

  if (FLAGS_show) {
    scoped_ptr<SoftTao> tao;
    tao.reset(new SoftTao(keys.release()));
    CHECK(tao->Init());

    string ser;
    CHECK(tao->SerializeToStringWithDirectory(path, pass, &ser));
    printf("export %s='%s'\n", Tao::HostTaoEnvVar, ser.c_str());

    string tao_name;
    CHECK(tao->GetTaoName(&tao_name));
    printf("export GOOGLE_TAO_SOFT='%s'\n", tao_name.c_str());
  }

  return 0;
}
