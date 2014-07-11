//  File: tpm_tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Administration tool for TPMTao.
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
#include <cstdio>
#include <list>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/auth.h"
#include "tao/tpm_tao.h"
#include "tao/util.h"

using std::list;
using std::string;

using tao::CreateDirectory;
using tao::DirectoryExists;
using tao::FilePath;
using tao::Principal;
using tao::ReadFileToString;
using tao::TPMTao;
using tao::Tao;
using tao::WriteStringToFile;
using tao::join;
using tao::split;

DEFINE_string(path, "tpm", "A path in which to store TPMTao AIK and settings.");
DEFINE_string(pcrs, "17, 18", "A comma-separated list of PCR numbers to use.");
DEFINE_bool(create, false, "Create a new TPMTao AIK and settings.");
DEFINE_bool(show, true, "Show the current TPMTao AIK and settings.");

int main(int argc, char **argv) {
  string usage = "Administrative utility for TPMTao.\nUsage:\n  ";
  google::SetUsageMessage(usage + argv[0] + " [options]");
  tao::InitializeApp(&argc, &argv, true);

  string path = FLAGS_path;

  std::unique_ptr<TPMTao> tao;

  if (FLAGS_create) {
    CHECK(!DirectoryExists(FilePath(path)));
    CHECK(CreateDirectory(FilePath(path)));

    list<int> pcrs;
    CHECK(split(FLAGS_pcrs, ",", &pcrs));

    tao.reset(new TPMTao(pcrs));
    CHECK(tao->Init());
    string aik_blob;
    printf("Creating new TPMTao AIK...\n");
    CHECK(tao->CreateAIK(&aik_blob));

    CHECK(WriteStringToFile(path + "/aikblob", aik_blob));
    CHECK(WriteStringToFile(path + "/pcrlist", join(pcrs, ", ")));
    printf("TPMTao AIK and settings are in: %s/*\n", path.c_str());
  } else {
    string aik_blob, pcr_list;
    CHECK(ReadFileToString(path + "/aikblob", &aik_blob));
    CHECK(ReadFileToString(path + "/pcrlist", &pcr_list));

    list<int> pcrs;
    CHECK(split(pcr_list, ",", &pcrs));

    tao.reset(new TPMTao(aik_blob, pcrs));
    CHECK(tao->Init());
  }

  if (FLAGS_show) {
    string ser1;
    CHECK(tao->SerializeToString(&ser1));
    string ser2;
    CHECK(tao->SerializeToStringWithFile(path + "/aikblob", &ser2));
    string ser3;
    CHECK(tao->SerializeToStringWithDirectory(path, &ser3));

    printf("# export %s='%s'\n", Tao::HostTaoEnvVar, ser1.c_str());
    printf("# export %s='%s'\n", Tao::HostTaoEnvVar, ser2.c_str());
    printf("export %s='%s'\n", Tao::HostTaoEnvVar, ser3.c_str());

    string tao_name;
    CHECK(tao->GetTaoName(&tao_name));
    std::unique_ptr<Principal> tao_prin(Principal::ParseFromString(tao_name));
    CHECK(tao_prin.get() != nullptr);
    printf("export GOOGLE_TAO_TPM='%s'\n",
           tao_prin->Parent()->SerializeToString().c_str());
    printf("export GOOGLE_TAO_PCRS='%s'\n",
           tao_prin->Extension()->SerializeToString().c_str());
  }

  return 0;
}
