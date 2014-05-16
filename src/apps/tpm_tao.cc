//  File: make_aik.cc
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

#include "tao/tpm_tao.h"
#include "tao/util.h"

using std::list;
using std::string;

using tao::Tao;
using tao::TPMTao;
using tao::WriteStringToFile;
using tao::ReadFileToString;
using tao::split;
using tao::join;

DEFINE_string(tao_path, "tpm", "A path in which to store TPMTao AIK and settings");
DEFINE_string(pcrs, "17, 18", "A comma-separated list of PCR numbers to use.");
DEFINE_bool(create, false, "Create a new TPMTao AIK and settings.");
DEFINE_bool(show, false, "(default) Show the current TPMTao AIK and settings.");

int main(int argc, char **argv) {
  tao::InitializeApp(&argc, &argv, true);

  scoped_ptr<TPMTao> tao;

  if (FLAGS_create) {
    list<int> pcrs;
    CHECK(split(FLAGS_pcrs, ",", &pcrs));

    tao.reset(new TPMTao(pcrs));
    CHECK(tao->Init());
    string aik_blob;
    printf("# Creating new TPMTao AIK...\n");
    CHECK(tao->CreateAIK(&aik_blob));
    printf("# Done!\n");

    CHECK(WriteStringToFile(FLAGS_tao_path + "/aikblob", aik_blob));
    CHECK(WriteStringToFile(FLAGS_tao_path + "/pcrlist", join(pcrs, ", ")));
  } else {
    string aik_blob, pcr_list;
    CHECK(ReadFileToString(FLAGS_tao_path + "/aikblob", &aik_blob));
    CHECK(ReadFileToString(FLAGS_tao_path + "/pcrlist", &pcr_list));

    list<int> pcrs;
    CHECK(split(pcr_list, ",", &pcrs));
    
    tao.reset(new TPMTao(aik_blob, pcrs));
    // CHECK(tao.Init());  // not necessary for just serializing
  }

  string ser1;
  CHECK(tao->SerializeToString(&ser1));
  string ser2;
  CHECK(tao->SerializeToStringWithFile(FLAGS_tao_path + "/aikblob", &ser2));
  string ser3;
  CHECK(tao->SerializeToStringWithDirectory(FLAGS_tao_path, &ser3));

  printf("# TPMTao AIK and settings are in: %s/*\n", FLAGS_tao_path.c_str());
  printf("# Use any of these:\n");
  printf("export %s='%s'\n", Tao::HostTaoEnvVar, ser1.c_str());
  printf("export %s='%s'\n", Tao::HostTaoEnvVar, ser2.c_str());
  printf("export %s='%s'\n", Tao::HostTaoEnvVar, ser3.c_str());

  return 0;
}
