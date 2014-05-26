//  File: demo.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Simple example of a hosted program.
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

#include "tao/tao.h"
#include "tao/auth.h"
#include "tao/util.h"

using namespace tao;

DEFINE_bool(raw, false, "Show raw, non-elided output");

string shorten(string s) { return (FLAGS_raw ? s : elideString(s)); }

int main(int argc, char **argv) {
  string usage = "Tao Hosted Program Demo.\nUsage:\n  ";
  google::SetUsageMessage(usage + argv[0] + " [options]");
  tao::InitializeApp(&argc, &argv, true);

  Tao *tao = Tao::GetHostTao();

  if (!tao) {
    printf(
        "# Sorry, no Tao Host found.\n"
        "# This program does not appear to be running as a Tao hosted "
        "program.\n");
    return 1;
  } else {
    printf("# Greetings from a Tao hosted program!\n");
  }

  string name;
  CHECK(tao->GetTaoName(&name));
  printf("TaoName='%s'\n", shorten(name).c_str());

  scoped_ptr<Principal> prin(Principal::ParseFromString(name));
  CHECK(prin.get() != nullptr);
  if (prin->HasParent()) {
    printf("# This program is running on top of a Tao host...\n");
    printf("ParentName='%s'\n",
           shorten(prin->Parent()->SerializeToString()).c_str());
    printf("Extension='%s'\n",
           shorten(prin->Extension()->SerializeToString()).c_str());
  } else {
    printf("# This program is running as the root Tao host.\n");
  }

  string bytes;
  CHECK(tao->GetRandomBytes(4, &bytes));
  printf("RandomBytes='%s'\n", bytesToHex(bytes).c_str());

  printf("Success\n");
  return 0;
}
