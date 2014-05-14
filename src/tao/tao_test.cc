//  File: tao_test.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A main file for tests.
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
#include <gtest/gtest.h>

#include "tao/tao.h"
#include "tao/util.h"

using std::string;
using namespace tao;

// Short program could be /bin/true as well, with any argument.
// See *_unittests.cc for uses.
DEFINE_string(short_program, "",
              "A short program to execute, "
              "preferably one that will stop on its own");
DEFINE_string(short_program_arg, "", "Argument for the short program");

// Long program could be /bin/sleep as well, with 5 as argument.
// See *_unittests.cc for uses.
DEFINE_string(long_program, "",
              "A long program to execute, "
              "preferably one that will run for a few seconds");
DEFINE_string(long_program_arg, "", "Argument for the long program");

// Hosted program should do some Tao calls and put results in file argv[2].
// See *_unittests.cc for uses.
DEFINE_string(hosted_program, "",
              "A hosted program to execute, "
              "preferably one that will make some tao run for a few seconds");
DEFINE_string(hosted_program_arg, "test_hosted", "Argument for the long program");

static string doTaoTest() {
  // Run a few tao tests here.
  Tao *tao = Tao::GetHostTao();
  if (tao == nullptr) {
    return "FAIL null host tao";
  }
  string results = "Connect OK";

  string bytes;
  if (!tao->GetRandomBytes(4, &bytes)) {
    results += " Rand failed";
  } else if (bytes.size() != 4) {
    results += " Rand bad size";
  } else if (bytes[0] == 0 && bytes[1] == 0 &&
                                   bytes[2] == 0 && bytes[3] == 0) {
    results += " Rand zero";
  } else {
    results += " Rand OK";
  }

  string name;
  if (!tao->GetTaoName(&name)) {
    results += " TaoName failed";
  } else if (name == "") {
    results += " TaoName empty";
  } else {
    results += " TaoName OK";
  }

  if (!tao->ExtendTaoName("Test1::Test2")) {
    results += " Extend failed";
  } else {
    string subname;
    if (!tao->GetTaoName(&subname)) {
      results += " Extend missing name";
    } else if (subname != name + "::Test1::Test2") {
      results += " Extend bad ";
    } else {
      results += " Extend OK";
    }
  }
  return results;
}

GTEST_API_ int main(int argc, char **argv) {
  // Check if we were run with the "quit" or "sleep" options
  if (argc >= 2 && string(argv[1]) == "quit") {
    // This is used for some unit tests.
    return 0;
  }
  if (argc >= 2 && string(argv[1]) == "sleep") {
    // This is used for some unit tests.
    sleep(10);
    return 0; 
  }
  if (argc >= 3 && string(argv[1]) == "hosted") {
    tao::WriteStringToFile(argv[2], doTaoTest());
    return 0;
  }
  // Run normal unit tests
  testing::InitGoogleTest(&argc, argv);
  tao::InitializeApp(&argc, &argv, true);
  if (FLAGS_short_program == "") {
    FLAGS_short_program = argv[0];
    FLAGS_short_program_arg = "quit";
  }
  if (FLAGS_long_program == "") {
    FLAGS_long_program = argv[0];
    FLAGS_long_program_arg = "sleep";
  }
  if (FLAGS_hosted_program == "") {
    FLAGS_hosted_program = argv[0];
    FLAGS_hosted_program_arg = "hosted";
  }
  if (argc != 1) {
    return 0;
  }
  return RUN_ALL_TESTS();
}
