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

#include "tao/util.h"

// Short program could be /bin/true as well, with any argument.
DEFINE_string(short_program, "",
              "A short program to execute, "
              "preferably one that will stop on its own");
DEFINE_string(short_program_arg, "", "Optional argument for the short program");

// Long program could be /bin/sleep as well, with 5 as argument.
DEFINE_string(long_program, "",
              "A long program to execute, "
              "preferably one that will run for a few seconds");
DEFINE_string(long_program_arg, "", "Optional argument for the long program");

GTEST_API_ int main(int argc, char **argv) {
  // Check if we were run with the "quit" or "sleep" options
  if (argc >= 2 && std::string(argv[1]) == "quit") {
    // This is used for some unit tests.
    return 0;
  }
  if (argc >= 2 && std::string(argv[1]) == "sleep") {
    // This is used for some unit tests.
    sleep(10);
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
  if (argc != 1) {
    return 0;
  }
  return RUN_ALL_TESTS();
}
