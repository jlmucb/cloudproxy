//  File: tao_test.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The main driver for unit tests.
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
#include "tao/tao_test.h"
#include "tao/util.h"

using std::string;

using namespace tao;  // NOLINT

int test_argc;
char **test_argv;

GTEST_API_ int main(int argc, char **argv) {
  // Check if we were run with a special argument.
  test_argc = argc;
  test_argv = argv;
  if (argc >= 2 && string(argv[1]) == "quit") {
    return doQuit();
  } else if (argc >= 2 && string(argv[1]) == "sleep") {
    return doSleep();
  } else if (argc >= 4 && string(argv[1]) == "hosted") {
    return doHosted();
  } else {
    // Otherwise, run normal unit tests.
    testing::InitGoogleTest(&argc, argv);
    tao::InitializeApp(&argc, &argv, true);
    return RUN_ALL_TESTS();
  }
}
