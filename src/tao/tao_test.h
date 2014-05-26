//  File: tao_test.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Header for unit tests.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#ifndef TAO_TAO_TEST_H_
#define TAO_TAO_TEST_H_

#include <string>

using std::string;

// Saved args from tao_test main.
extern int test_argc;
extern char **test_argv;

// If tao_test is run with certain args, it calls these functions:
int doQuit();    // args = "quit"
int doSleep();   // args = "sleep"
int doHosted();  // args = "hosted", op, tempfile...

#endif  // TAO_TAO_TEST_H_
