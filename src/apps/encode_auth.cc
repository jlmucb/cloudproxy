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
#include <iostream>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/util.h"

using std::string;

using tao::Base64WEncode;
using tao::InitializeApp;
using tao::MarshalKeyPrin;
using tao::MarshalSpeaksfor;

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, false);

  // A fake key for the parent.
  string taoKeyName("test tao key");
  string taoName;
  if (!MarshalKeyPrin(taoKeyName, &taoName)) {
    LOG(FATAL) << "Could not marshal a fake key auth.Prin value";
  }

  // A dummy key string to encode as bytes in MarshalSpeaksfor
  string testKey("test key");
  string speaksfor;
  if (!MarshalSpeaksfor(testKey, taoName, &speaksfor)) {
    LOG(FATAL) << "Could not marshal a speaksfor statement";
  }

  string encoded;
  if (!Base64WEncode(speaksfor, &encoded)) {
    LOG(FATAL) << "Could not encode the speaksfor in Base64W";
  }

  std::cout << encoded << std::endl;
  return 0;
}
