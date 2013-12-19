//  File: pipe_tao_channel_unittests.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: PipeTaoChannel implements Tao communication over file
//  descriptors
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

#include <gtest/gtest.h>

#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"

using tao::PipeTaoChannel;
class PipeTaoChannelTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Create a fake program that can be called with pipes
  }
};
