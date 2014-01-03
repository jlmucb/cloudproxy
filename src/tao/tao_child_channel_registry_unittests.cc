//  File: tao_child_channel_registry_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic TaoChildChannelRegistry functionality.
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
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/base64w.h>

#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/unix_fd_tao_child_channel.h"

using keyczar::base::Base64WEncode;

using tao::PipeTaoChildChannel;
using tao::TaoChildChannel;
using tao::TaoChildChannelParams;
using tao::TaoChildChannelRegistry;
using tao::UnixFdTaoChildChannel;

class TaoChildChannelRegistryTest : public ::testing::Test {
 public:
  TaoChildChannelRegistryTest() : registry_(new TaoChildChannelRegistry()) { }
 protected:
  scoped_ptr<TaoChildChannelRegistry> registry_;
};

TaoChildChannel *DummyCreator(const string &params) {
  return nullptr;
}

TEST_F(TaoChildChannelRegistryTest, DummyCreatorTest) {
  EXPECT_TRUE(registry_->Register("DummyCreator", DummyCreator))
    << "Could not register a dummy creator function with the registry";
}

TEST_F(TaoChildChannelRegistryTest, CreateTest) {
  EXPECT_TRUE(registry_->Register("DummyCreator", DummyCreator))
    << "Could not register a dummy creator function";

  TaoChildChannelParams tccp;
  tccp.set_channel_type("DummyCreator");
  tccp.set_params("DummyParams");

  string serialized;
  EXPECT_TRUE(tccp.SerializeToString(&serialized))
    << "Could not serialize the params";

  TaoChildChannel *child = registry_->Create(serialized);
  EXPECT_TRUE(child == nullptr);
}
TEST(TaoChildChannelRegistryStaticTest, ConstructorTest) {
  TaoChildChannel *child =
    TaoChildChannelRegistry::CallConstructor<PipeTaoChildChannel>("");
  EXPECT_TRUE(child != nullptr) << "Could not create a child from the registry";
}
