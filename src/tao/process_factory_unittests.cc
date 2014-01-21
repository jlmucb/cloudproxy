//  File: process_factory_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic process creation facility.
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
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>

#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"
#include "tao/util.h"

using keyczar::base::Base64WEncode;

using tao::PipeTaoChannel;
using tao::ProcessFactory;
using tao::ScopedTempDir;

DEFINE_string(program, "out/Release/bin/protoc",
              "The program to execute, "
              "preferably one that will stop on its own");

class ProcessFactoryTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Get a temporary directory to use for the files.
    string dir_template("/tmp/process_factory_test_XXXXXX");
    scoped_array<char> temp_name(new char[dir_template.size() + 1]);
    memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

    ASSERT_TRUE(mkdtemp(temp_name.get()));
    temp_dir_.reset(new string(temp_name.get()));

    creation_socket_ = *temp_dir_ + string("/creation_socket");
    stop_socket_ = *temp_dir_ + string("/stop_socket");

    channel_.reset(new PipeTaoChannel(creation_socket_, stop_socket_));

    child_hash_ = "Fake hash";
    ASSERT_TRUE(channel_->AddChildChannel(child_hash_, &params_))
        << "Could not create the channel for the child";

    ASSERT_TRUE(Base64WEncode(params_, &encoded_params_))
        << "Could not encode the parameters";

    factory_.reset(new ProcessFactory());
  }

  scoped_ptr<PipeTaoChannel> channel_;
  scoped_ptr<ProcessFactory> factory_;
  ScopedTempDir temp_dir_;
  string creation_socket_;
  string stop_socket_;
  string params_;
  string encoded_params_;
  string child_hash_;
};

TEST_F(ProcessFactoryTest, HashTest) {
  list<string> args;
  string new_hash;
  EXPECT_TRUE(factory_->HashHostedProgram(FLAGS_program, args, &new_hash))
      << "Could not hash the program";
}

TEST_F(ProcessFactoryTest, CreationTest) {
  list<string> args;
  string identifier;
  EXPECT_TRUE(factory_->CreateHostedProgram(
      FLAGS_program, args, child_hash_, *channel_, &identifier)) 
    << "Could not create a vm";
  EXPECT_TRUE(!identifier.empty()) 
    << "Did not get an identifier from the factory";
}
