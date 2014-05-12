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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/base/base64w.h>

#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"
#include "tao/util.h"

using keyczar::base::Base64WEncode;

using tao::CreateTempDir;
using tao::PipeTaoChannel;
using tao::ProcessFactory;
using tao::ScopedTempDir;

DEFINE_string(program, "/bin/true", "The program to execute, "
                                    "preferably one that will stop on its own");

class ProcessFactoryTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("process_factory_test", &temp_dir_));

    string domain_socket = *temp_dir_ + "/domain_socket";

    channel_.reset(new PipeTaoChannel(domain_socket));

    child_name_ = "Fake hash";
    ASSERT_TRUE(channel_->AddChildChannel(child_name_, &params_))
        << "Could not create the channel for the child";

    ASSERT_TRUE(Base64WEncode(params_, &encoded_params_))
        << "Could not encode the parameters";

    factory_.reset(new ProcessFactory());
  }

  scoped_ptr<PipeTaoChannel> channel_;
  scoped_ptr<ProcessFactory> factory_;
  ScopedTempDir temp_dir_;
  string params_;
  string encoded_params_;
  string child_name_;
};

TEST_F(ProcessFactoryTest, HashTest) {
  list<string> args;
  string tentative_child_name;
  EXPECT_TRUE(factory_->GetHostedProgramTentativeName(1234, FLAGS_program, args,
                                                      &tentative_child_name))
      << "Could not hash the program";
  string child_name;
  EXPECT_TRUE(factory_->CreateHostedProgram(1234, FLAGS_program, args,
                                            tentative_child_name,
                                            channel_.get(), &child_name))
      << "Could not create a process";
  EXPECT_TRUE(!child_name.empty())
      << "Did not get an identifier from the factory";
}
