//  File: linux_host_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Unit tests for key utility functions
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
#include "tao/linux_host.h"

#include <thread>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "tao/linux_admin_rpc.h"
#include "tao/soft_tao.h"
#include "tao/util.h"

using std::thread;

using namespace tao;

// See flags definitions in tao_test.cc
DECLARE_string(short_program);
DECLARE_string(short_program_arg);
DECLARE_string(long_program);
DECLARE_string(long_program_arg);
DECLARE_string(hosted_program);
DECLARE_string(hosted_program_arg);

class LinuxHostTest : public ::testing::Test {
 protected:
   virtual void Main() {
    host_->Listen();
    host_.reset(nullptr); // This will close channels
   }

  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("linux_host_test", &temp_dir_));
    tao_.reset(new SoftTao());
    ASSERT_TRUE(tao_->InitWithTemporaryKeys());
    host_.reset(new LinuxHost(tao_.release(), *temp_dir_));
    ASSERT_TRUE(host_->Init());

    listener_.reset(new thread(&LinuxHostTest::Main, this));

    admin_.reset(LinuxHost::Connect(*temp_dir_));
    ASSERT_TRUE(admin_.get() != nullptr);
  }
  virtual void TearDown() {
    if (admin_.get() != nullptr)
      admin_->Shutdown();
    if (listener_.get() != nullptr && listener_->joinable())
      listener_->join();
  }
  ScopedTempDir temp_dir_;
  scoped_ptr<SoftTao> tao_;
  scoped_ptr<LinuxHost> host_;
  scoped_ptr<thread> listener_;
  scoped_ptr<LinuxAdminRPC> admin_;
};

TEST_F(LinuxHostTest, GetTaoHostNameTest) {
  string name;
  ASSERT_TRUE(admin_->GetTaoHostName(&name));
  ASSERT_NE("", name);
}

TEST_F(LinuxHostTest, StartStopTest) {
  string name;
  EXPECT_TRUE(admin_->StartHostedProgram(
      FLAGS_long_program, list<string>{FLAGS_long_program_arg}, &name));
  EXPECT_NE("", name);
  EXPECT_TRUE(admin_->StopHostedProgram(name));
  EXPECT_FALSE(admin_->StopHostedProgram(name));
  EXPECT_FALSE(admin_->StopHostedProgram("nobody"));
}

TEST_F(LinuxHostTest, HostedTest) {
  string name;
  string result_path = *temp_dir_ + "/results";
  EXPECT_TRUE(admin_->StartHostedProgram(
      FLAGS_hosted_program,
      list<string>{FLAGS_hosted_program_arg, result_path}, &name));
  EXPECT_NE("", name);
  sleep(1);
  EXPECT_FALSE(admin_->StopHostedProgram(name)); // should have already exited
  string hosted_program_result;
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("Connect OK Rand OK TaoName OK Extend OK", hosted_program_result);
}

TEST_F(LinuxHostTest, ShutdownTest) {
  EXPECT_TRUE(admin_->Shutdown());
  EXPECT_FALSE(admin_->Shutdown()); // should fail, already shut down
}
