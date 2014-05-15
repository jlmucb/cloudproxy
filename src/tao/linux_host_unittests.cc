//  File: linux_host_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Unit tests for LinuxHost.
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

#include "tao/attestation.h"
#include "tao/linux_admin_rpc.h"
#include "tao/soft_tao.h"
#include "tao/tao_test.h"
#include "tao/util.h"

using std::string;
using std::thread;

using namespace tao;

string doTests(Tao *tao) {
  string results;
  string bytes;
  if (!tao->GetRandomBytes(4, &bytes)) {
    results += "Rand failed";
  } else if (bytes.size() != 4) {
    results += "Rand bad size";
  } else if (bytes[0] == 0 && bytes[1] == 0 &&
                                   bytes[2] == 0 && bytes[3] == 0) {
    results += "Rand zero";
  } else {
    results += "Rand OK";
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

string doSeal(Tao *tao) {
  string data = "a very important secret";
  string sealed;
  if (!tao->Seal(data, Tao::SealPolicyDefault, &sealed)) {
    return "Seal failed";
  } else if (sealed.size() == 0) {
    return "Seal empty";
  } else if (!WriteStringToFile(string(test_argv[2]) + ".sealed", sealed)) {
    return "Seal write failed";
  } else {
    return "Seal OK";
  }
}

string doUnseal(Tao *tao) {
  string sealed, data, policy;
  if (!ReadFileToString(string(test_argv[2]) + ".sealed", &sealed)) {
    return "Unseal read failed";
  } else if (!tao->Unseal(sealed, &data, &policy)) {
    return "Unseal failed";
  } else if (data.size() == 0) {
    return "Unseal empty";
  } else if (data != "a very important secret") {
    return "Unseal bad";
  } else if (policy != Tao::SealPolicyDefault) {
    return "Unseal wrong policy";
  }
  // Now extend our name and do try it again, it should fail
  if (!tao->ExtendTaoName("Test1::Test2")) {
    return "Unseal OK Extend failed";
  } else if (tao->Unseal(sealed, &data, &policy)) {
    return "Unseal OK Extend+Seal leaked";
  } else {
    return "Unseal OK Extend+Seal denied";
  }
}

string doAttest(Tao *tao) {
  string name;
  if (!tao->GetTaoName(&name)) {
    return "Attest getname failed";
  }
  Statement s;
  s.set_delegate("Alice");
  string a;
  if (!tao->Attest(s, &a)) {
    return "Attest failed";
  } else if (a.size() == 0) {
    return "Attest empty";
  } else if (!WriteStringToFile(string(test_argv[2]) + ".delegation", a)) {
    return "Attest write failed";
  }
  // Now do another one on behalf of a subprincipal
  s.set_delegate("Bob");
  s.set_issuer(name + "::Test1::Test2");
  if (!tao->Attest(s, &a)) {
    return "Attest OK AttestSubprin failed";
  } else if (a.size() == 0) {
    return "Attest OK AttestSubprin empty";
  } else if (!WriteStringToFile(string(test_argv[2]) + ".subprin-delegation", a)) {
    return "Attest OK AttestSubprin write failed";
  } else {
    return "Attest OK AttestSubprin OK";
  }
}

int doHosted() {
  string op = test_argv[2];
  string tempfile = test_argv[3];
  // tao::InitializeApp(&test_argc, &test_argv, true);
  string result;
  Tao *tao = Tao::GetHostTao();
  if (tao == nullptr)
    result == "FAIL: null host tao";
  else if (op == "tests")
    result = doTests(tao);
  else if (op == "seal")
    result = doSeal(tao);
  else if (op == "unseal")
    result = doUnseal(tao);
  else if (op == "attest")
    result = doAttest(tao);
  else
    result = "Bad op for unit test";
  WriteStringToFile(tempfile, result);
  return 0;
}


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
  EXPECT_TRUE(admin_->StartHostedProgram(test_argv[0], list<string>{"sleep"}, &name));
  EXPECT_NE("", name);
  EXPECT_TRUE(admin_->StopHostedProgram(name));
  EXPECT_FALSE(admin_->StopHostedProgram(name));
  EXPECT_FALSE(admin_->StopHostedProgram("nobody"));
}

TEST_F(LinuxHostTest, HostedTest) {
  string name;
  string result_path = *temp_dir_ + "/results";
  string hosted_program_result;
  // do tests via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "tests", result_path}, &name));
  EXPECT_NE("", name);
  sleep(1);
  EXPECT_FALSE(admin_->StopHostedProgram(name)); // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("Rand OK TaoName OK Extend OK", hosted_program_result);
}

TEST_F(LinuxHostTest, HostedSealUnsealTest) {
  string name;
  string result_path = *temp_dir_ + "/results";
  string hosted_program_result;
  // seal something via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "seal", result_path}, &name));
  EXPECT_NE("", name);
  sleep(1);
  EXPECT_FALSE(admin_->StopHostedProgram(name)); // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("Seal OK", hosted_program_result);
  // now unseal it via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "unseal", result_path}, &name));
  EXPECT_NE("", name);
  sleep(1);
  EXPECT_FALSE(admin_->StopHostedProgram(name)); // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("Unseal OK Extend+Unseal OK", hosted_program_result);
}

TEST_F(LinuxHostTest, HostedAttestValidateTest) {
  string name;
  string result_path = *temp_dir_ + "/results";
  string hosted_program_result;
  // attest something via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "attest", result_path}, &name));
  EXPECT_NE("", name);
  sleep(1);
  EXPECT_FALSE(admin_->StopHostedProgram(name)); // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  // validate the attestation
  string delegation, delegate, issuer;
  EXPECT_TRUE(ReadFileToString(result_path + ".delegation", &delegation));
  EXPECT_TRUE(
      ValidateDelegation(delegation, CurrentTime(), &delegate, &issuer));
  EXPECT_EQ("Alice", delegate);
  EXPECT_EQ(name, issuer);

  // validate the subprin attestation
  EXPECT_TRUE(
      ReadFileToString(result_path + ".subprin-delegation", &delegation));
  EXPECT_TRUE(
      ValidateDelegation(delegation, CurrentTime(), &delegate, &issuer));
  EXPECT_EQ("Bob", delegate);
  EXPECT_EQ(name + "::Test1::Test2", issuer);
}

TEST_F(LinuxHostTest, ShutdownTest) {
  EXPECT_TRUE(admin_->Shutdown());
  EXPECT_FALSE(admin_->Shutdown()); // should fail, already shut down
}
