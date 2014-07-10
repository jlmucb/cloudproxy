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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/attestation.h"
#include "tao/linux_admin_rpc.h"
#include "tao/soft_tao.h"
#include "tao/tao_test.h"
#include "tao/trivial_guard.h"
#include "tao/util.h"

using std::string;
using std::thread;

using namespace tao;  // NOLINT

string doTests(Tao *tao) {
  string results;
  string bytes;
  if (!tao->GetRandomBytes(4, &bytes)) {
    results += "Rand failed";
  } else if (bytes.size() != 4) {
    results += "Rand bad size";
  } else if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0) {
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
  } else if (!WriteStringToFile(string(test_argv[3]) + ".sealed", sealed)) {
    return "Seal write failed";
  } else {
    return "Seal OK";
  }
}

string doUnseal(Tao *tao) {
  string sealed, data, policy;
  if (!ReadFileToString(string(test_argv[3]) + ".sealed", &sealed)) {
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
    return "Unseal OK Extend+Unseal leaked";
  } else {
    return "Unseal OK Extend+Unseal denied";
  }
}

string make3Secrets(Tao *tao, string policies[3], string secrets[3]) {
  string name;
  if (!tao->GetTaoName(&name)) {
    name = "unknown";
  }
  policies[0] = Tao::SharedSecretPolicyDefault;
  policies[1] = Tao::SharedSecretPolicyConservative;
  policies[2] = Tao::SharedSecretPolicyLiberal;
  for (int i = 0; i < 3; i++) {
    string pol = policies[i];
    if (!tao->GetSharedSecret(200, pol, &secrets[i])) {
      return string("GetSharedSecret failed for policy ") + pol;
    }
    if (secrets[i].size() != 200) {
      return string("GetSharedSecret wrong size for policy ") + pol;
    }
    // Different policies should yield different secrets
    for (int j = 0; j < i; j++) {
      if (secrets[i] == secrets[j]) return "GetSharedSecret non-unique secret";
    }
  }
  return "";
}

string doMakeSecrets(Tao *tao) {
  string err, policies[3], secrets[3], subsecrets[3];
  err = make3Secrets(tao, policies, secrets);
  if (err != "") return err;
  if (!tao->ExtendTaoName("Test1::Test2")) {
    return "GetSharedSecret Extend failed";
  }
  err = make3Secrets(tao, policies, subsecrets);
  if (err != "") return err;
  for (int i = 0; i < 3; i++) {
    string pol = policies[i];
    if (!WriteStringToFile(string(test_argv[3]) + ".secret-" + pol,
                           secrets[i])) {
      return "GetSharedSecret write failed";
    }
    if (!WriteStringToFile(string(test_argv[3]) + ".subsecret-" + pol,
                           subsecrets[i])) {
      return "GetSharedSecret sub write failed";
    }
  }
  return "GetSharedSecret OK created";
}

string doCheckSecrets(Tao *tao) {
  string err, policies[3], secrets[3], subsecrets[3];
  string oldsecrets[3], oldsubsecrets[3];
  err = make3Secrets(tao, policies, secrets);
  if (err != "") return err;
  if (!tao->ExtendTaoName("Test1::Test2")) {
    return "GetSharedSecret Extend failed";
  }
  err = make3Secrets(tao, policies, subsecrets);
  if (err != "") return err;
  for (int i = 0; i < 3; i++) {
    string pol = policies[i];
    if (!ReadFileToString(string(test_argv[3]) + ".secret-" + pol,
                          &oldsecrets[i])) {
      return "GetSharedSecret read failed";
    }
    if (!ReadFileToString(string(test_argv[3]) + ".subsecret-" + pol,
                          &oldsubsecrets[i])) {
      return "GetSharedSecret sub read failed";
    }
  }
  // Old and new should match under any policy (for linux host)
  string errs = "";
  for (int i = 0; i < 3; i++) {
    if (secrets[i] != oldsecrets[i])
      errs += string(", secret mismatch for policy ") + policies[i];
    if (subsecrets[i] != oldsubsecrets[i])
      errs += string(", sub secret mismatch for policy ") + policies[i];
  }
  // subprin secret and parent secret should not match for non-liberal policies
  if (secrets[0] == subsecrets[0] || secrets[1] == subsecrets[1]) {
    errs += ", bad subprin match for non-liberal policy";
  }
  // subprin secret and parent secret should match for liberal policy
  if (secrets[2] != subsecrets[2]) {
    errs += "mismatch for liberal policy";
  }
  if (errs != "") {
    return "GetSharedSecret failed" + errs;
  }
  return "GetSharedSecret OK checked";
}

string doAttest(Tao *tao) {
  string name;
  if (!tao->GetTaoName(&name)) {
    return "Attest getname failed";
  }
  Statement s;
  s.set_delegate("Alice");
  string a;
  tao->Attest(s, &a);

  if (!tao->Attest(s, &a)) {
    return "Attest failed";
  } else if (a.size() == 0) {
    return "Attest empty";
  } else if (!WriteStringToFile(string(test_argv[3]) + ".delegation", a)) {
    return "Attest write failed";
  }
  // Now do another one on behalf of a subprincipal
  s.set_delegate("Bob");
  s.set_issuer(name + "::Test1::Test2");
  if (!tao->Attest(s, &a)) {
    return "Attest OK AttestSubprin failed";
  } else if (a.size() == 0) {
    return "Attest OK AttestSubprin empty";
  } else if (!WriteStringToFile(string(test_argv[3]) + ".subprin-delegation",
                                a)) {
    return "Attest OK AttestSubprin write failed";
  } else {
    return "Attest OK AttestSubprin OK";
  }
}

int doHosted() {
  tao::InitializeApp(&test_argc, &test_argv, true);
  string op = test_argv[2];
  string tempfile = test_argv[3];
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
  else if (op == "makesecrets")
    result = doMakeSecrets(tao);
  else if (op == "checksecrets")
    result = doCheckSecrets(tao);
  else
    result = "Bad op for unit test";
  WriteStringToFile(tempfile, result);
  return 0;
}

class LinuxHostTest : public ::testing::Test {
 protected:
  virtual void Main() {
    host_->Listen();
    host_.reset(nullptr);  // This will close channels
  }

  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("linux_host_test", &temp_dir_));
    unique_ptr<TaoGuard> policy(new TrivialGuard(TrivialGuard::LiberalPolicy));
    host_.reset(new LinuxHost(policy.release(), *temp_dir_));
    ASSERT_TRUE(host_->InitRoot("test_password"));

    listener_.reset(new thread(&LinuxHostTest::Main, this));

    admin_.reset(LinuxHost::Connect(*temp_dir_));
    ASSERT_TRUE(admin_.get() != nullptr);
  }
  virtual void TearDown() {
    if (admin_.get() != nullptr) admin_->Shutdown();
    if (listener_.get() != nullptr && listener_->joinable()) listener_->join();
  }
  ScopedTempDir temp_dir_;
  unique_ptr<LinuxHost> host_;
  unique_ptr<thread> listener_;
  unique_ptr<LinuxAdminRPC> admin_;
};

TEST_F(LinuxHostTest, GetTaoHostNameTest) {
  string name;
  ASSERT_TRUE(admin_->GetTaoHostName(&name));
  ASSERT_NE("", name);
}

TEST_F(LinuxHostTest, StartStopTest) {
  string name;
  EXPECT_TRUE(
      admin_->StartHostedProgram(test_argv[0], list<string>{"sleep"}, &name));
  EXPECT_NE("", name);
  EXPECT_TRUE(admin_->StopHostedProgram(name));
  usleep(250 *
         1000);  // Wait for it to be completely dead (SIGCHLD is asynchronous).
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
  usleep(250 * 1000);
  EXPECT_FALSE(admin_->StopHostedProgram(name));  // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("Rand OK TaoName OK Extend OK", hosted_program_result);
}

TEST_F(LinuxHostTest, HostedSecretsTest) {
  string name;
  string result_path = *temp_dir_ + "/results";
  string hosted_program_result;
  // get some secrets via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "makesecrets", result_path}, &name));
  EXPECT_NE("", name);
  usleep(250 * 1000);
  EXPECT_FALSE(admin_->StopHostedProgram(name));  // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("GetSharedSecret OK created", hosted_program_result);
  // now recheck them via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "checksecrets", result_path},
      &name));
  EXPECT_NE("", name);
  usleep(250 * 1000);
  EXPECT_FALSE(admin_->StopHostedProgram(name));  // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("GetSharedSecret OK checked", hosted_program_result);
}

TEST_F(LinuxHostTest, HostedSealUnsealTest) {
  string name;
  string result_path = *temp_dir_ + "/results";
  string hosted_program_result;
  // seal something via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "seal", result_path}, &name));
  EXPECT_NE("", name);
  usleep(250 * 1000);
  EXPECT_FALSE(admin_->StopHostedProgram(name));  // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("Seal OK", hosted_program_result);
  // now unseal it via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "unseal", result_path}, &name));
  EXPECT_NE("", name);
  usleep(250 * 1000);
  EXPECT_FALSE(admin_->StopHostedProgram(name));  // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  EXPECT_EQ("Unseal OK Extend+Unseal denied", hosted_program_result);
}

TEST_F(LinuxHostTest, HostedAttestValidateTest) {
  string name;
  string host;
  ASSERT_TRUE(admin_->GetTaoHostName(&host));
  string result_path = *temp_dir_ + "/results";
  string hosted_program_result;
  // attest something via hosted program
  EXPECT_TRUE(admin_->StartHostedProgram(
      test_argv[0], list<string>{"hosted", "attest", result_path}, &name));
  EXPECT_NE("", name);
  usleep(250 * 1000);
  EXPECT_FALSE(admin_->StopHostedProgram(name));  // should have already exited
  EXPECT_TRUE(ReadFileToString(result_path, &hosted_program_result));
  // validate the attestation
  string delegation, delegate, issuer;
  EXPECT_TRUE(ReadFileToString(result_path + ".delegation", &delegation));
  EXPECT_TRUE(
      ValidateDelegation(delegation, CurrentTime(), &delegate, &issuer));
  EXPECT_EQ("Alice", delegate);
  EXPECT_EQ(host + "::" + name, issuer);

  // validate the subprin attestation
  EXPECT_TRUE(
      ReadFileToString(result_path + ".subprin-delegation", &delegation));
  EXPECT_TRUE(
      ValidateDelegation(delegation, CurrentTime(), &delegate, &issuer));
  EXPECT_EQ("Bob", delegate);
  EXPECT_EQ(host + "::" + name + "::Test1::Test2", issuer);
}

TEST_F(LinuxHostTest, ShutdownTest) {
  EXPECT_TRUE(admin_->Shutdown());
  EXPECT_FALSE(admin_->Shutdown());  // should fail, already shut down
}
