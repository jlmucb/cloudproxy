//  File: tpm_tao_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic TPMTao functionality
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
#include "tao/tpm_tao.h"

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include "tao/attestation.h"
#include "tao/util.h"

using std::list;
using std::string;

using tao::ReadFileToString;
using tao::Statement;
using tao::TPMTao;
using tao::Tao;

DEFINE_string(aik_blob_file, "/home/tmroeder/src/fileProxy/src/apps/aikblob",
              "The blob for an AIK loaded in the TPM");

class TPMTaoTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    string blob;
    ASSERT_TRUE(ReadFileToString(FLAGS_aik_blob_file, &blob));
    tao_.reset(new TPMTao(blob, list<int>{17, 18}));
    ASSERT_TRUE(tao_->Init());
  }
  scoped_ptr<TPMTao> tao_;
};

TEST_F(TPMTaoTest, SealUnsealTest) {
  string bytes("Test bytes for sealing");
  string sealed;
  string seal_policy = Tao::SealPolicyDefault;
  EXPECT_TRUE(tao_->Seal(bytes, seal_policy, &sealed));
  string unsealed, unseal_policy;
  EXPECT_TRUE(tao_->Unseal(sealed, &unsealed, &unseal_policy));
  EXPECT_EQ(unsealed, bytes);
  EXPECT_EQ(seal_policy, unseal_policy);
}

TEST_F(TPMTaoTest, AttestTest) {
  Statement s;
  s.set_delegate("Key(\"..stuff..\")");
  string attestation;
  ASSERT_TRUE(tao_->Attest(s, &attestation));
  Statement s2;
  ASSERT_TRUE(ValidateAttestation(attestation, &s2));
  EXPECT_EQ(s.delegate(), s2.delegate());
  string name;
  ASSERT_TRUE(tao_->GetTaoName(&name));
  EXPECT_EQ(s2.issuer(), name);
}
