//  File: tao_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Unit tests for TPMTao and SoftTao.
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
#include "tao/tao.h"

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include "tao/attestation.h"
#include "tao/soft_tao.h"
#include "tao/tpm_tao.h"
#include "tao/util.h"

using namespace tao;

DEFINE_string(aik_blob_file, "./tpm/aikblob",
              "The blob for an AIK loaded in the TPM");

template <typename T>
class TaoTest : public ::testing::Test {
 protected:
  virtual void SetUp(scoped_ptr<TPMTao> *tao) {
    string blob;
    ASSERT_TRUE(ReadFileToString(FLAGS_aik_blob_file, &blob));
    tao->reset(new TPMTao(blob, list<int>{17, 18}));
    ASSERT_TRUE(tao->get()->Init());
  }
  virtual void SetUp(scoped_ptr<SoftTao> *tao) {
    string blob;
    ASSERT_TRUE(ReadFileToString(FLAGS_aik_blob_file, &blob));
    tao->reset(new SoftTao());
    ASSERT_TRUE(tao->get()->Init());
  }
  virtual void SetUp() { SetUp(&tao_); }
  scoped_ptr<T> tao_;
};
typedef ::testing::Types<TPMTao, SoftTao> TaoTypes;
TYPED_TEST_CASE(TaoTest, TaoTypes);

TYPED_TEST(TaoTest, SealUnsealTest) {
  string bytes("Test bytes for sealing");
  string sealed;
  string seal_policy = Tao::SealPolicyDefault;
  EXPECT_TRUE(this->tao_->Seal(bytes, seal_policy, &sealed));
  string unsealed, unseal_policy;
  EXPECT_TRUE(this->tao_->Unseal(sealed, &unsealed, &unseal_policy));
  EXPECT_EQ(unsealed, bytes);
  EXPECT_EQ(seal_policy, unseal_policy);
}

TYPED_TEST(TaoTest, AttestTest) {
  Statement s;
  s.set_delegate("Key(\"..stuff..\")");
  string attestation;
  ASSERT_TRUE(this->tao_->Attest(s, &attestation));
  Statement s2;
  ASSERT_TRUE(ValidateAttestation(attestation, &s2));
  EXPECT_EQ(s.delegate(), s2.delegate());
  string name;
  ASSERT_TRUE(this->tao_->GetTaoName(&name));
  EXPECT_NE("", name);
  EXPECT_EQ(s2.issuer(), name);
}

TYPED_TEST(TaoTest, RandomTest) {
  string bytes;
  ASSERT_TRUE(this->tao_->GetRandomBytes(4, &bytes));
  ASSERT_EQ(4, bytes.size());
  EXPECT_FALSE(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 &&
               bytes[3] == 0);
}

TYPED_TEST(TaoTest, ExtendTest) {
  string name, ename;
  ASSERT_TRUE(this->tao_->GetTaoName(&name));
  EXPECT_NE("", name);
  // TODO(kwalsh) implement extend for TPM
  if (name.substr(0, 3) != "TPM") {
    ASSERT_TRUE(this->tao_->ExtendTaoName("Test1::Test2"));
    ASSERT_TRUE(this->tao_->GetTaoName(&ename));
    EXPECT_EQ(name + "::" + "Test1::Test2", ename);
  }
}
