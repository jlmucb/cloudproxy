//  File: tpm_tao_child_channel_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic TPMTaoChildChannel functionality
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

#include "tao/tpm_tao_child_channel.h"

#include <fstream>
#include <sstream>

#include <gflags/gflags.h>
#include <gtest/gtest.h>

using std::ifstream;
using std::string;
using std::stringstream;

using tao::TPMTaoChildChannel;

DEFINE_string(aik_blob_file, "/home/tmroeder/src/fileProxy/src/apps/aikblob",
              "The blob for an AIK loaded in the TPM");

class TPMTaoChildChannelTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ifstream aik_blob_file(FLAGS_aik_blob_file, ifstream::in);
    ASSERT_TRUE(aik_blob_file) << "Could not load the aik blob";
    stringstream aik_blob_stream;
    aik_blob_stream << aik_blob_file.rdbuf();
    list<UINT32> pcrs_to_seal{17, 18};
    // For the purposes of this simple test, we don't need a real attestation.
    // But if this test is modified to have a hosted program talk to the
    // channel, then that program will expect the AIK to be certified correctly
    // by the policy key.
    tao_.reset(new TPMTaoChildChannel(
        aik_blob_stream.str(), "" /* empty attestation */, pcrs_to_seal));
    ASSERT_TRUE(tao_->Init());
  }

  scoped_ptr<TPMTaoChildChannel> tao_;
};

TEST_F(TPMTaoChildChannelTest, SealTest) {
  string bytes("Test bytes for sealing");
  string sealed;
  EXPECT_TRUE(tao_->Seal(bytes, &sealed));
}

TEST_F(TPMTaoChildChannelTest, UnsealTest) {
  string bytes("Test bytes for sealing");
  string sealed;
  EXPECT_TRUE(tao_->Seal(bytes, &sealed));
  string unsealed;
  EXPECT_TRUE(tao_->Unseal(sealed, &unsealed));
  EXPECT_EQ(unsealed, bytes);
}

TEST_F(TPMTaoChildChannelTest, AttestTest) {
  string bytes("Data to attest to");
  string attestation;
  EXPECT_TRUE(tao_->Attest(bytes, &attestation));
}
