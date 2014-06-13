//  File: pipe_factory_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Unit tests for PipeFactory and FDMessageChannel.
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
#include "tao/pipe_factory.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/attestation.pb.h"
#include "tao/util.h"

using namespace tao;  // NOLINT

class PipeFactoryTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(factory_.CreateChannelPair(&up_, &down_));
    s_.set_issuer("bogus_issuer");
    s_.set_time(123);
    s_.set_expiration(234);
  }
  PipeFactory factory_;
  scoped_ptr<FDMessageChannel> up_, down_;
  bool eof_;
  Statement s_, r_;
};

TEST_F(PipeFactoryTest, CreateTest) {
  list<int> fds;
  ASSERT_TRUE(up_->GetFileDescriptors(&fds));
  EXPECT_LE(0, up_->GetReadFileDescriptor());
  EXPECT_EQ(2, fds.size());
  if (fds.size() == 2) {
    EXPECT_EQ(*fds.begin(), up_->GetReadFileDescriptor());
  }
  string serialized;
  EXPECT_TRUE(up_->SerializeToString(&serialized));
  EXPECT_NE("", serialized);
  up_->Close();
  EXPECT_EQ(up_->GetReadFileDescriptor(), -1);
}

TEST_F(PipeFactoryTest, SendRecvTest) {
  ASSERT_TRUE(down_->SendMessage(s_));
  ASSERT_TRUE(up_->ReceiveMessage(&r_, &eof_));
  ASSERT_TRUE(!eof_);
  EXPECT_EQ("bogus_issuer", r_.issuer());
  EXPECT_EQ(123, r_.time());
  EXPECT_EQ(234, r_.expiration());

  ASSERT_TRUE(up_->SendMessage(s_));
  ASSERT_TRUE(down_->ReceiveMessage(&r_, &eof_));
  ASSERT_TRUE(!eof_);
}

TEST_F(PipeFactoryTest, CloseTest) {
  up_->Close();
  ASSERT_TRUE(down_->ReceiveMessage(&r_, &eof_));
  EXPECT_TRUE(eof_);
  EXPECT_FALSE(up_->SendMessage(s_));
}
