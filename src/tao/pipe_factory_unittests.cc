//  File: pipe_factory_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Unit tests for FDMessageChannel.
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

using namespace tao;

TEST(PipeFactoryTest, CreateTest) {
  PipeFactory factory;
  scoped_ptr<FDMessageChannel> up, down;
  ASSERT_TRUE(factory.CreateChannelPair(up, down));

  list<int> fds;
  ASSERT_TRUE(up->GetFileDescriptors(fds));
  EXPECT(up->GetReadFileDescriptor() >= 0);
  EXPECT_TRUE(fds.size() == 2);
  if (fds.size() == 2) {
    EXPECT_EQ(*fds.begin() == up->GetReadFileDescriptor());
  }
  string s;
  EXPECT_TRUE(up.SerializeToString(&s));
  EXPECT_NE("", s);
  EXPECT_TRUE(up.Close());
  EXPECT_EQ(up->GetReadFileDescriptor(), -1);
}

TEST(PipeFactoryTest, SendRecvTest) {
  PipeFactory factory;
  scoped_ptr<FDMessageChannel> up, down;
  ASSERT_TRUE(factory.CreateChannelPair(up, down));

  bool eof;
  Statement s, r;
  s.set_issuer("bogus_issuer");
  s.set_time(123);
  s.set_expiration(234);
  
  ASSERT_TRUE(down.SendMessage(s));
  ASSERT_TRUE(up.ReceiveMessage(&r, &eof));
  ASSERT_TRUE(!eof);
  EXPECT_EQ("bogus_issuer", r.issuer());
  EXPECT_EQ(123, r.time());
  EXPECT_EQ(234, r.expiration());

  ASSERT_TRUE(up.SendMessage(s));
  ASSERT_TRUE(down.ReceiveMessage(&r, &eof));
  ASSERT_TRUE(!eof);

  up.Close();
  ASSERT_TRUE(down.ReceiveMessage(&r, &eof));
  EXPECT_TRUE(eof);
  EXPECT_FALSE(up.SendMessage(s));
}

