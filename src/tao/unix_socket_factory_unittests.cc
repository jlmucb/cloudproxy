//  File: unix_socket_factory_unittests.cc
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
#include "tao/unix_socket_factory.h"

#include <thread>

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/util.h"

using std::thread;

using namespace tao;  // NOLINT

class UnixSocketFactoryTest : public ::testing::Test {
 protected:
  virtual void Listen() {
    for (;;) {
      scoped_ptr<FDMessageChannel> chan(factory_->AcceptConnection());
      if (chan.get() == nullptr) break;
      for (;;) {
        Statement r, s;
        bool eof;
        ASSERT_TRUE(chan->ReceiveMessage(&r, &eof));
        if (eof) {
          chan->Close();
          break;
        }
        if (r.issuer() == "quit") return;
        if (r.issuer() == "close") break;
        s.set_issuer("ack");
        s.set_time(r.time());
        s.set_expiration(r.expiration());
        ASSERT_TRUE(chan->SendMessage(s));
        if (r.issuer() == "last") break;
      }
    }
    factory_->Close();
  }
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("sock_test", &temp_dir_));
    path_ = *temp_dir_ + "/socket";
    factory_.reset(new UnixSocketFactory(path_));
    ASSERT_TRUE(factory_->Init());
    ASSERT_LE(0, factory_->GetListenFileDescriptor());
    listener_.reset(new thread(&UnixSocketFactoryTest::Listen, this));
  }
  virtual void TearDown() {
    if (factory_.get() != nullptr) factory_->Close();
    if (listener_.get() != nullptr && listener_->joinable()) listener_->join();
  }
  scoped_ptr<thread> listener_;
  scoped_ptr<UnixSocketFactory> factory_;
  ScopedTempDir temp_dir_;
  string path_;
};

TEST_F(UnixSocketFactoryTest, ConnectTest) {
  scoped_ptr<FDMessageChannel> chan(UnixSocketFactory::Connect(path_));
  ASSERT_TRUE(chan.get() != nullptr);
  ASSERT_TRUE(chan->Close());

  chan.reset(UnixSocketFactory::Connect(path_));
  ASSERT_TRUE(chan.get() != nullptr);
  chan.reset();  // This should close it, allowing next to proceed.

  chan.reset(UnixSocketFactory::Connect(path_));
  ASSERT_TRUE(chan.get() != nullptr);
}

TEST_F(UnixSocketFactoryTest, SendRecvTest) {
  scoped_ptr<FDMessageChannel> chan(UnixSocketFactory::Connect(path_));
  ASSERT_TRUE(chan.get() != nullptr);
  Statement s, r;
  bool eof;
  s.set_issuer("hello");
  s.set_time(1);
  s.set_expiration(0);
  ASSERT_TRUE(chan->SendMessage(s));
  EXPECT_TRUE(chan->ReceiveMessage(&r, &eof));
  EXPECT_TRUE(!eof);
  EXPECT_EQ(1, r.time());

  s.set_issuer("last");
  s.set_time(2);
  s.set_expiration(0);
  ASSERT_TRUE(chan->SendMessage(s));
  EXPECT_TRUE(chan->ReceiveMessage(&r, &eof));
  EXPECT_TRUE(!eof);
  EXPECT_EQ(2, r.time());
  EXPECT_TRUE(chan->ReceiveMessage(&r, &eof));
  EXPECT_TRUE(eof);
}
