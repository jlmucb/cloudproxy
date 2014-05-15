//  File: acl_guard_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Unit tests for ACLGuard, TaoDomain, TaoGuard.
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
#include "tao/acl_guard.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/soft_tao.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using namespace tao;

class ACLGuardTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempACLsDomain(&temp_dir_, &admin_));
    ASSERT_TRUE(dynamic_cast<ACLGuard *>(admin_.get()) != nullptr);
  }
  ScopedTempDir temp_dir_;
  scoped_ptr<TaoDomain> admin_;
};

TEST_F(ACLGuardTest, AuthorizeTest) {
  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Read", list<string>{"hello.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Write", list<string>{"hello.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Read", list<string>{"foo.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Bob", "Read", list<string>{"hello.txt"}));

  EXPECT_TRUE(admin_->Authorize("Alice", "Read", list<string>{"hello.txt"}));

  EXPECT_TRUE(admin_->IsAuthorized("Alice", "Read", list<string>{"hello.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Write", list<string>{"hello.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Read", list<string>{"foo.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Bob", "Read", list<string>{"hello.txt"}));

  EXPECT_TRUE(admin_->Revoke("Alice", "Read", list<string>{"hello.txt"}));

  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Read", list<string>{"hello.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Write", list<string>{"hello.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Alice", "Read", list<string>{"foo.txt"}));
  EXPECT_FALSE(admin_->IsAuthorized("Bob", "Read", list<string>{"hello.txt"}));
}

