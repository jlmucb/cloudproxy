//  File: tao_domain_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Unit tests for DatalogGuard, ACLGuard, TaoDomain, TaoGuard.
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
#include "tao/tao_domain.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/acl_guard.h"
#include "tao/datalog_guard.h"
#include "tao/soft_tao.h"
#include "tao/util.h"

using namespace tao;

template <typename T>
class TaoDomainTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("admin_domain", temp_dir_));
    config_path_ = *temp_dir_ + "/tao.config";
    string config = T::ExampleGuardDomain;
    scoped_ptr<TaoDomain> guard(TaoDomain::Create(config, path, "temppass"));
    ASSERT_TRUE(dynamic_cast<T *>(domain_.get()) != nullptr);
  }
  ScopedTempDir temp_dir_;
  string config_path_;
  scoped_ptr<TaoDomain> domain_;
};
typedef ::testing::Types<ACLGuard, DatalogGuard> GuardTypes;
TYPED_TEST_CASE(TaoDomainTest, GuardTypes);

TEST_F(TaoDomainTest, LoadDomainFailTest) {
  this->domain_.reset(TaoDomain::Load(this->config_path_));
  EXPECT_FALSE(this->domain_.get() != nullptr);
}

TEST_F(TaoDomainTest, LoadUnlockDomainTest) {
  string config = TaoDomain::ExampleACLGuardDomain;
  this->domain_.reset(TaoDomain::Create(config, this->config_path_, "temppass"));
  EXPECT_TRUE(this->domain_.get() != nullptr);

  this->domain_.reset(TaoDomain::Load(this->config_path_, "badpass"));
  ASSERT_TRUE(this->domain_.get() == nullptr);
  this->domain_.reset(TaoDomain::Load(this->config_path_, "temppass"));
  ASSERT_TRUE(this->domain_.get() != nullptr);
}

TEST_F(TaoDomainTest, DeepCopyTest) {
  string config = TaoDomain::ExampleACLGuardDomain;
  this->domain_.reset(TaoDomain::Create(config, this->config_path_, "temppass"));
  EXPECT_TRUE(this->domain_.get() != nullptr);

  // DeepCopy after Create
  scoped_ptr<TaoDomain> other_admin(this->domain_->DeepCopy());

  ASSERT_TRUE(other_admin.get() != nullptr);
  EXPECT_EQ(other_admin->GetName(), this->domain_->GetName());
  EXPECT_TRUE(other_admin->GetPolicySigner() != nullptr);

  // DeepCopy after Load
  this->domain_.reset(TaoDomain::Load(this->config_path_));
  ASSERT_TRUE(this->domain_.get() != nullptr);
  other_admin.reset(this->domain_->DeepCopy());
  ASSERT_TRUE(other_admin.get() != nullptr);
  EXPECT_EQ(other_admin->GetName(), this->domain_->GetName());
  EXPECT_TRUE(other_admin->GetPolicySigner() == nullptr);
}

TEST_F(TaoDomainTest, AuthorizeTest) {
  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Read", list<string>{"hello.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Write", list<string>{"hello.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Read", list<string>{"foo.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Bob", "Read", list<string>{"hello.txt"}));

  EXPECT_TRUE(this->domain_->Authorize("Alice", "Read", list<string>{"hello.txt"}));

  EXPECT_TRUE(this->domain_->IsAuthorized("Alice", "Read", list<string>{"hello.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Write", list<string>{"hello.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Read", list<string>{"foo.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Bob", "Read", list<string>{"hello.txt"}));

  EXPECT_TRUE(this->domain_->Revoke("Alice", "Read", list<string>{"hello.txt"}));

  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Read", list<string>{"hello.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Write", list<string>{"hello.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Alice", "Read", list<string>{"foo.txt"}));
  EXPECT_FALSE(this->domain_->IsAuthorized("Bob", "Read", list<string>{"hello.txt"}));
}

