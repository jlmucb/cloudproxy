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
    ASSERT_TRUE(CreateTempDir("admin_domain", &temp_dir_));
    config_path_ = *temp_dir_ + "/tao.config";
    config_ = T::ExampleGuardDomain;
    domain_.reset(TaoDomain::Create(config_, config_path_, "temppass"));
    ASSERT_NE(nullptr, domain_.get());
    ASSERT_TRUE(dynamic_cast<T *>(domain_.get()) != nullptr);
  }
  ScopedTempDir temp_dir_;
  string config_path_;
  string config_;
  scoped_ptr<TaoDomain> domain_;
};
typedef ::testing::Types<ACLGuard, DatalogGuard> GuardTypes;
TYPED_TEST_CASE(TaoDomainTest, GuardTypes);

TYPED_TEST(TaoDomainTest, LoadDomainFailTest) {
  this->domain_.reset(TaoDomain::Load(this->config_path_ + "_missing_"));
  EXPECT_EQ(nullptr, this->domain_.get());
}

TYPED_TEST(TaoDomainTest, LoadUnlockDomainTest) {
  this->domain_.reset(TaoDomain::Create(this->config_, this->config_path_, "temppass"));
  EXPECT_TRUE(this->domain_.get() != nullptr);

  this->domain_.reset(TaoDomain::Load(this->config_path_, "badpass"));
  ASSERT_TRUE(this->domain_.get() == nullptr);
  this->domain_.reset(TaoDomain::Load(this->config_path_, "temppass"));
  ASSERT_TRUE(this->domain_.get() != nullptr);
}

TYPED_TEST(TaoDomainTest, DeepCopyTest) {
  this->domain_.reset(TaoDomain::Create(this->config_, this->config_path_, "temppass"));
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

TYPED_TEST(TaoDomainTest, AuthorizeTest) {
  string alice = "System(\"Test\")::User(\"Alice\")";
  string bob = "System(\"Test\")::User(\"Bob\")";
  list<unique_ptr<Term>> hello;
  hello.push_back(
      std::move(unique_ptr<Term>(new Term("hello.txt", Term::QUOTED_STRING))));
  list<unique_ptr<Term>> bad;
  bad.push_back(
      std::move(unique_ptr<Term>(new Term("bad.txt", Term::QUOTED_STRING))));

  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Read", hello));
  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Write", hello));
  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Read", bad));
  EXPECT_FALSE(this->domain_->IsAuthorized(bob, "Read", hello));

  EXPECT_TRUE(this->domain_->Authorize(alice, "Read", hello));

  EXPECT_TRUE(this->domain_->IsAuthorized(alice, "Read", hello));
  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Write", hello));
  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Read", bad));
  EXPECT_FALSE(this->domain_->IsAuthorized(bob, "Read", hello));

  EXPECT_TRUE(this->domain_->Revoke(alice, "Read", hello));

  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Read", hello));
  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Write", hello));
  EXPECT_FALSE(this->domain_->IsAuthorized(alice, "Read", bad));
  EXPECT_FALSE(this->domain_->IsAuthorized(bob, "Read", hello));
}
