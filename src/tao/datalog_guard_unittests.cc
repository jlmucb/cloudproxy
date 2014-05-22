//  File: datalog_guard_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Unit tests for DatalogGuard.
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
#include "tao/datalog_guard.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/auth.h"
#include "tao/util.h"

using namespace tao;

class DatalogGuardTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("admin_domain", &temp_dir_));
    config_path_ = *temp_dir_ + "/tao.config";
    config_ = DatalogGuard::ExampleGuardDomain;
    scoped_ptr<TaoDomain> domain(TaoDomain::Create(config_, config_path_, "temppass"));
    ASSERT_NE(nullptr, domain.get());
    domain_.reset(dynamic_cast<DatalogGuard *>(domain.get()));
    ASSERT_NE(nullptr, domain_.get());
    domain.release();
  }
  ScopedTempDir temp_dir_;
  string config_path_;
  string config_;
  scoped_ptr<DatalogGuard> domain_;
};

TEST_F(DatalogGuardTest, SimpleRuleTest) {
  string simplerule = "IsAuthorized(System(1)::User(\"Alice\"), \"Read\", \"hello.txt\")";
  scoped_ptr<Predicate> pred(Predicate::ParseFromString(simplerule));
  EXPECT_TRUE(domain_->AddRule(*pred));
  list<unique_ptr<Term>> hello;
  hello.push_back(
      std::move(unique_ptr<Term>(new Term("hello.txt", Term::STRING))));
  EXPECT_TRUE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Bob\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Write", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(2)::User(\"Alice\")", "Read", hello));
}

TEST_F(DatalogGuardTest, ImplicationRuleTest) {
  string simplecond = "IsGoodUser(U)";
  string simplerule = "IsAuthorized(U, \"Read\", \"hello.txt\")";
  string alice_is_good = "IsGoodUser(System(1)::User(\"Alice\"))";
  scoped_ptr<Predicate> pred(Predicate::ParseFromString(simplerule));
  scoped_ptr<Predicate> cond(Predicate::ParseFromString(simplecond));
  scoped_ptr<Predicate> fact(Predicate::ParseFromString(alice_is_good));
  list<unique_ptr<Predicate>> conds;
  conds.push_back(std::move(unique_ptr<Predicate>(cond.release())));
  EXPECT_TRUE(domain_->AddRule(list<string>{"U"}, conds, *pred));
  EXPECT_TRUE(domain_->AddRule(*fact));
  list<unique_ptr<Term>> hello;
  hello.push_back(
      std::move(unique_ptr<Term>(new Term("hello.txt", Term::STRING))));
  EXPECT_TRUE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Bob\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Write", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(2)::User(\"Alice\")", "Read", hello));
}

TEST_F(DatalogGuardTest, StringImplicationRuleTest) {

  EXPECT_TRUE(
      domain_->AddRule("(forall U, F: IsGoodUser(U) and IsPrivateFile(F) "
                       "implies IsAuthorized(U, \"Read\", F))"));
  EXPECT_TRUE(domain_->AddRule("IsGoodUser(System(1)::User(\"Alice\"))"));
  EXPECT_TRUE(domain_->AddRule("IsPrivateFile(\"hello.txt\")"));

  list<unique_ptr<Term>> hello;
  hello.push_back(
      std::move(unique_ptr<Term>(new Term("hello.txt", Term::STRING))));
  list<unique_ptr<Term>> bad;
  bad.push_back(
      std::move(unique_ptr<Term>(new Term("bad.txt", Term::STRING))));

  EXPECT_TRUE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Read", bad));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Bob\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Write", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(2)::User(\"Alice\")", "Read", hello));
}

TEST_F(DatalogGuardTest, SubprinImplicationRuleTest) {

  EXPECT_TRUE(
      domain_->AddRule("(forall P, S, U: IsGoodUserName(U) and IsGoodSystem(S) "
                       "and subprin(P, S, U) implies IsGoodUser(P))"));
  EXPECT_TRUE(
      domain_->AddRule("(forall U, F: IsGoodUser(U) and IsPrivateFile(F) "
                       "implies IsAuthorized(U, \"Read\", F))"));
  EXPECT_TRUE(domain_->AddRule("IsGoodSystem(System(1))"));
  EXPECT_TRUE(domain_->AddRule("IsGoodSystem(System(0))"));
  EXPECT_TRUE(domain_->AddRule("IsGoodUserName(User(\"Alice\"))"));
  EXPECT_TRUE(domain_->AddRule("IsGoodUserName(User(\"Bob\"))"));
  EXPECT_TRUE(domain_->AddRule("IsPrivateFile(\"hello.txt\")"));

  list<unique_ptr<Term>> hello;
  hello.push_back(
      std::move(unique_ptr<Term>(new Term("hello.txt", Term::STRING))));
  list<unique_ptr<Term>> bad;
  bad.push_back(
      std::move(unique_ptr<Term>(new Term("bad.txt", Term::STRING))));

  EXPECT_TRUE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Read", hello));
  EXPECT_TRUE(domain_->IsAuthorized("System(0)::User(\"Alice\")", "Read", hello));
  EXPECT_TRUE(domain_->IsAuthorized("System(1)::User(\"Bob\")", "Read", hello));
  EXPECT_TRUE(domain_->IsAuthorized("System(0)::User(\"Bob\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Read", bad));
  EXPECT_FALSE(domain_->IsAuthorized("System(2)::User(\"Bob\")", "Read", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(1)::User(\"Alice\")", "Write", hello));
  EXPECT_FALSE(domain_->IsAuthorized("System(2)::User(\"Alice\")", "Read", hello));
}
