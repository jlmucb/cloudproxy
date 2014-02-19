//  File: admin_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Tests basic admin functionality.
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
#include <keyczar/base/file_util.h>

#include "tao/util.h"

using tao::CreateTempDir;
using tao::ScopedTempDir;
using tao::TaoDomain;

class TaoDomainTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(CreateTempDir("create_domain_test", &temp_dir_));
    path_ = *temp_dir_ + "/tao.config";
  }
  scoped_ptr<TaoDomain> admin_;
  ScopedTempDir temp_dir_;
  string path_;
};

TEST_F(TaoDomainTest, CreateWhitelistDomainTest) {
  string config = TaoDomain::ExampleWhitelistAuthDomain;
  admin_.reset(TaoDomain::Create(config, path_, "temppass"));
  EXPECT_TRUE(admin_.get() != nullptr);
}

TEST_F(TaoDomainTest, CreateRootDomainTest) {
  string config = TaoDomain::ExampleRootAuthDomain;
  admin_.reset(TaoDomain::Create(config, path_, "temppass"));
  EXPECT_TRUE(admin_.get() != nullptr);
}

TEST_F(TaoDomainTest, LoadDomainFailTest) {
  admin_.reset(TaoDomain::Load(path_));
  EXPECT_FALSE(admin_.get() != nullptr);
}

TEST_F(TaoDomainTest, LoadUnlockDomainTest) {
  string config = TaoDomain::ExampleWhitelistAuthDomain;
  admin_.reset(TaoDomain::Create(config, path_, "temppass"));
  EXPECT_TRUE(admin_.get() != nullptr);

  admin_.reset(TaoDomain::Load(path_));
  ASSERT_TRUE(admin_.get() != nullptr);
  EXPECT_FALSE(admin_->Unlock("badpass"));
  EXPECT_TRUE(admin_->Unlock("temppass"));
}

TEST_F(TaoDomainTest, DeepCopyTest) {
  string config = TaoDomain::ExampleWhitelistAuthDomain;
  admin_.reset(TaoDomain::Create(config, path_, "temppass"));
  EXPECT_TRUE(admin_.get() != nullptr);

  // DeepCopy after Create
  scoped_ptr<TaoDomain> other_admin(admin_->DeepCopy());

  ASSERT_TRUE(other_admin.get() != nullptr);
  EXPECT_EQ(other_admin->GetName(), admin_->GetName());
  EXPECT_TRUE(other_admin->GetPolicySigner() != nullptr);

  // DeepCopy after Load
  admin_.reset(TaoDomain::Load(path_));
  ASSERT_TRUE(admin_.get() != nullptr);
  other_admin.reset(admin_->DeepCopy());
  ASSERT_TRUE(other_admin.get() != nullptr);
  EXPECT_EQ(other_admin->GetName(), admin_->GetName());
  EXPECT_TRUE(other_admin->GetPolicySigner() == nullptr);

  EXPECT_TRUE(other_admin->Unlock("temppass"));
}
