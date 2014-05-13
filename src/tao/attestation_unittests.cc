//  File: attestation_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Unit tests for attestation.
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
#include "tao/attestation.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/keys.h"
#include "tao/util.h"

using namespace tao;

class AttestationTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    key_.reset(new Keys("unittest", Keys::Signing));
    ASSERT_TRUE(key_->InitTemporary());
    ASSERT_TRUE(key_->GetPrincipalName(&key_name_));
    key_child_ = key_name_ + "::Test1::Test2";
  }

  scoped_ptr<Keys> key_;
  string key_name_;
  string key_child_;
};

TEST_F(AttestationTest, GenerateTestFail) {
  string a;
  Statement s;
  
  // With empty statement, generate should fail.
  EXPECT_FALSE(GenerateAttestation(*key_, "" /* delegation */, s, &a));
  EXPECT_FALSE(GenerateAttestation(*key_, "bogus_delegation", s, &a));
}

TEST_F(AttestationTest, VerifyTestFail) {
  string a, issuer;
  Statement s, v;

  // With bad issuer, generate should pass, verify should fail.
  s.set_issuer("bogus_issuer");
  s.set_time(123);
  s.set_expiration(234);
  ASSERT_TRUE(GenerateAttestation(*key_, "" /* delegation */, s, &a));
  EXPECT_TRUE(GetAttestationIssuer(a, &issuer));
  EXPECT_EQ("bogus_issuer", issuer);
  EXPECT_FALSE(ValidateAttestation(a, &v));

  ASSERT_TRUE(GenerateAttestation(*key_, "bogus_delegation", s, &a));
  EXPECT_TRUE(GetAttestationIssuer(a, &issuer));
  EXPECT_EQ("bogus_issuer", issuer);
  EXPECT_FALSE(ValidateAttestation(a, &v));
}

TEST_F(AttestationTest, GenerateTestOk) {
  string a, issuer;
  Statement s, v;

  // With keys as issuer, generate should pass, verify should pass.
  s.set_issuer(key_name_);
  ASSERT_TRUE(GenerateAttestation(*key_, "" /* delegation */, s, &a));
  EXPECT_TRUE(GetAttestationIssuer(a, &issuer));
  EXPECT_EQ(key_name_, issuer);
  EXPECT_TRUE(ValidateAttestation(a, &v));
  EXPECT_EQ(key_name_, v.issuer());
  EXPECT_EQ(123, v.time());
  EXPECT_EQ(234, v.expiration());
  EXPECT_FALSE(v.has_delegate());

  // With key::subprin as issuer, generate should pass, verify should pass.
  s.set_issuer(key_child_);
  ASSERT_TRUE(GenerateAttestation(*key_, "" /* delegation */, s, &a));
  EXPECT_TRUE(GetAttestationIssuer(a, &issuer));
  EXPECT_EQ(key_child_, issuer);
  EXPECT_TRUE(ValidateAttestation(a, &v));
  EXPECT_EQ(key_child_, v.issuer());
  EXPECT_EQ(123, v.time());
  EXPECT_EQ(234, v.expiration());
  EXPECT_FALSE(v.has_delegate());
}

TEST_F(AttestationTest, DelegateTest) {
  string a, issuer, delegate;
  Statement s, v;

  time_t now = CurrentTime();

  ASSERT_TRUE(AttestDelegation(*key_, "" /* delegation */, "bogus_delegate",
                               key_child_, &a));
  EXPECT_TRUE(GetAttestationIssuer(a, &issuer));
  EXPECT_EQ(key_child_, issuer);
  EXPECT_TRUE(GetAttestationDelegate(a, &delegate));
  EXPECT_EQ("bogus_delegate", delegate);
  EXPECT_FALSE(ValidateDelegation(a, now-1, &delegate, &issuer));
  ASSERT_TRUE(ValidateDelegation(a, CurrentTime(), &delegate, &issuer));
  EXPECT_EQ(key_child_, issuer);
  EXPECT_EQ("bogus_delegate", delegate);
}

TEST_F(AttestationTest, PredicateTest) {
  string a, issuer, predicate;
  list<string> args;
  Statement s, v;

  time_t now = CurrentTime();

  ASSERT_TRUE(AttestPredicate(*key_, "" /* delegation */, key_child_, "Testing",
                              list<string>{"\"Hello\"", "1234"}, &a));
  EXPECT_TRUE(GetAttestationIssuer(a, &issuer));
  EXPECT_EQ(key_child_, issuer);
  EXPECT_TRUE(GetAttestationPredicate(a, &predicate, &args));
  EXPECT_EQ("Testing", predicate);
  EXPECT_EQ(2, args.size());
  if (args.size() == 2) {
    EXPECT_EQ("\"Hello\"", *args.begin());
    EXPECT_EQ("1234", *(++args.begin()));
  }
  EXPECT_FALSE(ValidatePredicate(a, now-1, &issuer, &predicate, &args));
  ASSERT_TRUE(ValidatePredicate(a, CurrentTime(), &issuer, &predicate, &args));
  EXPECT_EQ(key_child_, issuer);
  if (args.size() == 2) {
    EXPECT_EQ("\"Hello\"", *args.begin());
    EXPECT_EQ("1234", *(++args.begin()));
  }
}

TEST_F(AttestationTest, DelegatePredicateTest) {
  string a, d, issuer, delegate, predicate;
  list<string> args;
  Statement s, v;
  scoped_ptr<Keys> key2;
  string key2_name;
  key2.reset(new Keys("unittest2", Keys::Signing));
  ASSERT_TRUE(key2->InitTemporary());
  ASSERT_TRUE(key2->GetPrincipalName(&key2_name));
  string key2_child = key2_name + "::Test3::Test4";

  time_t now = CurrentTime();

  // key_child speaksfor key2_child
  ASSERT_TRUE(AttestDelegation(*key2, "" /* delegation */, key_child_,
                               key2_child, &d));

  // key2_child says predicate using key to sign
  ASSERT_TRUE(AttestPredicate(*key_, d, key2_child, "Testing",
                              list<string>{"\"Hello\"", "1234"}, &a));
  EXPECT_TRUE(GetAttestationIssuer(a, &issuer));
  EXPECT_EQ(key2_child, issuer);
  EXPECT_TRUE(GetAttestationPredicate(a, &predicate, &args));
  EXPECT_EQ("Testing", predicate);
  EXPECT_EQ(2, args.size());
  if (args.size() == 2) {
    EXPECT_EQ("\"Hello\"", *args.begin());
    EXPECT_EQ("1234", *(++args.begin()));
  }
  EXPECT_FALSE(ValidatePredicate(a, now-1, &issuer, &predicate, &args));
  ASSERT_TRUE(ValidatePredicate(a, CurrentTime(), &issuer, &predicate, &args));
  EXPECT_EQ(key2_child, issuer);
  if (args.size() == 2) {
    EXPECT_EQ("\"Hello\"", *args.begin());
    EXPECT_EQ("1234", *(++args.begin()));
  }
}

