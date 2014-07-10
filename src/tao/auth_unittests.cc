//  File: auth_unittests.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Unit tests for authorization logic functions.
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
#include "tao/auth.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tao/util.h"

using std::string;

using namespace tao;  // NOLINT

class AuthTest : public ::testing::Test {
 protected:
  virtual void SetUp() {}
};

TEST_F(AuthTest, PrincipalTest) {
  string p[4];
  int i = 0;
  p[i++] = "Key(\"foo\")";
  p[i++] = p[0] + "::Test()";
  p[i++] = p[1] + "::Test_3(1, 2, 3, \"abc\", \"def\")";
  p[i++] = p[2] + "::Test_4(Nested(NestedMore(3), 2), 1)";
  for (i = 0; i < 4; i++) {
    unique_ptr<Principal> prin(Principal::ParseFromString(p[i]));
    EXPECT_NE(nullptr, prin.get());
    if (prin.get() == nullptr) continue;
    EXPECT_EQ(p[i], prin->SerializeToString());
    if (i > 0) {
      EXPECT_TRUE(prin->HasParent());
      const Principal *parent = prin->Parent();
      EXPECT_NE(nullptr, parent);
      if (parent != nullptr) {
        EXPECT_EQ(p[i - 1], parent->SerializeToString());
      }
    } else {
      EXPECT_FALSE(prin->HasParent());
      EXPECT_EQ(nullptr, prin->Parent());
      const Predicate *ext = prin->Extension();
      EXPECT_NE(nullptr, ext);
      EXPECT_EQ(p[0], ext->SerializeToString());
    }
  }
  stringstream in(p[0] + ", " + p[1]);
  unique_ptr<Principal> p0(Principal::ParseFromStream(in));
  skip(in, ", ");
  unique_ptr<Principal> p1(Principal::ParseFromStream(in));
  EXPECT_TRUE(in && in.eof());
  EXPECT_NE(nullptr, p0.get());
  EXPECT_NE(nullptr, p1.get());
  EXPECT_EQ(p[0], p0->SerializeToString());
  EXPECT_EQ(p[1], p1->SerializeToString());
}

TEST_F(AuthTest, PrincipalFailTest) {
  string p[4];
  int i = 0;
  p[i++] = "Alice";
  p[i++] = "User(\"Alice\")::";
  p[i++] = "User(\"Alice\"):Test(1)";
  p[i++] = "User::Test(1)";

  for (i = 0; i < 4; i++) {
    unique_ptr<Principal> prin(Principal::ParseFromString(p[i]));
    EXPECT_EQ(nullptr, prin.get());
  }
}

TEST_F(AuthTest, PredicateTest) {
  string p[3];
  int i = 0;
  p[i++] = "Empty()";
  p[i++] = "Lots(1, \"one\", 2, \"two\", 3, \"three\")";
  p[i++] =
      "Nested(\"test\", 42, One(1), Two(\"two\")::Point(0), Pair(Three(3), "
      "\"four\"), X)";

  unique_ptr<Predicate> pred;
  for (i = 0; i < 3; i++) {
    pred.reset(Predicate::ParseFromString(p[i]));
    EXPECT_NE(nullptr, pred.get());
    if (pred.get() != nullptr) {
      EXPECT_EQ(p[i], pred->SerializeToString());
    }
  }
  ASSERT_NE(nullptr, pred.get());
  EXPECT_EQ("Nested", pred->Name());
  ASSERT_EQ(6, pred->ArgumentCount());
  for (i = 0; i < 6; i++) {
    ASSERT_NE(nullptr, pred->Argument(i));
  }

  ASSERT_TRUE(Term::STRING == pred->Argument(0)->GetType());
  ASSERT_TRUE(pred->Argument(0)->IsString());
  EXPECT_EQ("test", pred->Argument(0)->GetString());

  ASSERT_EQ(Term::INTEGER, pred->Argument(1)->GetType());
  ASSERT_TRUE(pred->Argument(1)->IsInteger());
  EXPECT_EQ(42, pred->Argument(1)->GetInteger());

  ASSERT_TRUE(Term::PREDICATE == pred->Argument(2)->GetType() ||
              Term::PRINCIPAL == pred->Argument(2)->GetType());
  ASSERT_TRUE(pred->Argument(2)->IsPredicate());
  ASSERT_NE(nullptr, pred->Argument(2)->GetPredicate());
  EXPECT_EQ("One(1)", pred->Argument(2)->SerializeToString());

  ASSERT_EQ(Term::PRINCIPAL, pred->Argument(3)->GetType());
  ASSERT_TRUE(pred->Argument(3)->IsPrincipal());
  ASSERT_NE(nullptr, pred->Argument(3)->GetPrincipal());
  EXPECT_EQ("Two(\"two\")::Point(0)",
            pred->Argument(3)->GetPrincipal()->SerializeToString());

  ASSERT_TRUE(Term::PREDICATE == pred->Argument(4)->GetType() ||
              Term::PRINCIPAL == pred->Argument(4)->GetType());
  ASSERT_TRUE(pred->Argument(4)->IsPredicate());
  ASSERT_NE(nullptr, pred->Argument(4)->GetPrincipal());
  EXPECT_EQ("Pair(Three(3), \"four\")",
            pred->Argument(4)->GetPredicate()->SerializeToString());

  ASSERT_EQ(Term::VARIABLE, pred->Argument(5)->GetType());
  ASSERT_TRUE(pred->Argument(5)->IsVariable());
  ASSERT_EQ("X", pred->Argument(5)->GetVariable());
}

TEST_F(AuthTest, PredicateFailTest) {
  string p[4];
  int i = 0;
  p[i++] = "Test";
  p[i++] = "(\"Test\")";
  p[i++] = "1(\"Test\")";
  p[i++] = "_(\"Test\")";
  unique_ptr<Predicate> pred;
  for (i = 0; i < 3; i++) {
    pred.reset(Predicate::ParseFromString(p[i]));
    EXPECT_EQ(nullptr, pred.get());
  }
}
