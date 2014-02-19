//  File: cloud_server_thread_data_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Unit tests for CloudServerThreadData
//
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

#include <gtest/gtest.h>
#include <keyczar/base/scoped_ptr.h>

#include "cloudproxy/cloud_server_thread_data.h"

using cloudproxy::CloudServerThreadData;

class CloudServerThreadDataTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    peer_cert_ = "Fake peer cert";
    self_cert_ = "Fake self cert";

    cstd_.reset(new CloudServerThreadData(peer_cert_, self_cert_));
  }

  scoped_ptr<CloudServerThreadData> cstd_;
  string peer_cert_;
  string self_cert_;
};

TEST_F(CloudServerThreadDataTest, CertTest) {
  EXPECT_EQ(cstd_->GetPeerCert(), peer_cert_);
  EXPECT_EQ(cstd_->GetSelfCert(), self_cert_);
}

TEST_F(CloudServerThreadDataTest, ValidTest) {
  EXPECT_FALSE(cstd_->GetCertValidated());
  EXPECT_TRUE(cstd_->SetCertValidated());
  EXPECT_TRUE(cstd_->GetCertValidated());
}

TEST_F(CloudServerThreadDataTest, UserTest) {
  string username("tmroeder");
  EXPECT_FALSE(cstd_->IsAuthenticated(username));
  EXPECT_FALSE(cstd_->RemoveAuthenticated(username));
  EXPECT_TRUE(cstd_->SetAuthenticated(username));
  EXPECT_TRUE(cstd_->IsAuthenticated(username));
  EXPECT_TRUE(cstd_->RemoveAuthenticated(username));
}

TEST_F(CloudServerThreadDataTest, ChallengeTest) {
  string challenge;
  string username("tmroeder");
  EXPECT_FALSE(cstd_->GetChallenge(username, &challenge));
  string fake_challenge("Fake challenge");
  EXPECT_TRUE(cstd_->AddChallenge(username, fake_challenge));
  EXPECT_TRUE(cstd_->GetChallenge(username, &challenge));
  EXPECT_EQ(challenge, fake_challenge);

  EXPECT_TRUE(cstd_->RemoveChallenge(username));
  EXPECT_FALSE(cstd_->GetChallenge(username, &challenge));
}
