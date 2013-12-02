//  File: cloud_server_thread_data.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the CloudServerThreadData class used
// to store thread-local data for the CloudServer class
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

#include "cloudproxy/cloud_server_thread_data.h"

#include <glog/logging.h>

namespace cloudproxy {
bool CloudServerThreadData::GetChallenge(const string &user, string *chall) {
  CHECK(chall) << "null challenge pointer";

  auto c_it = challenges_.find(user);
  if (challenges_.end() == c_it) return false;

  chall->assign(c_it->second.data(), c_it->second.length());
  return true;
}

bool CloudServerThreadData::AddChallenge(const string &user,
                                         const string &chall) {
  challenges_[user] = chall;
  return true;
}

bool CloudServerThreadData::RemoveChallenge(const string &user) {
  auto c_it = challenges_.find(user);
  if (challenges_.end() == c_it) return false;

  challenges_.erase(c_it);
  return true;
}

bool CloudServerThreadData::SetAuthenticated(const string &user) {
  auth_.insert(user);
  return true;
}

bool CloudServerThreadData::IsAuthenticated(const string &user) {
  return auth_.find(user) != auth_.end();
}

bool CloudServerThreadData::RemoveAuthenticated(const string &user) {
  auto a_it = auth_.find(user);
  if (auth_.end() == a_it) return false;
  auth_.erase(a_it);
  return true;
}

bool CloudServerThreadData::SetCertValidated() {
  cert_validated_ = true;
  return true;
}

bool CloudServerThreadData::GetCertValidated() { return cert_validated_; }
}  // namespace cloudproxy
