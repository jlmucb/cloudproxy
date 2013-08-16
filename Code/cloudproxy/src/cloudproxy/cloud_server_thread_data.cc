//  File: cloud_server_thread_data.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the CloudServerThreadData class used
// to store thread-local data for the CloudServer class
//
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#include "cloudproxy/cloud_server_thread_data.h"

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
