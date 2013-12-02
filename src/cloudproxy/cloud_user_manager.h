//  File: cloud_user_manager.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudUserManager class handles authenticated users for
// CloudClient and CloudServer
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

#ifndef CLOUDPROXY_CLOUD_USER_MANAGER_H_
#define CLOUDPROXY_CLOUD_USER_MANAGER_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include <keyczar/base/basictypes.h> // DISALLOW_COPY_AND_ASSIGN

#include "cloudproxy/cloudproxy.pb.h"

using std::set;
using std::shared_ptr;
using std::string;
using std::map;

namespace keyczar {
class Keyczar;
} // namespace keyczar

namespace cloudproxy {
class CloudUserManager {
 public:
  CloudUserManager() : users_() {}

  bool HasKey(const string &user) const;
  bool GetKey(const string &user, keyczar::Keyczar **key);
  bool AddSigningKey(const string &user, const string &path,
                     const string &password);
  bool AddKey(const string &user, const string &pub_key);
  bool AddKey(const SignedSpeaksFor &ssf, keyczar::Keyczar *verifier);

  void SetAuthenticated(const string &user);
  bool IsAuthenticated(const string &user);

 private:
  map<string, shared_ptr<keyczar::Keyczar> > users_;
  set<string> authenticated_;

  DISALLOW_COPY_AND_ASSIGN(CloudUserManager);
};
}

#endif  // CLOUDPROXY_CLOUD_USER_MANAGER_H_
