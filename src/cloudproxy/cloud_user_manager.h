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

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "cloudproxy/cloudproxy.pb.h"

using std::set;
using std::shared_ptr;
using std::string;
using std::map;

namespace keyczar {
class Keyczar;
}  // namespace keyczar

namespace cloudproxy {
/// A class that manages information about users: whether they are authenticated
/// or not, and the keys associated with them. This is used at the server to
/// keep track of users that have succesfully authenticated on a given client
/// channel, and it is also used at the client to keep track of users that have
/// been loaded into memory and whether or not they have been authenticated with
/// the server.
class CloudUserManager {
 public:
  /// Construct an empty manager.
  CloudUserManager() : users_() {}

  /// Check to see if a user has a key associated with it. This can happen on
  /// the server when a client requests an action associated with a given user
  /// as subject.
  /// @param user The user to check.
  bool HasKey(const string &user) const;

  /// Get the key associated with a user, if any.
  /// @param user The user to look up.
  /// @param[out] key The key associated with the user, if any.
  bool GetKey(const string &user, keyczar::Keyczar **key);

  /// Record a signing key associated with a user. The binding between user and
  /// key must already have been established by the caller.
  /// @param user The user to record.
  /// @param path The path to the key for this user.
  /// @param password The password needed to unlock the key, if any. The
  /// security of the bytes of the incoming password string should be managed by
  /// the caller.  This method immediately copies the password into a keyczar
  /// ScopedSafeString, so it does not leave any bytes of the password in memory
  /// after it is called.
  bool AddSigningKey(const string &user, const string &path,
                     const string &password);

  /// Records an association between a user and a public key.
  /// @param user The user part of the association.
  /// @param pub_key The public key to associate with this user.
  bool AddKey(const string &user, const string &pub_key);

  /// Add a key based on a SignedSpeaksFor statement.
  /// @param ssf A signed statement associating a user with a key.
  /// @param verifier A key used to verify ssf.
  bool AddKey(const SignedSpeaksFor &ssf, keyczar::Keyczar *verifier);

  /// Record that a user has been authenticated.
  /// @param user The user to record as authenticated.
  void SetAuthenticated(const string &user);

  /// Check to see if a user has been authenticated.
  /// @param user The user to check.
  bool IsAuthenticated(const string &user);

  constexpr static auto SpeaksForSigningContext =
      "CloudUserManager cloudproxy::SignedSpeaksFor Version 1";
 private:
  // A set of users and their keys.
  map<string, shared_ptr<keyczar::Keyczar> > users_;

  // A set of authenticated users.
  set<string> authenticated_;

  DISALLOW_COPY_AND_ASSIGN(CloudUserManager);
};
}

#endif  // CLOUDPROXY_CLOUD_USER_MANAGER_H_
