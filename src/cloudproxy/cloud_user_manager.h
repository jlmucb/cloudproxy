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

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "cloudproxy/cloudproxy.pb.h"

using std::map;
using std::set;
using std::shared_ptr;
using std::string;

namespace keyczar {
class Signer;
class Verifier;
}  // namespace keyczar

namespace tao {
class Keys;
}  // namespace keyczar

namespace cloudproxy {
/// A class that manages information about users: whether they are authenticated
/// or not, and the keys associated with them. This is used at the server to
/// keep track of users that have successfully authenticated on a given client
/// channel, and it is also used at the client to keep track of users that have
/// been loaded into memory and whether or not they have been authenticated with
/// the server.
class CloudUserManager {
 public:
  /// Construct an empty manager.
  CloudUserManager() : user_private_keys_(), user_public_keys_() {}

  /// Check to see if a user has a key associated with it. This can happen on
  /// the server when a client requests an action associated with a given user
  /// as subject.
  /// @param user The user to check.
  bool HasKey(const string &user) const;

  /// Get the signing key associated with a user, if any.
  /// @param user The user to look up.
  /// @param[out] key The key associated with the user, if any.
  bool GetKey(const string &user, keyczar::Signer **key);

  /// Get the verifying or signing key associated with a user, if any.
  /// @param user The user to look up.
  /// @param[out] key The key associated with the user, if any.
  bool GetKey(const string &user, keyczar::Verifier **key);

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
  bool AddKey(const SignedSpeaksFor &ssf, keyczar::Verifier *verifier);

  /// Record that a user has been authenticated.
  /// @param user The user to record as authenticated.
  void SetAuthenticated(const string &user);

  /// Check to see if a user has been authenticated.
  /// @param user The user to check.
  bool IsAuthenticated(const string &user);

  /// Create keys and attestations necessary for a new user, including:
  ///   path/username/signing/private.key  - private key
  ///   path/username/signing/public.key   - public key
  ///   path/username/signing/ssf          - policy-signed delegation
  /// @param path The location to store keys and attestations:
  /// @param username The name for the new user.
  /// @param password A password to protect the new user keys.
  /// @param policy_key The policy key to sign the user delgation.
  /// @param[out] key The new key for the user.
  static bool MakeNewUser(const string &path, const string &username,
                          const string &password,
                          const keyczar::Signer &policy_key,
                          scoped_ptr<tao::Keys> *key);

  constexpr static auto SpeaksForSigningContext =
      "CloudUserManager cloudproxy::SignedSpeaksFor Version 1";
  
  /// Suffix for a Tao attestation for a signing key.
  constexpr static auto UserDelegationSuffix = "signing/ssf";

 private:
  // A set of users and their keys.
  map<string, shared_ptr<keyczar::Signer> > user_private_keys_;
  map<string, shared_ptr<keyczar::Verifier> > user_public_keys_;

  // A set of authenticated users.
  set<string> authenticated_;

  DISALLOW_COPY_AND_ASSIGN(CloudUserManager);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_CLOUD_USER_MANAGER_H_
