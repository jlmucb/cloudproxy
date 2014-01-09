//  File: cloud_auth.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudAuth class manages authorization of users of
// CloudClient
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

#ifndef CLOUDPROXY_CLOUD_AUTH_H_
#define CLOUDPROXY_CLOUD_AUTH_H_

#include <map>
#include <set>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "cloudproxy/cloudproxy.pb.h"

using std::map;
using std::set;
using std::string;

namespace keyczar {
class Keyczar;
}  // namespace keyczar

namespace cloudproxy {
/// A class that answers authorization requests about actions, using an ACL.
class CloudAuth {
 public:
  /// Create the authorization instance.
  /// @param acl_path The path to a signed ACL of form SignedACL.
  /// @param key The public key to use to check the signature on the ACL.
  CloudAuth(const string &acl_path, keyczar::Keyczar *key);

  virtual ~CloudAuth() {}

  /// Check to see if this operation is permitted by the ACL.
  /// @param subject The subject requesting the operation. The client must have
  /// already been authenticated by the caller.
  /// @param op The operation to check.
  /// @param object The object of the operation.
  /// @return A value indicating whether or not the subject is permitted to
  /// perform this operation.
  virtual bool Permitted(const string &subject, Op op, const string &object);

  /// Remove a given entry from the ACL if it exists.
  /// @param subject The subject of the entry to delete.
  /// @param op The operation of the entry to delete.
  /// @param object The operation of the entry to delete.
  virtual bool Delete(const string &subject, Op op, const string &object);

  /// Insert an entry into the ACL.
  /// @param subject The subject of the entry to insert.
  /// @param op The operation of the entry to insert.
  /// @param object The operation of the entry to insert.
  virtual bool Insert(const string &subject, Op op, const string &object);

  /// Serialize the ACL.
  /// @param[out] data A string to fill with the serialized representation.
  virtual bool Serialize(string *data);

  constexpr static auto ACLSigningContext =
      "CloudAuth cloudproxy::SignedACL Version 1";
 protected:
  /// Look up a set of permissions for a subject/object pair.
  /// @param subject The subject to look for.
  /// @param object The object to look for.
  /// @param[out] perms The set of permissions found in the ACL.
  bool FindPermissions(const string &subject, const string &object,
                       set<Op> **perms);

 private:
  // a map from subject->(object, permission set)
  map<string, map<string, set<Op>>> permissions_;

  // a list of users with admin privilege (able to perform any action)
  set<string> admins_;

  DISALLOW_COPY_AND_ASSIGN(CloudAuth);
};
}

#endif  // CLOUDPROXY_CLOUD_AUTH_H_
