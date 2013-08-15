//  File: cloud_auth.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudAuth class manages authorization of users of
// CloudClient
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

#ifndef CLOUDPROXY_CLOUD_AUTH_H_
#define CLOUDPROXY_CLOUD_AUTH_H_

#include <keyczar/keyczar.h>
#include "cloudproxy/cloudproxy.pb.h"

#include <map>
#include <set>
#include <string>

using std::map;
using std::set;
using std::string;

namespace cloudproxy {
class CloudAuth {
 public:
  // Instantiates the Auth class with a serialized representation of a
  // cloudproxy::ACL object.
  CloudAuth(const string &acl_path, keyczar::Keyczar *key);

  virtual ~CloudAuth() {}

  // Checks to see if this operation is permitted by the ACL
  virtual bool Permitted(const string &subject, Op op, const string &object);

  // Removes a given entry from the ACL if it exists
  virtual bool Delete(const string &subject, Op op, const string &object);

  // Adds a given entry to the ACL
  virtual bool Insert(const string &subect, Op op, const string &object);

  // serializes the ACL into a given string
  virtual bool Serialize(string *data);

 protected:
  bool findPermissions(const string &subject, const string &object,
                       set<Op> **perms);

 private:
  // a map from subject->(object, permission set)
  map<string, map<string, set<Op> > > permissions_;

  // a list of users with admin privilege (able to perform any action)
  set<string> admins_;

  DISALLOW_COPY_AND_ASSIGN(CloudAuth);
};
}

#endif  // CLOUDPROXY_CLOUD_AUTH_H_
