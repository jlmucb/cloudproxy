//  File: cloud_auth.cc
//      Tom Roeder
//
//  Description: Implementation of the CloudAuth class that manages
//  authorization of users of CloudClient
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

#include "cloudproxy/cloud_auth.h"
#include <glog/logging.h>

#include "util.h"

namespace cloudproxy {

CloudAuth::CloudAuth(const string &acl_path, keyczar::Keyczar *key)
    : permissions_(), admins_() {
  string acl;

  CHECK(ExtractACL(acl_path, key, &acl)) << "Could not extract the ACL";

  // deserialize the cloudproxy::ACL and convert it into a map of permissions
  ACL acl_proto;
  acl_proto.ParseFromString(acl);
  for (int i = 0; i < acl_proto.permissions_size(); i++) {
    Action a = acl_proto.permissions(i);
    string subject = a.subject();
    Op o = a.verb();

    if (o == ADMIN) {
      admins_.insert(subject);
    } else {
      CHECK(a.has_object()) << "No object for a non-ADMIN permission";
      string object = a.object();

      permissions_[subject][object].insert(o);
    }
  }
}

bool CloudAuth::findPermissions(const string &subject, const string &object,
                                set<Op> **perms) {
  CHECK(perms) << "null perms parameter";

  // look it up in the permissions
  auto subject_it = permissions_.find(subject);
  if (permissions_.end() == subject_it) return false;

  auto object_it = subject_it->second.find(object);
  if (subject_it->second.end() == object_it) return false;

  // this is safe in single-threaded code because references to map objects are
  // guaranteed to remain unchanged unless the given item is deleted
  *perms = &object_it->second;
  ;
  return true;
}

bool CloudAuth::Permitted(const string &subject, Op op, const string &object) {
  // first check to see if this subject is an ADMIN
  if (admins_.find(subject) != admins_.end()) return true;

  set<Op> *perms = nullptr;
  if (!findPermissions(subject, object, &perms)) return false;

  // check first to see if the specified permission exists
  auto op_it = perms->find(op);
  if (perms->end() != op_it) return true;

  // otherwise look to see if the ALL permission is specified
  op_it = perms->find(Op::ALL);
  return perms->end() != op_it;
}

bool CloudAuth::Delete(const string &subject, Op op, const string &object) {
  set<Op> *perms = nullptr;
  if (!findPermissions(subject, object, &perms)) return false;

  // look for the operation in the set for this subject/object pair
  auto op_it = perms->find(op);
  if (perms->end() == op_it) return false;
  perms->erase(op_it);
  return true;
}

bool CloudAuth::Insert(const string &subject, Op op, const string &object) {
  permissions_[subject][object].insert(op);
  return true;
}

bool CloudAuth::Serialize(string *data) {
  // create an ACL from the map and serialize it to the data string
  CHECK(data) << "Can't serialize to a null string";

  ACL acl;

  auto subject_it = permissions_.begin();
  for (; subject_it != permissions_.end(); subject_it++) {
    auto object_it = subject_it->second.begin();
    for (; object_it != subject_it->second.end(); object_it++) {
      auto op_it = object_it->second.begin();
      for (; op_it != object_it->second.end(); op_it++) {
        Action *a = acl.add_permissions();
        a->set_subject(subject_it->first);
        a->set_verb(*op_it);
        a->set_object(object_it->first);
      }
    }
  }

  auto admin_it = admins_.begin();
  for (; admins_.end() != admin_it; admin_it++) {
    Action *a = acl.add_permissions();
    a->set_subject(*admin_it);
    a->set_verb(ADMIN);
  }

  return acl.SerializeToString(data);
}

}  // namespace cloudproxy
