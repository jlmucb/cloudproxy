//  File: cloud_auth.cc
//      Tom Roeder
//
//  Description: Implementation of the CloudAuth class that manages
//  authorization of users of CloudClient
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

#include "cloudproxy/cloud_auth.h"

#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/util.h"
#include "tao/keys.h"
#include "tao/util.h"

using google::protobuf::TextFormat;

namespace cloudproxy {

CloudAuth::CloudAuth(const string &acl_path, const keyczar::Verifier *key)
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

bool CloudAuth::FindPermissions(const string &subject, const string &object,
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

  return true;
}

bool CloudAuth::Permitted(const string &subject, Op op, const string &object) {
  // first check to see if this subject is an ADMIN
  if (admins_.find(subject) != admins_.end()) return true;

  set<Op> *perms = nullptr;
  if (!FindPermissions(subject, object, &perms)) return false;

  // check first to see if the specified permission exists
  auto op_it = perms->find(op);
  if (perms->end() != op_it) return true;

  // otherwise look to see if the ALL permission is specified
  op_it = perms->find(Op::ALL);
  return perms->end() != op_it;
}

bool CloudAuth::Delete(const string &subject, Op op, const string &object) {
  set<Op> *perms = nullptr;
  if (!FindPermissions(subject, object, &perms)) return false;

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

bool CloudAuth::SignACL(const keyczar::Signer *signer, const string &acl_path,
                        const string &acl_sig_path) {
  if (signer == nullptr) {
    LOG(ERROR) << "null key";
    return false;
  }
  string acl_txt;
  if (!keyczar::base::ReadFileToString(acl_path, &acl_txt)) {
    LOG(ERROR) << "Could not read ACL from " << acl_path;
    return false;
  }
  // deserialize from pretty text then reserialize as compact binary
  ACL acl;
  if (!TextFormat::ParseFromString(acl_txt, &acl)) {
    LOG(ERROR) << "Could not parse ACL from " << acl_path;
    return false;
  }
  string serialized_acl;
  if (!acl.SerializeToString(&serialized_acl)) {
    LOG(ERROR) << "Could not serialize ACL from " << acl_path;
    return false;
  }
  string sig;
  if (!tao::SignData(*signer, serialized_acl, ACLSigningContext, &sig)) {
    LOG(ERROR) << "Could not sign ACL";
    return false;
  }
  SignedACL sacl;
  sacl.set_serialized_acls(serialized_acl);
  sacl.set_signature(sig);
  string serialized;
  if (!sacl.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the signed ACL";
    return false;
  }
  if (!keyczar::base::WriteStringToFile(acl_sig_path, serialized)) {
    LOG(ERROR) << "Could not write signed ACL to " << acl_sig_path;
    return false;
  }
  return true;
}
}  // namespace cloudproxy
