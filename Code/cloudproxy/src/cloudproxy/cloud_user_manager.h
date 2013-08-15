//  File: cloud_user_manager.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudUserManager class handles authenticated users for
// CloudClient and CloudServer
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

#ifndef CLOUDPROXY_CLOUD_USER_MANAGER_H_
#define CLOUDPROXY_CLOUD_USER_MANAGER_H_

#include <keyczar/keyczar.h>
#include "cloudproxy/cloudproxy.pb.h"

#include <map>
#include <memory>
#include <set>
#include <string>

using std::set;
using std::shared_ptr;
using std::string;
using std::map;

namespace cloudproxy {
class CloudUserManager {
 public:
  CloudUserManager() : users_() {}

  bool HasKey(const string &user) const;
  bool GetKey(const string &user, shared_ptr<keyczar::Keyczar> *key);
  bool AddSigningKey(const string &user, const string &path,
                     const string &password);
  bool AddKey(const string &user, const string &key, const string &meta);
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
