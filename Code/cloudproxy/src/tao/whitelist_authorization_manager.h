//  File: whitelist_authorization_manager.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The whitelist manager handles whitelist files signed
//  with the policy public key.
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

#ifndef TAO_WHITELIST_AUTHORIZATION_MANAGER_H_
#define TAO_WHITELIST_AUTHORIZATION_MANAGER_H_

#include "tao/tao_authorization_manager.h"
#include <keyczar/keyczar.h>
#include <map>
#include <set>

using std::map;
using std::set;

namespace tao {
class WhitelistAuthorizationManager : public TaoAuthorizationManager {
 public:
  WhitelistAuthorizationManager() : whitelist_(), hash_whitelist_() {}
  virtual ~WhitelistAuthorizationManager() {}
  bool Init(const string &whitelist_path,
            const keyczar::Keyczar &public_policy_key);
  virtual bool IsAuthorized(const string &program_hash) const;
  virtual bool IsAuthorized(const string &program_name,
                            const string &program_hash) const;

 private:
  map<string, string> whitelist_;
  set<string> hash_whitelist_;

  DISALLOW_COPY_AND_ASSIGN(WhitelistAuthorizationManager);
};
}  // namespace tao

#endif  // TAO_WHITELIST_AUTHORIZATION_MANAGER_H_
