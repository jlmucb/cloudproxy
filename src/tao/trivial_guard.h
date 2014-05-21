//  File: trivial_guard.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A trivial authorization guard.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#ifndef TAO_TRIVIAL_GUARD_H_
#define TAO_TRIVIAL_GUARD_H_

#include <string>

#include "tao/tao_guard.h"

namespace tao {
using std::string;

/// A trivial authorization guard that returns the same answer for every
/// authorization query.
class TrivialGuard : public TaoGuard {
 public:
  enum Policy {
    ConservativePolicy, LiberalPolicy
  };

  TrivialGuard(Policy policy) : policy_(policy) {}

  virtual bool GetSubprincipalName(string *subprin) const {
    if (policy_ == LiberalPolicy)
      subprin->assign("TrivialPolicy(\"Liberal\")");
    else
      subprin->assign("TrivialPolicy(\"Conservative\")");
    return true;
  }

  virtual bool IsAuthorized(const string &name, const string &op,
                            const list<string> &args) {
    return (policy_ == LiberalPolicy);
  }

  virtual bool Authorize(const string &name, const string &op,
                         const list<string> &args) {
    return true;
  }

  virtual bool Revoke(const string &name, const string &op,
                      const list<string> &args) {
    return false;
  }

  virtual string DebugString() const {
    if (policy_ == LiberalPolicy)
      return "Trivial Liberal Policy (a.k.a. \"allow all\")";
    else
      return "Trivial Conservative Policy (a.k.a. \"deny all\")";
  }

 protected:
  /// The policy.
  Policy policy_;
 private:
  DISALLOW_COPY_AND_ASSIGN(TrivialGuard);
};
}  // namespace tao

#endif  // TAO_TRIVIAL_GUARD_H_
