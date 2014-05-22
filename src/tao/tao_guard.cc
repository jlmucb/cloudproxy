//  File: tao_guard.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization guard interface.
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
#include "tao/tao_guard.h"

#include <glog/logging.h>

namespace tao {

string TaoGuard::MakePredicate(const string &name, const string &op,
                                      const list<unique_ptr<Term>> &args) {
  stringstream out;
  out << "Authorized(" << name << ", " << quotedString(op);
  for (const auto &arg : args) {
    out << ", " << arg->SerializeToString();
  }
  out << ")";
  return out.str();
}

string TaoGuard::MakePredicate(const string &name, const string &op,
                                      const list<string> &args) {
  stringstream out;
  out << "Authorized(" << name << ", " << quotedString(op);
  for (const auto &arg : args) {
    out << ", " << quotedString(arg);
  }
  out << ")";
  return out.str();
}

bool TaoGuard::IsAuthorized(const string &name, const string &op,
                            const list<unique_ptr<Term>> &args) {
  if (!Query(MakePredicate(name, op, args))) {
    LOG(INFO) << "Principal " << elideString(name) << " not authorized for "
              << op << "(...)";
    return false;
  }
  LOG(INFO) << "Principal " << elideString(name) << " authorized for " << op
            << "(...)";
  return true;
}

bool TaoGuard::IsAuthorized(const string &name, const string &op,
                            const list<string> &args) {
  if (!Query(MakePredicate(name, op, args))) {
    LOG(INFO) << "Principal " << elideString(name) << " not authorized for "
              << op << "(...)";
    return false;
  }
  LOG(INFO) << "Principal " << elideString(name) << " authorized for " << op
            << "(...)";
  return true;
}

string TaoGuard::DebugString() const {
  std::stringstream out;
  int n = RuleCount();
  if (n == 0) {
    out << GuardTypeName() << " with empty rule set.";
  } else {
    out << GuardTypeName() << " with " << n << " rules:";
    for (int i = 0; i < n; i++) {
      out << "\n  Rule " << (i + 1) << ". " << RuleDebugString(i);
    }
  }
  return out.str();
}

}  // namespace tao
