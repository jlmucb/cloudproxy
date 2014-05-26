//  File: tao_guard.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization guard interface.
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
#ifndef TAO_TAO_GUARD_H_
#define TAO_TAO_GUARD_H_

#include <list>
#include <string>

#include "tao/auth.h"
#include "tao/util.h"

namespace tao {
using std::list;
using std::string;

/// An interface for authorization guards. This may be a stand-in until a
/// more complete authorization logic is implemented.
class TaoGuard {
 public:
  virtual ~TaoGuard() {}

  /// Get a unique name for this policy that can be used as a subprincipal name.
  /// @param[out] subprin The name.
  virtual bool GetSubprincipalName(string *subprin) const = 0;

  /// Get a name for this type of guard that can be used as a predicate name.
  virtual string GuardTypeName() const = 0;

  /// Methods that take lists of Term arguments.
  /// @{

  // Construct an authorization predicate of the form:
  //   Authorize(name, op, args...)
  /// @param name The name of the principal.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  static string MakePredicate(const string &name, const string &op,
                              const list<unique_ptr<Term>> &args);

  /// Authorize a principal to perform an operation.
  /// @param name The name of the principal.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  virtual bool Authorize(const string &name, const string &op,
                         const list<unique_ptr<Term>> &args) {
    return AddRule(MakePredicate(name, op, args));
  }

  /// Retract an authorization for a principal to perform an operation,
  /// essentially reversing the effect of an Authorize() call with identical
  /// name, op, and args. Note: This reverses the effect of an Authorize() call
  /// with identical parameters or the equivalent AddRule() call. However,
  /// particularly when expressive policies are supported (e.g. an "authorize
  /// all" rule), other rules may still be in place authorizing the principal to
  /// perform the operation.
  /// @param name The name of the principal.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  virtual bool Retract(const string &name, const string &op,
                       const list<unique_ptr<Term>> &args) {
    return RetractRule(MakePredicate(name, op, args));
  }

  /// Check whether a principal is authorized to perform an operation.
  /// @param name The name of the principal requesting the operation.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  virtual bool IsAuthorized(const string &name, const string &op,
                            const list<unique_ptr<Term>> &args);

  /// @}

  /// Methods that take lists of string arguments. Semantics are the same as
  /// above.
  /// @{
  static string MakePredicate(const string &name, const string &op,
                              const list<string> &args);
  virtual bool Authorize(const string &name, const string &op,
                         const list<string> &args) {
    return AddRule(MakePredicate(name, op, args));
  }
  virtual bool Retract(const string &name, const string &op,
                       const list<string> &args) {
    return RetractRule(MakePredicate(name, op, args));
  }
  virtual bool IsAuthorized(const string &name, const string &op,
                            const list<string> &args);
  /// @}

  /// Methods for manipulating subclass-specific policy rules.
  /// @{

  /// Add a policy rule. Subclasses should support at least rules of the form:
  ///   Authorized(P, op, args...)
  /// Which is equivalent to calling Authorize(P, op, args...), with each of the
  /// arguments converted to either a string or integer.
  /// @param rule The rule, encoded as text.
  virtual bool AddRule(const string &rule) = 0;

  /// Retract a rule previously added via AddRule() or the equivalent
  /// Authorize() methods.
  /// @param rule The rule, encoded as text.
  virtual bool RetractRule(const string &rule) = 0;

  /// Retract all rules.
  virtual bool Clear() = 0;

  /// Query the policy. Subclasses should support at least queries of the form:
  ///   Authorized(P, op, args...)
  /// @param query The query, encoded as text.
  virtual bool Query(const string &query) = 0;

  /// Get a count of how many rules there are.
  virtual int RuleCount() const = 0;

  /// Get the i^th policy rule, if it exists.
  /// @param i The rule index.
  virtual string GetRule(int i) const = 0;

  /// Get a debug string for the i^th policy rule.
  /// @param i The rule index.
  virtual string RuleDebugString(int i) const {
    return elideString(GetRule(i));
  }

  /// @}

  /// Get a string suitable for showing users authorization info.
  virtual string DebugString() const;
};
}  // namespace tao

#endif  // TAO_TAO_GUARD_H_
