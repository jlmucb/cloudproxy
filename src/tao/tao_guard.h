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

  /// Check whether a principal is authorized to perform an operation.
  /// @param name The name of the principal requesting the operation.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  virtual bool IsAuthorized(const string &name, const string &op,
                            const list<string> &args) const = 0;

  /// Authorize a principal to perform an operation.
  /// @param name The name of the principal.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  virtual bool Authorize(const string &name, const string &op,
                         const list<string> &args) = 0;

  /// Attempt to revoke authorization for a principal to perform an operation,
  /// essentially reversing the effect of an Authorize() call with identical
  /// name, op, and args.
  /// @param name The name of the principal.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  /// Note, we say "attempt" because there may be a variety of policies in place
  /// that authorize a principal to perform the operation, particularly when the
  /// authorization logic is expressive. For instance, if there is an "allow
  /// all" policy, or an "allow any principal with property P" policy, then this
  /// function can't be expected to know if or when the given name meets those
  /// criteria. Instead, this function just handles the simplest case where the
  /// principal name was explicitly and individually authorized, e.g. via
  /// Authorize().
  virtual bool Revoke(const string &name, const string &op,
                      const list<string> &args) = 0;

  /// Get a string suitable for showing users authorization info.
  virtual string DebugString() const = 0;
};
}  // namespace tao

#endif  // TAO_TAO_GUARD_H_
