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

using std::list;
using std::string;

namespace tao {
/// An simple interface for authorization guards. This may be a stand-in until a
/// more complete authorization logic is implemented.
class TaoGuard {
 public:
  virtual ~TaoGuard() {}

  /// Check whether a principal is authorized to perform an operation.
  /// @param name The name of the principal requesting the operation.
  /// @param op The name of the operation
  /// @param args A list of arguments to the operation.
  virtual bool IsAuthorized(const string &name, const string &op,
                            const list<string> &args) const = 0;

  /// Authorize a principal to perform an operation.
  /// @param name The name of the principal.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  virtual bool Authorize(const string &name, const string &op,
                         const list<string> &args) = 0;

  /// Attempt to revoke authorization for a principal to perform an operation.
  /// @param name The name of the principal.
  /// @param op The name of the operation.
  /// @param args A list of arguments to the operation.
  virtual bool Forbid(const string &name, const string &op,
                      const list<string> &args) = 0;

  /// Get a string suitable for showing users authorization info.
  virtual string DebugString() const = 0;
};
}  // namespace tao

#endif  // TAO_TAO_GUARD_H_
