//  File: direct_tao_child_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A TaoChildChannel that calls directly to another Tao object
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

#ifndef TAO_DIRECT_TAO_CHILD_CHANNEL_H_
#define TAO_DIRECT_TAO_CHILD_CHANNEL_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/scoped_ptr.h>

#include "tao/tao_child_channel.h"

namespace tao {

class Tao;

/// A TaoChannel that interacts directly with an underlying Tao object.
class DirectTaoChildChannel : public TaoChildChannel {
 public:
  /// The parent constructor with its descriptors and the child descriptors.
  /// @param tao The tao to use as the underlying object. Ownership is taken.
  /// @param child_name The name to pass to the tao in each call.
  DirectTaoChildChannel(Tao *tao, const string &child_name)
      : tao_(tao), child_name_(child_name) {}
  virtual ~DirectTaoChildChannel() {}

  virtual bool Init() { return true; }
  virtual bool Destroy() { return true; }

  /// These operations directly invoke the corresponding Tao method.
  /// @{
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &data, int policy, string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data, int *policy) const;
  virtual bool Attest(const string &data, string *attestation) const;
  virtual bool GetHostedProgramFullName(string *full_name) const;
  /// @}

 protected:
  virtual bool SendRPC(const TaoChildRequest &rpc) const { return false; }
  virtual bool ReceiveRPC(TaoChildResponse *resp, bool *eof) const {
    *eof = false;
    return false;
  }

 private:
  // The underlying Tao object to call.
  scoped_ptr<Tao> tao_;

  // The child name to pass to each call.
  string child_name_;

  DISALLOW_COPY_AND_ASSIGN(DirectTaoChildChannel);
};
}  // namespace tao

#endif  // TAO_DIRECT_TAO_CHILD_CHANNEL_H_
