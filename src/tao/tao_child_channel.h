//  File: tao_child_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A class for communication from hosted program to the host
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

#ifndef TAO_TAO_CHILD_CHANNEL_H_
#define TAO_TAO_CHILD_CHANNEL_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN

#include "tao/tao_child_channel.pb.h"

using std::string;

namespace tao {
/// An interface that hosted programs use to communicate with a host Tao. It
/// implements an interface similar to the Tao but without the child_name
/// parameter in cases where it is implicit. Other parameters are bundled
/// up and sent in a message along the channel. The details of this message
/// passing depend on the specific implementation). The host TaoChannel RPC
/// server will, upon receiving a message, add the appropriate child_name
/// parameter. In this way, a hosted program is not free to use an arbitrary
/// hash.
class TaoChildChannel {
 public:
  TaoChildChannel() {}
  virtual ~TaoChildChannel() {}

  /// Initialize by opening ports and acquiring resources as needed.
  virtual bool Init() { return true; }

  /// Disconnect ports and release resources acquired during Init().
  virtual bool Destroy() { return true; }

  /// Methods that invoke the hosted-program interfaces of the host Tao.
  /// These methods omit the child_name parameter since it is implicit.
  /// @{

  /// Get random bytes. See Tao for semantics.
  virtual bool GetRandomBytes(size_t size, string *bytes) const;

  /// Seal data. See Tao for semantics.
  virtual bool Seal(const string &data, int policy, string *sealed) const;

  /// Unseal data. See Tao for semantics.
  virtual bool Unseal(const string &sealed, string *data, int *policy) const;

  /// Generate attestation. See Tao for semantics.
  virtual bool Attest(const string &stmt, string *attestation) const;

  /// Get our full name. See Tao for semantics.
  virtual bool GetHostedProgramFullName(string *full_name) const;

  /// Extend our name. See Tao for semantics.
  virtual bool ExtendName(const string &subprin) const;

  /// @}

 protected:
  /// Send an RPC request to the host Tao.
  /// @param rpc The rpc to send.
  virtual bool SendRPC(const TaoChildRequest &rpc) const = 0;

  /// Receive an RPC response from the host Tao.
  /// @param[out] resp The response received.
  /// @param[out] eof Set to true if end of stream reached.
  virtual bool ReceiveRPC(TaoChildResponse *resp, bool *eof) const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaoChildChannel);
};
}  // namespace tao

#endif  // TAO_TAO_CHILD_CHANNEL_H_
