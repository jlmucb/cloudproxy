//  File: tao_rpc.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: RPC client stub for channel-based Tao implementations.
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
#ifndef TAO_TAO_RPC_H_
#define TAO_TAO_RPC_H_

#include <string>

#include "tao/message_channel.h"
#include "tao/tao.h"
#include "tao/tao_rpc.pb.h"

namespace tao {
using std::string;

/// A class that sends Tao requests and responses over a channel between Tao
/// hosts and Tao hosted programs. 
class TaoRPC : public Tao {
 public:
  /// Construct a TaoRPC.
  /// @param channel The channel over which to send and recieve messages.
  /// Ownership is taken.
  TaoRPC(MessageChannel *channel) : channel_(channel) {}

  /// Tao implementation.
  /// @{
  virtual bool GetTaoName(string *name) const;
  virtual bool ExtendTaoName(const string &subprin) const;
  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Attest(const Statement &stmt, string *attestation) const;
  virtual bool Seal(const string &data, const string &policy,
                    string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data, string *policy) const;
  /// @}

 protected:
  /// The channel over which to send and receive messages.
  scoped_ptr<MessageChannel> channel_;

 private:
  /// Do an RPC request/response interaction with the host Tao.
  /// @param req The request to send.
  /// @param[out] data The returned data, if not nullptr.
  /// @param[out] policy The returned policy, if not nullptr.
  bool Request(const TaoRPCRequest &req, string *data, string *policy) const;
};
}  // namespace tao

#endif  // TAO_TAO_RPC_H_
