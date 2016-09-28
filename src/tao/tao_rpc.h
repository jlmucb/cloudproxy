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
  /// @param channel The channel over which to send and receive messages.
  /// Ownership is taken.
  explicit TaoRPC(MessageChannel *channel) : channel_(channel) {}

  virtual void Close() { channel_->Close(); }

  virtual bool SerializeToString(string *params) const;

  static TaoRPC *DeserializeFromString(const string &params);

  /// Tao implementation.
  /// @{
  virtual bool GetTaoName(string *name);
  virtual bool ExtendTaoName(const string &subprin);
  virtual bool GetRandomBytes(size_t size, string *bytes);
  virtual bool GetSharedSecret(size_t size, const string &policy,
                               string *bytes);
  virtual bool Attest(const string &message, string *attestation);
  virtual bool Seal(const string &data, const string &policy, string *sealed);
  virtual bool Unseal(const string &sealed, string *data, string *policy);

  virtual bool InitCounter(const string &label, int64_t& c);
  virtual bool GetCounter(const string &label, int64_t* c);
  virtual bool RollbackProtectedSeal(const string &data, const string &policy, string *sealed);
  virtual bool RollbackProtectedUnseal(const string &sealed, string *data, string *policy);

  virtual string GetRecentErrorMessage() const { return failure_msg_; }
  virtual string ResetRecentErrorMessage() {
    string msg = failure_msg_;
    failure_msg_ = "";
    return msg;
  }
  /// @}

 protected:
  /// The channel over which to send and receive messages.
  unique_ptr<MessageChannel> channel_;

  /// Most recent RPC failure message, if any.
  string failure_msg_;

  /// Most recent RPC sequence number.
  unsigned int last_seq_;

 private:
  /// Do an RPC request/response interaction with the host Tao.
  /// @param op The operation.
  /// @param req The request to send.
  /// @param[out] data The returned data, if not nullptr.
  /// @param[out] policy The returned policy, if not nullptr.
  bool Request(const string &op, const TaoRPCRequest &req, string *data,
               string *policy);

  DISALLOW_COPY_AND_ASSIGN(TaoRPC);
};
}  // namespace tao

#endif  // TAO_TAO_RPC_H_
