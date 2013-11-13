//  File: legacy_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A class for communication between hosted programs and
//  the Legacy Tao.
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

#ifndef LEGACY_TAO_TAO_CHANNEL_H_
#define LEGACY_TAO_TAO_CHANNEL_H_

#include "tao/tao_channel.h"

// jlm's taoHostServices and taoEnvironment
// along with startMeAsMeasuredProgram for clients of LegacyTao
#include <tao.h>

namespace legacy_tao {
// A connection to a legacy Host Tao from the original implementation
// of CloudProxy.
class LegacyTaoChannel : public tao::TaoChannel {
 public:
  LegacyTaoChannel(const string &directory);
  virtual ~LegacyTaoChannel() {}

  // Tao interface methods
  virtual bool Init();
  virtual bool Destroy() { return true; }

  // the LegacyTaoChannel doesn't support starting programs
  virtual bool StartHostedProgram(const string &path, int argc, char **argv) {
    CHECK(false) << "Cannot start programs using the LegacyTaoChannel";
    return false;
  }

  virtual bool GetRandomBytes(size_t size, string *bytes) const;
  virtual bool Seal(const string &data, string *sealed) const;
  virtual bool Unseal(const string &sealed, string *data) const;
  virtual bool Attest(const string &data, string *attestation) const;
  virtual bool VerifyAttestation(const string &attestation) const;
  virtual bool ExtractData(const string &attestation, string *data) const;

 protected:
  // The LegacyTaoChannel implements all the Tao interface methods
  // directly without sending messages. So, it should fail if Listen is
  // called (on the tao::TaoChannel interface).
  virtual bool ReceiveMessage(google::protobuf::Message *m) {
    CHECK(false) << "The LegacyTaoChannel does not send or receive messages on "
                    "an underlying transport mechanism";
    return false;
  }

  virtual bool SendMessage(const google::protobuf::Message &m) {
    CHECK(false) << "The LegacyTaoChannel does not send or receive messages on "
                    "an underlying transport mechanism";
    return false;
  }

 private:
  // A 5-minute attestation timeout
  static const int AttestationTimeout = 300;

  /// The directory used for initializing the legacy Tao
  string directory_;

  /// The subdirectory of #directory_ that is used to storage keys
  /// created and managed by the legacy Tao.
  string keys_directory_;

  /// The domain to use in the legacy Tao's certificates, like
  /// www.manferdelli.com
  string domain_name_;

  /// The legacy Tao host
  scoped_ptr<taoHostServices> tao_host_;

  /// The legacy Tao environment
  scoped_ptr<taoEnvironment> tao_env_;

  /// The policy key in a form used by the legacy tao
  scoped_ptr<PrincipalCert> legacy_policy_key_;
};
}  // namespace tao

#endif  // TAO_TAO_CHANNEL_H_
