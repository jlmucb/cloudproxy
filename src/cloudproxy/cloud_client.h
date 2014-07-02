//  File: cloud_client.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Client-side stub that communicates with CloudServer instances
// over a TLS+Tao authenticated channel.
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
#ifndef CLOUDPROXY_CLOUD_CLIENT_H_
#define CLOUDPROXY_CLOUD_CLIENT_H_

#include <string>

#include "cloudproxy/util.h"

namespace tao {
class Signer;
}

namespace cloudproxy {
using std::string;

class CloudChannel;

/// A client that opens a TCP connection and does TLS+Tao authentication with a
/// CloudServer instance.
class CloudClient {
 public:
  /// Construct a client. Temporary TLS keys and certificates will be generated.
  CloudClient() {}
  
  /// Construct a client.
  /// @param tls_key A key to use for TLS. Ownership is taken. If nullptr, a
  /// new temporary key will be generated.
  /// @param tls_cert A serialized PEM-encoded x509 certificate for tls_key. If
  /// emptystring, a new self-signed certificate will be generated.
  /// @param tls_delegation A serialized host Tao delegation for tls_key. If
  /// emptystring, a new delegation will be generated.
  CloudClient(tao::Signer *tls_key, const string &tls_cert,
              const string &tls_delegation)
      : tls_key_(tls_key),
        tls_self_cert_(tls_cert),
        tls_delegation_(tls_delegation) {}

  virtual bool Init();
  virtual ~CloudClient() {}

  /// Connect to a server and do TLS+Tao authentication.
  /// @param server The server to connect to.
  /// @param port The port to connect to on the server.
  virtual bool Connect(const string &server, const string &port);

  /// Get a pointer to the connection after connecting to server.
  /// Ownership is retained by this class.
  virtual CloudChannel *Channel() { return chan_.get(); }
  
  /// Close the channel, usually after calling Channel->Abort() or
  /// Channel->Disconnect().
  virtual bool Close() {
    chan_.reset(nullptr);
    return true;
  }

 private:
  /// A context object that stores TLS parameters.
  ScopedSSLCtx tls_context_;

  /// A signing key for TLS.
  scoped_ptr<tao::Signer> tls_key_;

  /// A self-signed certificate for the TLS key.
  string tls_self_cert_;
  
  /// Delegation for the TLS key, signed on our behalf by the host Tao.
  string tls_delegation_;

  /// A TLS connection to a CloudServer.
  scoped_ptr<CloudChannel> chan_;

  DISALLOW_COPY_AND_ASSIGN(CloudClient);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_CLOUD_CLIENT_H_
