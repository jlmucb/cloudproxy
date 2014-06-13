//  File: tls_message_channel.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A socket-based MessageChannel authenticated with TLS.
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
#ifndef CLOUDPROXY_TLS_MESSAGE_CHANNEL_H_
#define CLOUDPROXY_TLS_MESSAGE_CHANNEL_H_

#include "cloudproxy/util.h"
#include "tao/message_channel.h"

namespace cloudproxy {

/// A MessageChannel that communicates with a remote endpoint over a TLS socket.
/// On Close() or object destruction the socket will be closed.
class TLSMessageChannel : public tao::MessageChannel {
 public:
  /// Construct TLSMessageChannel.
  /// @param tls_ctx Parameters for TLS connection setup.
  /// @param sock A newly accepted TCP socket.
  TLSMessageChannel(SSL_CTX *tls_ctx, int sock);
  
  virtual ~TLSMessageChannel() { TLSClose(); }

  /// These methods have the same semantics as MessageChannel.
  /// @{
  virtual void Close() { TLSClose(); }
  virtual bool IsClosed() const { return (tls_.get() == nullptr); }
  virtual bool SendData(const void *buffer, size_t buffer_len);
  /// @}

  /// Perform TLS handshaking. Must be called before other methods.
  /// @{
  virtual bool TLSServerHandshake();
  virtual bool TLSClientHandshake();
  /// @}

  /// Get certificate information for the TLS connection
  /// @{
  string GetTLSSelfCert() const { return serialized_self_cert_; }
  string GetTLSPeerCert() const { return serialized_peer_cert_; }
  /// @}

 protected:
  /// Record our own self-signed certificate from the connection.
  bool InitTLSSelfCert();

  /// Record peer self-signed certificate from the connection.
  bool InitTLSPeerCert();

 private:
  /// The underlying TLS connection.
  ScopedSSL tls_;

  /// Our own serialized, self-signed x509.
  string serialized_self_cert_;

  /// Peer's serialized, self-signed x509.
  string serialized_peer_cert_;

  /// These methods have the same semantics as MessageChannel.
  /// @{
  virtual bool ReceivePartialData(void *buffer, size_t max_recv_len,
                                  size_t *recv_len, bool *eof);
  /// @}
 
  /// A non-virtual version of close for use in destructor.
  void TLSClose();

  DISALLOW_COPY_AND_ASSIGN(TLSMessageChannel);
};
}  // namespace cloudproxy
#endif  // CLOUDPROXY_TLS_MESSAGE_CHANNEL_H_
