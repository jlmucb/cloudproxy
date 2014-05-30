//  File: cloud_channel.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A socket-based MessageChannel authenticated with TLS+Tao.
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
#ifndef CLOUDPROXY_CLOUD_CHANNEL_H_
#define CLOUDPROXY_CLOUD_CHANNEL_H_

#include "cloudproxy/cloud_channel.pb.h"
#include "cloudproxy/util.h"
#include "tao/message_channel.h"

namespace cloudproxy {

// A CloudChannel is a socket-based MessageChannel that is authenticated
// using TLS and Tao handshaking.
class CloudChannel : public tao::MessageChannel {
 public:
  /// Construct CloudChannel in un-authenticated state.
  /// @param ssl_ctx Parameters for TLS connection setup.
  /// @param sock A newly accepted TCP socket.
  CloudChannel(SSL_CTX *ssl_ctx, int sock);
  
  virtual ~CloudChannel();

  /// Perform TLS handshaking. Must be called before other methods.
  /// @{
  virtual bool TLSServerHandshake();
  virtual bool TLSClientHandshake();
  /// @}

  /// Perform Tao handshaking.
  /// @param self_delegation_ Degation containing our own TLS key and name.
  virtual bool TaoHandshake(const string &self_delegation);

  virtual bool SendMessage(const google::protobuf::Message &m) const;

  virtual bool ReceiveMessage(google::protobuf::Message *m, bool *eof) const;

  /// Notify peer of error before closing connection.
  /// @param msg The error message.
  virtual bool Abort(const string &msg);

  /// Notify peer of no error before closing connection.
  virtual bool Disconnect();

  /// Close connection.
  virtual bool Close();

  /// Get our own Tao name. Only valid after successful TaoHandshake().
  virtual string GetSelfName() { return self_name_; }

  /// Get peer's Tao name. Only valid after successful TaoHandshake().
  virtual string GetPeerName() { return peer_name_; }

  /// Maximum 20 MB for message reception on this channel.
  static constexpr size_t MaxMessageSize = 20 * 1024 * 1024;

 protected:
  /// Record our own self-signed certificate from the connection.
  bool InitTLSSelfCert();

  /// Record peer self-signed certificate from the connection.
  bool InitTLSPeerCert();

  /// Validate a delgation purportedly conveying cert->key speaksfor name.
  /// @param delegation The delegation to validate.
  /// @param cert A serialized self-signed x509 certificate for some key
  /// @param[out] name A name the certificate key speaks for.
  bool ValidateDelegation(const string &delegation, const string &cert,
                          string *name);

  /// Send a message without an encapsulating CloudConnectionMessage wrapper.
  /// @param tag The tag to send.
  /// @param msg The string to send.
  virtual bool SendFrame(CloudChannelFrameTag tag, const string &msg) const;

  /// Receive a message without an encapsulating CloudConnectionMessage wrapper.
  /// @param expected_tag The expected tag to be received.
  /// @param[out] msg The received string.
  /// @param[out] eof Whether the connection has been closed.
  virtual bool ReceiveFrame(CloudChannelFrameTag expeted_tag, string *msg,
                            bool *eof) const;

 private:
  /// The underlying TLS connection.
  ScopedSSL ssl_;

  /// Our own serialized, self-signed x509.
  string serialized_self_cert_;

  /// Peer's serialized, self-signed x509.
  string serialized_peer_cert_;

  // Our own Tao name.
  string self_name_;

  // Peer's Tao name.
  string peer_name_;
};
}  // namespace cloudproxy
#endif  // CLOUDPROXY_CLOUD_CHANNEL_H_
