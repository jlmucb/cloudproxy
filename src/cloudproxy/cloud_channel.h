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
#include "cloudproxy/tls_message_channel.h"
#include "cloudproxy/util.h"
#include "tao/message_channel.h"

namespace cloudproxy {

// A socket-based MessageChannel authenticated using TLS and Tao handshaking,
// augmented with messages for clean disconnect and abort.
class CloudChannel {
 public:
  /// Construct CloudChannel in un-authenticated state.
  /// @param tls_ctx Parameters for TLS connection setup.
  /// @param sock A newly accepted TCP socket.
  CloudChannel(SSL_CTX *tls_ctx, int sock);
  
  virtual ~CloudChannel() {}

  /// These methods have the same semantics as MessageChannel.
  /// @{
  virtual void Close() { chan_.Close(); }
  virtual bool IsClosed() { return chan_.IsClosed(); }
  virtual bool SendData(const void *buffer, size_t buffer_len);
  virtual bool ReceiveData(void *buffer, size_t buffer_len, bool *eof);
  virtual bool SendString(const string &s);
  virtual bool ReceiveString(string *s, bool *eof);
  virtual bool SendMessage(const google::protobuf::Message &m);
  virtual bool ReceiveMessage(google::protobuf::Message *m, bool *eof);
  /// @}

  /// Perform TLS handshaking. Must be called before other methods.
  /// @{
  virtual bool TLSServerHandshake() { return chan_.TLSServerHandshake(); }
  virtual bool TLSClientHandshake() { return chan_.TLSClientHandshake(); }
  /// @}

  /// Perform Tao handshaking. Must be called after TLS handshake and
  /// before other methods.
  /// @param self_delegation_ Degation containing our own TLS key and name.
  virtual bool TaoHandshake(const string &self_delegation);

  /// Notify peer of error, not wait for confirmation, then close connection.
  /// @param msg The error message.
  virtual bool Abort(const string &msg);

  /// Notify peer of no error, wait for confirmation from peer, then close
  /// connection.
  virtual bool Disconnect();

  /// Get our own Tao name. Only valid after successful TaoHandshake().
  virtual string SelfName() { return self_name_; }

  /// Get peer's Tao name. Only valid after successful TaoHandshake().
  virtual string PeerName() { return peer_name_; }

 protected:
  /// Validate a delgation purportedly conveying cert->key speaksfor name.
  /// @param delegation The delegation to validate.
  /// @param cert A serialized self-signed x509 certificate for some key
  /// @param[out] name A name the certificate key speaks for.
  bool ValidateDelegation(const string &delegation, const string &cert,
                          string *name);

  /// Send a message in an encapsulating CloudChannelFrame wrapper.
  /// @param tag The tag to send.
  /// @param msg The string to send.
  virtual bool SendFrame(CloudChannelFrameTag tag, const string &msg);

  /// Receive a message in an encapsulating CloudChannelFrame wrapper.
  /// @param expected_tag The expected tag to be received.
  /// @param[out] msg The received string.
  /// @param[out] eof Whether the connection has been closed.
  virtual bool ReceiveFrame(CloudChannelFrameTag expeted_tag, string *msg,
                            bool *eof);

  /// This method is never used since the underlying channel is
  /// message-oriented, not streams oriented..
  virtual bool ReceivePartialData(void *buffer, size_t max_recv_len,
                                  size_t *recv_len, bool *eof) {
    Close();
    return false;
  }

 private:
  /// The underlying TLS connection.
  TLSMessageChannel chan_;

  // Our own Tao name.
  string self_name_;

  // Peer's Tao name.
  string peer_name_;

  DISALLOW_COPY_AND_ASSIGN(CloudChannel);
};
}  // namespace cloudproxy
#endif  // CLOUDPROXY_CLOUD_CHANNEL_H_
