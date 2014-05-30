//  File: cloud_channel.cc
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
#include "cloudproxy/cloud_channel.h"

#include <arpa/inet.h>

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <openssl/ssl.h>

#include "cloudproxy/util.h"
#include "tao/attestation.h"
#include "tao/keys.h"

using tao::OpenSSLSuccess;

namespace cloudproxy {
constexpr size_t CloudChannel::MaxMessageSize;

// TODO(kwalsh) Consier merge helper functions with  similarly-named functions
// in tao/fd_message_channel.cc?

CloudChannel::CloudChannel(SSL_CTX *ssl_ctx, int sock)
    : ssl_(SSL_new(ssl_ctx)) {
  SSL_set_fd(ssl_.get(), sock);
}

bool CloudChannel::TLSServerHandshake() {
  if (SSL_accept(ssl_.get()) == -1) {
    LOG(ERROR) << "Could not perform TLS server handshake";
    return false;
  }
  if (!InitTLSSelfCert()) {
    LOG(ERROR) << "Could not initialize TLS self cert";
    return false;
  }
  if (!InitTLSPeerCert()) {
    LOG(ERROR) << "Could not initialize TLS peer cert";
    return false;
  }
  return true;
}

bool CloudChannel::TLSClientHandshake() {
  if (SSL_connect(ssl_.get()) == -1) {
    LOG(ERROR) << "Could not perform TLS client handshake";
    return false;
  }
  if (!InitTLSSelfCert()) {
    LOG(ERROR) << "Could not initialize TLS self cert";
    return false;
  }
  if (!InitTLSPeerCert()) {
    LOG(ERROR) << "Could not initialize TLS peer cert";
    return false;
  }
  return true;
}

bool CloudChannel::InitTLSSelfCert() {
  // Don't delete our own X.509 certificate, since it is owned by the SSL_CTX
  // and will be deleted there. 
  X509 *self_cert = SSL_get_certificate(ssl_.get());
  return tao::SerializeX509(self_cert, &serialized_self_cert_);
}

bool CloudChannel::InitTLSPeerCert() {
  // Be sure to delete peer cert, is is not owned by SSL_CTX.
  tao::ScopedX509 peer_cert(SSL_get_peer_certificate(ssl_.get()));
  if (peer_cert.get() == nullptr) {
    LOG(ERROR) << "No X.509 certificate received from the client";
    return false;
  }
  return tao::SerializeX509(peer_cert.get(), &serialized_peer_cert_);
}

bool CloudChannel::ValidateDelegation(const string &delegation,
                                         const string &cert, string *name) {
  string delegate, issuer;
  if (!tao::ValidateDelegation(delegation, tao::CurrentTime(), &delegate,
                               &issuer)) {
    LOG(ERROR) << "Delegation is invalid";
    return false;
  }
  scoped_ptr<keyczar::Verifier> cert_key(tao::VerifierFromX509(cert));
  if (cert_key.get() == nullptr) {
    LOG(ERROR) << "Could not parse key from x509";
    return false;
  }
  string cert_key_name;
  if (!tao::VerifierToPrincipalName(*cert_key, &cert_key_name)) {
    LOG(ERROR) << "Could not get principal name for x509 key";
    return false;
  }

  if (delegate != cert_key_name) {
    LOG(ERROR) << "Delegated key did not match x509 key";
    return false;
  }
  name->assign(issuer);
  return true;
}

bool CloudChannel::TaoHandshake(const string &self_delegation) {
  if (!ValidateDelegation(self_delegation, serialized_self_cert_, &self_name_)) {
    LOG(ERROR) << "Could not initialize Tao self name";
    return false;
  }
  // Exchange Tao delegations.
  string peer_delegation;
  bool eof;
  if (!SendFrame(CLOUD_CHANNEL_FRAME_HANDSHAKE, self_delegation) ||
      !ReceiveFrame(CLOUD_CHANNEL_FRAME_HANDSHAKE, &peer_delegation, &eof)) {
    LOG(ERROR) << "Could not exchange Tao delegations";
    return false;
  }
  if (eof) {
    LOG(ERROR) << "Lost connection while exchanging Tao delegations";
    return false;
  }
  if (!ValidateDelegation(peer_delegation, serialized_peer_cert_,
                          &peer_name_)) {
    LOG(ERROR) << "Could not initialize Tao peer name";
    return false;
  }
  return true;
}

// This is nearly identical to function in fd_message_channel.cc 
/// Send data to an SSL connection.
/// @param fd The SSL connection to use to send the data.
/// @param buffer The buffer containing data to send.
/// @param buffer_len The length of buffer.
static bool SendData(SSL *ssl, const void *buffer, size_t buffer_len) {
  // SSL_write with length 0 is undefined, so catch that case here
  if (buffer_len == 0) return true;
  // SSL is configured as blocking with auto-retry, so
  // SSL_write will either succeed completely or fail immediately.
  int out_len = SSL_write(ssl, buffer, buffer_len);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Failed to write data to SSL";
    return false;
  }
  if (out_len == 0) {
    LOG(ERROR) << "SSL connection closed";
    return false;
  }
  if (out_len < 0) {
    LOG(ERROR) << "SSL write failed";
    return false;
  }
  // Unless someone sets SSL_MODE_ENABLE_PARTIAL_WRITE,
  // SSL_write should always write the whole buffer.
  if (static_cast<size_t>(out_len) != buffer_len) {
    LOG(ERROR) << "Unexpected partial SSL write";
    return false;
  }
  return true;
}

/// Send a string to an SSL connection.
/// @param fd The SSL connection to use to send the string.
/// @param s The string to send.
// This is nearly identical to function in fd_message_channel.cc 
static bool SendString(SSL *ssl, const string &s) {
  uint32_t net_len = htonl(s.size());
  return SendData(ssl, &net_len, sizeof(net_len)) &&
         SendData(ssl, s.c_str(), s.size());
}

bool CloudChannel::SendFrame(CloudChannelFrameTag tag, const string &msg) const {
  CloudChannelFrame frame;
  frame.set_tag(tag);
  frame.set_msg(msg);
  string serialized;
  if (!frame.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize request";
    return false;
  }
  return SendString(ssl_.get(), serialized);
}

bool CloudChannel::SendMessage(const google::protobuf::Message &m) const {
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }
  return SendFrame(CLOUD_CHANNEL_FRAME_WRAPPED, serialized);
}

// This is nearly identical to function in fd_message_channel.cc 
/// Receive partial data from an SSL connection. This reads into buffer[i],
/// where filled_len <= i < buffer_len, and it returns the number of bytes read,
/// or 0 if end of stream, or negative on error.
/// @param fd The SSL connection to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param filed_len The length of buffer that is already filled.
/// @param buffer_len The total length of buffer.
static int ReceivePartialData(SSL *ssl, void *buffer, size_t filled_len,
                       size_t buffer_len) {
  if (ssl == nullptr || buffer == nullptr || filled_len >= buffer_len) {
    LOG(ERROR) << "Invalid ReceivePartialData parameters";
    return -1;
  }
  int in_len =
      SSL_read(ssl, reinterpret_cast<unsigned char *>(buffer) + filled_len,
               buffer_len - filled_len);
  if (!OpenSSLSuccess()) LOG(ERROR) << "Failed to read data from SSL";
  return in_len;
}

// This is nearly identical to function in fd_message_channel.cc 
/// Receive data from an SSL connection.
/// @param fd The SSL connection to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param buffer_len The length of buffer.
/// @param[out] eof Will be set to true iff end of stream reached.
static bool ReceiveData(SSL *ssl, void *buffer, size_t buffer_len, bool *eof) {
  *eof = false;
  size_t filled_len = 0;
  while (filled_len != buffer_len) {
    int in_len = ReceivePartialData(ssl, buffer, filled_len, buffer_len);
    if (in_len == 0) {
      *eof = true;
      return (filled_len == 0);  // fail only on truncated message
    }
    if (in_len < 0) return false;  // fail on errors
    filled_len += in_len;
  }
  return true;
}

// This is nearly identical to function in fd_message_channel.cc 
/// Receive a string from an SSL connection.
/// @param fd The SSL connection to use to receive the data.
/// @param max_size The maximum allowable size string to receive.
/// @param[out] s The string to receive the data.
/// @param[out] eof Will be set to true iff end of stream reached.
static bool ReceiveString(SSL *ssl, size_t max_size, string *data, bool *eof) {
  uint32_t net_len;
  if (!ReceiveData(ssl, &net_len, sizeof(net_len), eof)) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  } else if (*eof) {
    return true;
  }
  uint32_t len = ntohl(net_len);
  if (len > max_size) {
    LOG(ERROR) << "Message exceeded maximum allowable size";
    return false;
  }
  scoped_array<char> temp_data(new char[len]);
  if (!ReceiveData(ssl, temp_data.get(), static_cast<size_t>(len), eof) ||
      *eof) {
    LOG(ERROR) << "Could not get the data";
    return false;
  }
  data->assign(temp_data.get(), len);
  return true;
}


bool CloudChannel::ReceiveFrame(CloudChannelFrameTag expected_tag, string *msg,
                                bool *eof) const {
  string s;
  if (!ReceiveString(ssl_.get(), MaxMessageSize, &s, eof)) {
    LOG(ERROR) << "Could not receive message";
    return false;
  } else if (*eof) {
    return true;
  }
  CloudChannelFrame frame;
  if (!frame.ParseFromString(s)) {
    LOG(ERROR) << "Could not parse message";
    return false;
  }
  switch (frame.tag()) {
    case CLOUD_CHANNEL_FRAME_ABORT:
      LOG(ERROR) << "Connection closed by peer with error: " << frame.msg();
      *eof = true;
      return true;
    case CLOUD_CHANNEL_FRAME_SHUTDOWN:
      LOG(INFO) << "Connection closed by peer";
      *eof = true;
      return true;
    default:
      if (frame.tag() != expected_tag) {
        LOG(INFO) << "Unexpected message tag: " << frame.tag();
        return false;
      }
      msg->assign(frame.msg());
      return true;
  }
}

bool CloudChannel::ReceiveMessage(google::protobuf::Message *m,
                                     bool *eof) const {
  string serialized;
  if (!ReceiveFrame(CLOUD_CHANNEL_FRAME_WRAPPED, &serialized, eof)) {
    LOG(ERROR) << "Could not receive wrapped message";
    return false;
  }
  if (*eof) {
    LOG(WARNING) << "Connection has unexpectedly closed";
    return true;
  }
  if (m->ParseFromString(serialized)) {
    LOG(ERROR) << "Could not unwrap message";
    return false;
  }
  return true;
}

bool CloudChannel::Abort(const string &msg) {
  return SendFrame(CLOUD_CHANNEL_FRAME_ABORT, msg);
}

bool CloudChannel::Disconnect() {
  return SendFrame(CLOUD_CHANNEL_FRAME_SHUTDOWN, "" /* empty message */);
}

bool CloudChannel::Close() {
  if (!ssl_.get())
    return true;
  SSL_shutdown(ssl_.get());
  ssl_.reset();  // This will call SSL_free() and close()
  return true;
}

}  // namespace cloudproxy
