//  File: tls_message_channel.cc
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
#include "cloudproxy/tls_message_channel.h"

#include <arpa/inet.h>

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <openssl/ssl.h>

#include "cloudproxy/util.h"
#include "tao/keys.h"

using tao::OpenSSLSuccess;

namespace cloudproxy {

TLSMessageChannel::TLSMessageChannel(SSL_CTX *tls_ctx, int sock)
    : tls_(SSL_new(tls_ctx)) {
  SSL_set_fd(tls_.get(), sock);
}

bool TLSMessageChannel::TLSServerHandshake() {
  if (SSL_accept(tls_.get()) == -1) {
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

bool TLSMessageChannel::TLSClientHandshake() {
  if (SSL_connect(tls_.get()) == -1) {
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

bool TLSMessageChannel::InitTLSSelfCert() {
  // Don't delete our own X.509 certificate, since it is owned by the SSL_CTX
  // and will be deleted there. 
  X509 *self_cert = SSL_get_certificate(tls_.get());
  serialized_self_cert_ = tao::SerializeX509(self_cert);
  return (serialized_self_cert_ != "");
}

bool TLSMessageChannel::InitTLSPeerCert() {
  // Be sure to delete peer cert, is is not owned by SSL_CTX.
  tao::ScopedX509 peer_cert(SSL_get_peer_certificate(tls_.get()));
  if (peer_cert.get() == nullptr) {
    LOG(ERROR) << "No X.509 certificate received from the client";
    return false;
  }
  serialized_peer_cert_ = tao::SerializeX509(peer_cert.get());
  return (serialized_peer_cert_ != "");
}

bool TLSMessageChannel::SendData(const void *buffer, size_t buffer_len) {
  if (IsClosed()) {
    LOG(ERROR) << "Could not send data, channel already closed";
    return false;
  }
  // SSL_write with length 0 is undefined, so catch that case here
  if (buffer_len == 0) return true;
  // SSL is configured as blocking with auto-retry, so
  // SSL_write will either succeed completely or fail immediately.
  int bytes_written = SSL_write(tls_.get(), buffer, buffer_len);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Failed to write data to SSL";
    Close();
    return false;
  }
  if (bytes_written == 0) {
    LOG(ERROR) << "SSL connection closed";
    Close();
    return false;
  }
  if (bytes_written < 0) {
    LOG(ERROR) << "SSL write failed";
    Close();
    return false;
  }
  // Unless someone sets SSL_MODE_ENABLE_PARTIAL_WRITE,
  // SSL_write should always write the whole buffer.
  if (static_cast<size_t>(bytes_written) != buffer_len) {
    LOG(ERROR) << "Unexpected partial SSL write";
    Close();
    return false;
  }
  return true;
}

bool TLSMessageChannel::ReceivePartialData(void *buffer, size_t max_recv_len,
                                          size_t *recv_len, bool *eof) {
  if (IsClosed()) {
    LOG(ERROR) << "Can't receive data, channel is already closed";
    *eof = true;
    return true;
  } else {
    *eof = false;
  }
  int in_len =
      SSL_read(tls_.get(), reinterpret_cast<unsigned char *>(buffer), max_recv_len);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Failed to read data from SSL";
    Close();
    return false;
  } else if (in_len == 0) {
    *eof = true;
    Close();
    return true;
  } else if (in_len < 0) {
    LOG(ERROR) << "Failed to read data from tls channel";
    Close();
    return false;
  }
  *recv_len = in_len;
  return true;
}

void TLSMessageChannel::TLSClose() {
  if (!tls_.get())
    return;
  LOG(INFO) << "Closing tls channel";
  SSL_shutdown(tls_.get());
  tls_.reset();  // This will call SSL_free() and close()
}

}  // namespace cloudproxy
