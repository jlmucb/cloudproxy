//  File: util.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of useful functions for CloudProxy
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

#include "cloudproxy/util.h"

#include <glog/logging.h>
#include <keyczar/crypto_factory.h>

#include "tao/keys.h"
#include "tao/util.h"

using tao::Signer;
using tao::OpenSSLSuccess;
using tao::ScopedX509;

namespace cloudproxy {

/// Size of random SSL session IDs, large enough to avoid rollover or session
/// clashes in the common case.
static const int SessionIDSize = 4;

void ssl_cleanup(SSL *ssl) {
  if (ssl != nullptr) {
    int fd = SSL_get_fd(ssl);
    SSL_free(ssl);
    if (!OpenSSLSuccess()) {
      PLOG(ERROR) << "Could not close SSL " << fd;
    }
    if (close(fd) < 0) {
      PLOG(ERROR) << "Could not close socket " << fd;
    }
  }
}

static int AlwaysAcceptCert(int preverify_ok, X509_STORE_CTX *ctx) {
  // we always let the X.509 cert pass verification because we're
  // going to check it using a Tao handshake message exchange.
  return 1;
}

static bool SetUpSSLCtx(const SSL_METHOD *method, const Signer &key,
                        const string &cert, bool require_peer_cert,
                        ScopedSSLCtx *ctx) {
  if (!ctx || cert.empty()) {
    LOG(ERROR) << "Invalid SetUpSSLCTX parameters";
    return false;
  }
  tao::ScopedEvpPkey evp_key(key.GetEvpPkey());
  if (evp_key.get() == nullptr) {
    LOG(ERROR) << "Could not export key to openssl";
    return false;
  }

  // Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
  // So, they need to be added again. Typical error is:
  // * 336236785:SSL routines:SSL_CTX_new:unable to load ssl2 md5 routines
  OpenSSL_add_all_algorithms();

  ctx->reset(SSL_CTX_new(method));
  if (ctx->get() == nullptr) {
    LOG(ERROR) << "Could not create TLS context";
    return false;
  }

  // Set up the TLS connection with the list of acceptable ciphers.
  // We only accept ECDH key exchange, with ECDSA signatures and GCM
  // for the channel. Cloudproxy prefers ECDHE-ECDSA-AES256-GCM-SHA384,
  // but chrome currently supports only ECDHE-ECDSA-AES128-GCM-SHA256,
  // so we allow both.
  if (!SSL_CTX_set_cipher_list(
          ctx->get(),
          "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")) {
    LOG(ERROR) << "Could not set up a cipher list on the TLS context";
    return false;
  }

  // turn off compression (?)
  if (!SSL_CTX_set_options(ctx->get(), SSL_OP_NO_COMPRESSION)) {
    LOG(ERROR) << "Could not turn off compression on the TLS connection";
    return false;
  }

  // turn on auto-retry for reads and writes
  if (!SSL_CTX_set_mode(ctx->get(), SSL_MODE_AUTO_RETRY)) {
    LOG(ERROR)
        << "Could not turn on auto-retry for reads and writes on the TLS "
           "connection";
    return false;
  }

  // string tls_cert_file = keys->SigningX509CertificatePath();
  // if (!SSL_CTX_use_certificate_chain_file(ctx->get(), tls_cert_file.c_str())) {
  //   LOG(ERROR) << "Could not load the certificate chain for this connection";
  //   return false;
  // }
  ScopedX509 x509(tao::DeserializeX509(cert));
  if (x509.get() == nullptr ||
      !SSL_CTX_use_certificate(ctx->get(), x509.get())) {
    // TODO(kwalsh) Does SSL_CTX_use_certificate take ownership of x509 pointer?
    // TODO(kwalsh) handle x509 chains?
    LOG(ERROR) << "Could not load the certificate chain for this connection";
    return false;
  }

  if (!SSL_CTX_use_PrivateKey(ctx->get(), evp_key.get())) {
    LOG(ERROR) << "Could not set the private key for this connection";
    return false;
  }

  // set up verification to (optionally) insist on getting a certificate from
  // the peer
  int verify_mode = SSL_VERIFY_PEER;
  if (require_peer_cert) verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  SSL_CTX_set_verify(ctx->get(), verify_mode, AlwaysAcceptCert);

  // Set session id context to a unique id to avoid session reuse problems when
  // using client certs. No need to use a strong random -- we could just use a
  // counter instead.
  string sid;
  if (!keyczar::CryptoFactory::Rand()->RandBytes(SessionIDSize, &sid) ||
      !SSL_CTX_set_session_id_context(
          ctx->get(), reinterpret_cast<const unsigned char *>(sid.c_str()),
          sid.length())) {
    LOG(ERROR) << "Could not set session id";
    return false;
  }

  // set up the server to use ECDH for key agreement using ANSI X9.62
  // Prime 256 V1
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ecdh == nullptr) {
    LOG(ERROR) << "EC curve not found";
    return false;
  }
  if (!SSL_CTX_set_tmp_ecdh(ctx->get(), ecdh)) {
    LOG(ERROR) << "Could not set up ECDH";
    return false;
  }

  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Failed to create SSL context";
    return false;
  }

  return true;
}

bool SetUpSSLServerCtx(const Signer &key, const string &cert, ScopedSSLCtx *ctx) {
  return SetUpSSLCtx(TLSv1_2_server_method(), key, cert, true, ctx);
}

bool SetUpSSLClientCtx(const Signer &key, const string &cert, ScopedSSLCtx *ctx) {
  return SetUpSSLCtx(TLSv1_2_client_method(), key, cert, true, ctx);
}

}  // namespace cloudproxy
