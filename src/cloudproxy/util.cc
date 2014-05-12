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
#include <arpa/inet.h>

#include <glog/logging.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/values.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <openssl/x509v3.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/file_server.h"
#include "cloudproxy/util.h"
#include "tao/keys.h"
#include "tao/util.h"

using keyczar::Signer;
using keyczar::base::PathExists;
using keyczar::base::ReadFileToString;
using keyczar::base::ScopedSafeString;
using keyczar::base::WriteStringToFile;

using cloudproxy::CloudAuth;
using tao::Keys;
using tao::OpenSSLSuccess;
using tao::ScopedFile;
using tao::SignData;
using tao::VerifySignature;

#define READ_BUFFER_LEN 16384

namespace cloudproxy {

static const int SessionIDSize = 20;

void ecleanup(EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_cleanup(ctx); }

// TODO(kwalsh) use keyczar HMACImpl instead of openssl, it has nicer api
void hcleanup(HMAC_CTX *ctx) { HMAC_CTX_cleanup(ctx); }

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
  // going to check it using a SignedQuote in the first message (and
  // fail if no SignedQuote is provided or if it doesn't pass
  // verification)
  return 1;
}

static bool SetUpSSLCtx(const SSL_METHOD *method, const Keys &key,
                        bool require_peer_cert, ScopedSSLCtx *ctx) {
  string tls_cert = key.SigningX509CertificatePath();
  if (!ctx || !key.Signer() || !PathExists(FilePath(tls_cert))) {
    LOG(ERROR) << "Invalid SetUpSSLCTX parameters";
    return false;
  }
  tao::ScopedEvpPkey evp_key;
  if (!key.ExportSignerToOpenSSL(&evp_key)) {
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

  if (!SSL_CTX_use_certificate_chain_file(ctx->get(), tls_cert.c_str())) {
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

  // set session id context to a unique id to avoid session reuse problems

  // note that the output of CryptoFactory::Rand is static and doesn't need to
  // be cleaned up
  keyczar::RandImpl *rand = keyczar::CryptoFactory::Rand();
  if (!rand || !rand->Init()) {
    LOG(ERROR) << "Could not get a random number generator";
    return false;
  }

  // get an IV
  string sid;
  if (!rand->RandBytes(SessionIDSize, &sid)) {
    LOG(ERROR) << "Could not get enough random bytes for the session id";
    return false;
  }

  if (!SSL_CTX_set_session_id_context(
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

bool SetUpSSLServerCtx(const Keys &key, ScopedSSLCtx *ctx) {
  return SetUpSSLCtx(TLSv1_2_server_method(), key, true, ctx);
}

bool SetUpPermissiveSSLServerCtx(const Keys &key, ScopedSSLCtx *ctx) {
  return SetUpSSLCtx(TLSv1_2_server_method(), key, false, ctx);
}

bool SetUpSSLClientCtx(const Keys &key, ScopedSSLCtx *ctx) {
  return SetUpSSLCtx(TLSv1_2_client_method(), key, true, ctx);
}

bool ExtractACL(const string &signed_acls_file, const keyczar::Verifier *key,
                string *acl) {
  if (key == nullptr || acl == nullptr) {
    LOG(ERROR) << "Invalid ExtractACL parameters";
    return false;
  }

  // load the signature
  string sig;
  if (!ReadFileToString(signed_acls_file, &sig)) {
    LOG(ERROR) << "Could not open the signed acls file " << signed_acls_file;
    return false;
  }
  cloudproxy::SignedACL sacl;
  if (!sacl.ParseFromString(sig)) {
    LOG(ERROR) << "Could not parse the signed acl file " << signed_acls_file;
    return false;
  }

  if (!VerifySignature(*key, sacl.serialized_acls(),
                       CloudAuth::ACLSigningContext, sacl.signature())) {
    LOG(ERROR) << "ACL signature did not verify";
    return false;
  }

  acl->assign(sacl.serialized_acls());
  return true;
}

int ReceivePartialData(SSL *ssl, void *buffer, size_t filled_len,
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

bool ReceiveData(SSL *ssl, void *buffer, size_t buffer_len) {
  size_t filled_len = 0;
  while (filled_len != buffer_len) {
    int in_len = ReceivePartialData(ssl, buffer, filled_len, buffer_len);
    if (in_len == 0) return false;  // fail on truncated message
    if (in_len < 0) return false;   // fail on errors
    filled_len += in_len;
  }

  return true;
}

bool ReceiveData(SSL *ssl, string *data) {
  uint32_t net_len;
  if (!ReceiveData(ssl, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  }

  // convert from network byte order to get the length
  uint32_t len = ntohl(net_len);
  scoped_array<char> temp_data(new char[len]);

  if (!ReceiveData(ssl, temp_data.get(), static_cast<size_t>(len))) {
    LOG(ERROR) << "Could not get the data";
    return false;
  }

  data->assign(temp_data.get(), len);

  return true;
}

bool SendData(SSL *ssl, const void *buffer, size_t buffer_len) {
  if (ssl == nullptr || buffer == nullptr) {
    LOG(ERROR) << "Invalid SendData parameters";
    return false;
  }

  // SSL_write with length 0 is undefined, so catch that case here
  if (buffer_len > 0) {
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
    CHECK(static_cast<size_t>(out_len) == buffer_len);
  }

  return true;
}

bool SendData(SSL *ssl, const string &data) {
  size_t s = data.length();
  uint32_t net_len = htonl(s);

  // send the length to the client first
  if (!SendData(ssl, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not send the len";
    return false;
  }

  if (!SendData(ssl, data.data(), data.length())) {
    LOG(ERROR) << "Could not send the data";
    return false;
  }

  return true;
}

bool ReceiveStreamData(SSL *ssl, const string &path) {
  if (ssl == nullptr) {
    LOG(ERROR) << "Invalid ReceiveStreamData parameters";
    return false;
  }
  // open the file
  ScopedFile f(fopen(path.c_str(), "w"));
  if (nullptr == f.get()) {
    LOG(ERROR) << "Could not open the file " << path << " for writing";
    return false;
  }

  // first receive the length
  uint32_t net_len = 0;
  if (!ReceiveData(ssl, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  }

  // convert from network byte order to get the length
  uint32_t expected_len = ntohl(net_len);

  uint32_t total_len = 0;
  int len = READ_BUFFER_LEN;
  int out_len = 0;
  size_t bytes_written = 0;
  scoped_array<unsigned char> buf(new unsigned char[len]);
  while ((total_len < expected_len) &&
         (out_len = SSL_read(ssl, buf.get(), len)) != 0) {
    if (out_len < 0) {
      LOG(ERROR) << "Write failed after " << total_len << " bytes were written";
      return false;
    } else {
      // TODO(tmroeder): write to a temp file first so we only need to lock on
      // the final rename step
      bytes_written = fwrite(buf.get(), 1, out_len, f.get());

      // this cast is safe, since out_len is guaranteed to be non-negative
      if (bytes_written != static_cast<size_t>(out_len)) {
        LOG(ERROR) << "Could not write the received bytes to disk after "
                   << total_len << " bytes were written";
        return false;
      }

      total_len += bytes_written;
    }
  }

  return true;
}

bool SendStreamData(const string &path, size_t size, SSL *ssl) {
  if (ssl == nullptr) {
    LOG(ERROR) << "Invalid SendStreamData parameters";
    return false;
  }
  // open the file
  ScopedFile f(fopen(path.c_str(), "r"));
  if (nullptr == f.get()) {
    PLOG(ERROR) << "Could not open the file " << path << " for reading";
    return false;
  }

  // send the length of the file first
  uint32_t net_len = htonl(size);

  // send the length to the client
  if (!SendData(ssl, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not send the len";
    return false;
  }

  // stream the file bytes from disk to the network
  size_t total_bytes = 0;
  size_t len = READ_BUFFER_LEN;
  size_t bytes_read = 0;
  scoped_array<unsigned char> buf(new unsigned char[len]);
  while ((total_bytes < size) &&
         (bytes_read = fread(buf.get(), 1, len, f.get())) != 0) {
    int x = SSL_write(ssl, buf.get(), bytes_read);
    if (!OpenSSLSuccess() || x < 0) {
      LOG(ERROR) << "Network write operation failed";
      return false;
    }

    if (x == 0) {
      LOG(ERROR) << "Could not write the bytes to the network after "
                 << " total_bytes were written";
    }

    // this cast is safe, since x is guaranteed to be non-negative
    total_bytes += static_cast<size_t>(x);
  }

  if (total_bytes != size) {
    LOG(ERROR) << "Did not send all bytes to the server";
    return false;
  }

  return true;
}

bool InitEncryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes) {
  EVP_CIPHER_CTX_init(aes);
  if (!EVP_EncryptInit_ex(
          aes, EVP_aes_128_cbc(), nullptr,
          reinterpret_cast<const unsigned char *>(aes_key.get()->data()),
          reinterpret_cast<const unsigned char *>(iv.data()))) {
    LOG(ERROR) << "EVP_EncryptInit failed";
    return false;
  }

  return true;
}

bool InitDecryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes) {
  EVP_CIPHER_CTX_init(aes);
  if (!EVP_DecryptInit_ex(
          aes, EVP_aes_128_cbc(), nullptr,
          reinterpret_cast<const unsigned char *>(aes_key.get()->data()),
          reinterpret_cast<const unsigned char *>(iv.data()))) {
    LOG(ERROR) << "EVP_DecryptInit failed";
    return false;
  }
  return true;
}

bool InitHmacCtx(const keyczar::base::ScopedSafeString &hmac_key,
                 HMAC_CTX *hmac) {
  HMAC_Init(hmac, hmac_key.get()->data(), hmac_key.get()->length(),
            EVP_sha256());
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not initialize hmac context";
    return false;
  }

  return true;
}

bool DecryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac) {
  // add the encrypted bytes to the hmac computation before decrypting
  HMAC_Update(hmac, buffer, size);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not add the encrypted bytes to the hmac";
    return false;
  }

  EVP_DecryptUpdate(aes, out, out_size, buffer, size);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not decrypt block";
    return false;
  }

  return true;
}

bool EncryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac) {
  EVP_EncryptUpdate(aes, out, out_size, buffer, size);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not encrypt a block of data";
    return false;
  }

  // add the encrypted bytes to the hmac computation
  HMAC_Update(hmac, out, *out_size);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not add the encrypted bytes to the HMAC computation";
    return false;
  }

  return true;
}

// no need for the HMAC here, since the output is plaintext bytes
bool GetFinalDecryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes) {
  EVP_DecryptFinal_ex(aes, out, out_size);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not get the final decrypted bytes";
    return false;
  }

  return true;
}

bool GetFinalEncryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes, HMAC_CTX *hmac) {
  EVP_EncryptFinal_ex(aes, out, out_size);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not get the final encrypted bytes";
    return false;
  }

  if (*out_size > 0) {
    HMAC_Update(hmac, out, *out_size);
    if (!OpenSSLSuccess()) {
      LOG(ERROR) << "Could not add the final encrypted bytes to the hmac";
      return false;
    }
  }

  return true;
}

bool GetHmacOutput(unsigned char *out, unsigned int *out_size, HMAC_CTX *hmac) {
  HMAC_Final(hmac, out, out_size);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not compute the hmac";
    return false;
  }

  return true;
}

bool ReceiveAndEncryptStreamData(
    SSL *ssl, const string &path, const string &meta_path,
    const string &object_name, const keyczar::base::ScopedSafeString &aes_key,
    const keyczar::base::ScopedSafeString &hmac_key,
    const keyczar::Signer *main_key) {
  if (ssl == nullptr || main_key == nullptr) {
    LOG(ERROR) << "Invalid RecvAndEncryptStreamData parameters";
    return false;
  }

  ScopedFile f(fopen(path.c_str(), "w"));
  if (nullptr == f.get()) {
    LOG(ERROR) << "Could not open the file " << path << " for reading";
    return false;
  }

  // set up the cipher context and the hmac context
  EVP_CIPHER_CTX aes;
  HMAC_CTX hmac;

  // scoped values that clean up the EVP_CIPHER_CTX and HMAC_CTX before going
  // out of scope. These do not attempt to delete their pointers but instead
  // call cleanup functions on them.
  // TODO(kwalsh) semantics of these is nonsensical
  ScopedCipherCtx aes_cleanup(&aes);
  ScopedHmacCtx hmac_cleanup(&hmac);

  // note that the output of CryptoFactory::Rand is static and doesn't need to
  // be cleaned up
  keyczar::RandImpl *rand = keyczar::CryptoFactory::Rand();
  if (!rand || !rand->Init()) {
    LOG(ERROR) << "Could not get a random number generator";
    return false;
  }

  // get an IV
  string iv;
  if (!rand->RandBytes(IvSize, &iv)) {
    LOG(ERROR) << "Could not get enough random bytes for the IV";
    return false;
  }

  // set up the encryption and hmac contexts
  if (!InitEncryptEvpCipherCtx(aes_key, iv, &aes)) {
    LOG(ERROR) << "Could not initialize the cipher context from the key";
    return false;
  }

  if (!InitHmacCtx(hmac_key, &hmac)) {
    LOG(ERROR) << "Could not initialize the hmac context from the key";
    return false;
  }

  // first receive the length
  uint32_t net_len = 0;
  if (!ReceiveData(ssl, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  }

  // convert from network byte order to get the length
  uint32_t expected_len = ntohl(net_len);

  uint32_t total_len = 0;
  int len = READ_BUFFER_LEN;

  // this number comes from the OpenSSL documentation for EVP_EncryptUpdate
  int enc_len = len + AesBlockSize - 1;
  int out_enc_len = enc_len;
  int out_len = 0;
  size_t bytes_written = 0;
  scoped_array<unsigned char> buf(new unsigned char[len]);
  scoped_array<unsigned char> enc_buf(new unsigned char[enc_len]);
  while ((total_len < expected_len) &&
         (out_len = SSL_read(ssl, buf.get(), len)) != 0) {
    if (!OpenSSLSuccess() || out_len < 0) {
      LOG(ERROR) << "Write failed after " << total_len << " bytes were written";
      return false;
    } else {
      // TODO(tmroeder): write to a temp file first so we only need to lock on
      // the final rename step
      out_enc_len = enc_len;
      if (!EncryptBlock(buf.get(), out_len, enc_buf.get(), &out_enc_len, &aes,
                        &hmac)) {
        LOG(ERROR) << "Could not encrypt the bytes";
        return false;
      }

      // keep track of the total number of plaintext bytes in the file
      total_len += out_len;

      bytes_written = fwrite(enc_buf.get(), 1, out_enc_len, f.get());

      // this cast is safe, since out_len is guaranteed to be non-negative
      if (bytes_written != static_cast<size_t>(out_enc_len)) {
        PLOG(ERROR) << "Could not write the encrypted bytes to disk after "
                    << total_len << " bytes were written";
        return false;
      }
    }
  }
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "SSL connection failed";
    return false;
  }

  out_enc_len = enc_len;
  if (!GetFinalEncryptedBytes(enc_buf.get(), &out_enc_len, &aes, &hmac)) {
    LOG(ERROR) << "Could not get the final encrypted bytes";
    return false;
  }

  bytes_written = fwrite(enc_buf.get(), 1, out_enc_len, f.get());
  if (bytes_written != static_cast<size_t>(out_enc_len)) {
    PLOG(ERROR) << "Could not write the final encrypted bytes to disk";
    return false;
  }

  // get the hmac and write it to the end of the file
  unsigned int out_hmac_len = enc_len;
  if (!GetHmacOutput(enc_buf.get(), &out_hmac_len, &hmac)) {
    LOG(ERROR) << "Could not get the hmac output";
    return false;
  }

  // now write metadata to disk about this file, including the iv and hmac
  string computed_hmac(reinterpret_cast<char *>(enc_buf.get()), out_hmac_len);

  ObjectMetadata om;
  om.set_name(object_name);
  om.set_size(total_len);
  om.set_iv(iv);
  om.set_hmac(computed_hmac);

  string serialized_metadata;
  om.SerializeToString(&serialized_metadata);

  string metadata_hmac;
  if (!SignData(*main_key, serialized_metadata,
                FileServer::ObjectMetadataSigningContext, &metadata_hmac)) {
    LOG(ERROR) << "Could not compute an HMAC for the metadata for this file";
    return false;
  }

  HmacdObjectMetadata hom;
  hom.set_serialized_metadata(serialized_metadata);
  hom.set_hmac(metadata_hmac);

  string hom_serialized;
  if (!hom.SerializeToString(&hom_serialized)) {
    LOG(ERROR) << "Could not serialize HMAC meta data";
    return false;
  }
  if (!WriteStringToFile(meta_path, hom_serialized)) {
    LOG(ERROR) << "Could not write meta file " << meta_path;
    return false;
  }

  return true;
}

bool DecryptAndSendStreamData(const string &path, const string &meta_path,
                              const string &object_name, SSL *ssl,
                              const keyczar::base::ScopedSafeString &aes_key,
                              const keyczar::base::ScopedSafeString &hmac_key,
                              const keyczar::Verifier *main_key) {
  if (ssl == nullptr || main_key == nullptr) {
    LOG(ERROR) << "Invalid DecryptAndSendStreamData parameters";
    return false;
  }
  // open the file
  ScopedFile f(fopen(path.c_str(), "r"));
  if (nullptr == f.get()) {
    LOG(ERROR) << "Could not open the file " << path << " for reading";
    return false;
  }

  // recover the metadata
  string hom_serialized;
  if (!ReadFileToString(meta_path, &hom_serialized)) {
    LOG(ERROR) << "Could not open the meta file " << meta_path;
    return false;
  }

  HmacdObjectMetadata hom;
  if (!hom.ParseFromString(hom_serialized)) {
    LOG(ERROR) << "Could not parse meta file " << meta_path;
    return false;
  }

  // check the hmac
  if (!VerifySignature(*main_key, hom.serialized_metadata(),
                       FileServer::ObjectMetadataSigningContext, hom.hmac())) {
    LOG(ERROR) << "The object HMAC did not pass verification";
    return false;
  }

  ObjectMetadata om;
  if (!om.ParseFromString(hom.serialized_metadata())) {
    LOG(ERROR) << "Could not parse the serialized metadata";
    return false;
  }

  // check for renaming attacks: see if this name matches the name in the
  // metadata
  if (object_name.compare(om.name()) != 0) {
    LOG(ERROR) << "The name of the object is " << object_name << " but the"
               << " name in the metadata is " << om.name();
    return false;
  }

  // set up the cipher context and the hmac context
  EVP_CIPHER_CTX aes;
  HMAC_CTX hmac;

  // scoped values that clean up the EVP_CIPHER_CTX and HMAC_CTX before going
  // out of scope. These do not attempt to delete their pointers but instead
  // call cleanup functions on them.
  ScopedCipherCtx aes_cleanup(&aes);
  ScopedHmacCtx hmac_cleanup(&hmac);

  // note that the output of CryptoFactory::Rand is static and doesn't need to
  // be cleaned up
  keyczar::RandImpl *rand = keyczar::CryptoFactory::Rand();
  if (!rand || !rand->Init()) {
    LOG(ERROR) << "Could not get a random number generator";
    return false;
  }

  // set up the encryption and hmac contexts
  if (!InitDecryptEvpCipherCtx(aes_key, om.iv(), &aes)) {
    LOG(ERROR) << "Could not initialize the cipher context from the key";
    return false;
  }

  if (!InitHmacCtx(hmac_key, &hmac)) {
    LOG(ERROR) << "Could not initialize the hmac context from the key";
    return false;
  }

  // send the length of the file first
  uint32_t net_len = htonl(om.size());

  // send the length to the client
  if (!SendData(ssl, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not send the len";
    return false;
  }

  // stream the file bytes from disk to the network
  size_t total_bytes = 0;
  int len = READ_BUFFER_LEN;

  // according to the OpenSSL docs, the buffer passed to EVP_DecryptUpdate must
  // have enough space for input size + block size
  int dec_len = len + AesBlockSize;
  int out_dec_len = dec_len;
  size_t bytes_read = 0;
  scoped_array<unsigned char> buf(new unsigned char[len]);
  scoped_array<unsigned char> dec_buf(new unsigned char[dec_len]);
  while ((total_bytes < om.size()) &&
         (bytes_read = fread(buf.get(), 1, len, f.get())) != 0) {
    out_dec_len = dec_len;
    if (!DecryptBlock(buf.get(), bytes_read, dec_buf.get(), &out_dec_len, &aes,
                      &hmac)) {
      LOG(ERROR) << "Could not decrypt bytes from the file";
      return false;
    }

    if (out_dec_len > 0) {
      int x = SSL_write(ssl, dec_buf.get(), out_dec_len);
      if (!OpenSSLSuccess() || x < 0) {
        LOG(ERROR) << "Network write operation failed";
        return false;
      }

      if (x == 0) {
        LOG(ERROR) << "Could not write the bytes to the network after "
                   << " total_bytes were written";
        return false;
      }

      // this cast is safe, since x is guaranteed to be non-negative
      total_bytes += static_cast<size_t>(x);
    }
  }

  // handle the final block, if needed (e.g., for AES CBC)
  out_dec_len = dec_len;
  if (!GetFinalDecryptedBytes(dec_buf.get(), &out_dec_len, &aes)) {
    LOG(ERROR) << "Could not get the final decrypted bytes from the file";
    return false;
  }

  if (out_dec_len > 0) {
    // send it to the client
    int x = SSL_write(ssl, dec_buf.get(), out_dec_len);
    if (!OpenSSLSuccess() || x < 0) {
      LOG(ERROR) << "Final network operation failed";
      return false;
    }

    total_bytes += out_dec_len;
  }

  if (total_bytes != om.size()) {
    LOG(ERROR) << "Did not send all bytes to the server";
    return false;
  }

  // TODO(tmroeder): this style of encryption is the same as used in the
  // original CloudProxy, but it leaks far too much information: in particular,
  // it sends out all the bytes of the decrypted file before checking the HMAC,
  // which means that the authenticated encryption is not worth much. Instead,
  // we should either check the HMAC first (more expensive), or store the file
  // in encrypted chunks that each have an hmac (and a block number in their
  // metadata).

  // check the HMAC value
  unsigned int out_hmac_len = static_cast<unsigned int>(dec_len);
  if (!GetHmacOutput(dec_buf.get(), &out_hmac_len, &hmac)) {
    LOG(ERROR) << "Could not get the HMAC value";
    return false;
  }

  string computed_hmac(reinterpret_cast<char *>(dec_buf.get()), out_hmac_len);
  if (om.hmac().compare(computed_hmac) != 0) {
    LOG(ERROR) << "The computed file HMAC did not match the stored hmac";
    return false;
  }

  return true;
}
}  // namespace cloudproxy
