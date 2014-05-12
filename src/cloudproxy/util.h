//  File: util.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Useful functions for CloudProxy
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

#ifndef CLOUDPROXY_UTIL_H_
#define CLOUDPROXY_UTIL_H_

#include <stdio.h>

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/openssl/util.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

using std::string;

namespace keyczar {
class Signer;
class Verifier;
}  // namespace keyczar

namespace tao {
class Keys;
}

namespace cloudproxy {

static const int AesKeySize = 16;
static const int AesBlockSize = 16;
static const int IvSize = AesBlockSize;

// For now, we are using 128-bit HMAC keys.
static const int HmacKeySize = 16;

/// Clean up an OpenSSL EVP CTX.
/// @param ctx The context to clean up.
void ecleanup(EVP_CIPHER_CTX *ctx);

/// Clean up an OpenSSL HMAC CTX.
/// @param ctx The context to clean up.
void hcleanup(HMAC_CTX *ctx);

void ssl_cleanup(SSL *ssl);

// Taken from a private definition in keyczar/openssl/aes.h
// A smart pointer wrapping an OpenSSL EVP_CIPHER_CTX.
typedef scoped_ptr_malloc<
    EVP_CIPHER_CTX, keyczar::openssl::OSSLDestroyer<EVP_CIPHER_CTX, ecleanup> >
    ScopedCipherCtx;

// A smart pointer wrapping an OpenSSL HMAC_CTX.
typedef scoped_ptr_malloc<HMAC_CTX, keyczar::openssl::OSSLDestroyer<
                                        HMAC_CTX, hcleanup> > ScopedHmacCtx;

// A smart pointer wrapping an OpenSSL SSL_CTX.
typedef scoped_ptr_malloc<SSL_CTX, keyczar::openssl::OSSLDestroyer<
                                       SSL_CTX, SSL_CTX_free> > ScopedSSLCtx;

// A smart pointer wrapping an SSL object.
typedef scoped_ptr_malloc<
    SSL, keyczar::openssl::OSSLDestroyer<SSL, ssl_cleanup> > ScopedSSL;

/// Prepare an SSL_CTX for a server to accepts connections from clients.
/// Peer certificates will be required.
/// @param key The private signing key and x509 certificate to use.
/// @param ctx The OpenSSL context to prepare.
bool SetUpSSLServerCtx(const tao::Keys &key, ScopedSSLCtx *ctx);

/// Prepare an SSL_CTX for a server to accepts connections from clients.
/// Peer certificates will not be required.
/// @param key The private signing key and x509 certificate to use.
/// @param ctx The OpenSSL context to prepare.
bool SetUpPermissiveSSLServerCtx(const tao::Keys &key, ScopedSSLCtx *ctx);

/// Prepare an SSL_CTX for a client to connect to a server.
/// @param key The private signing key and x509 certificate to use.
/// @param ctx The OpenSSL context to prepare.
bool SetUpSSLClientCtx(const tao::Keys &key, ScopedSSLCtx *ctx);

/// Check the signature on a SignedACL file and get a serialized ACL.
/// @param serialized_signed_acls A path to a file containing a serialized
/// SignedACL.
/// @param key The key to use to verify the signature on the SignedACL.
/// @param[out] acls The extract ACL.
/// TODO(kwalsh) Should this be a static method of CloudAuth?
/// TODO(kwalsh) Use const reference for key
bool ExtractACL(const string &serialized_signed_acls,
                const keyczar::Verifier *key, string *acls);

// TODO(kwalsh) Consier merge with similarly-named functions in tao/util.cc?

/// Receive partial data from an OpenSSL SSL. This will read as
/// many bytes as possible into buffer[i], where filled_len <= i < buffer_len,
/// and it returns the number of bytes read, or 0 if end of stream, or negative
/// on error.
/// @param ssl The SSL to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param filed_len The length of buffer that is already filled.
/// @param buffer_len The total length of buffer.
int ReceivePartialData(SSL *ssl, void *buffer, size_t filled_len,
                       size_t buffer_len);

/// Receive data from an OpenSSL SSL.
/// @param ssl The SSL to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param buffer_len The length of buffer.
bool ReceiveData(SSL *ssl, void *buffer, size_t buffer_len);

/// Receive data from an OpenSSL SSL.
/// @param ssl The SSL to use to receive the data.
/// @param[out] data The object to receive the data.
bool ReceiveData(SSL *ssl, string *data);

/// Send data on an OpenSSL SSL.
/// @param ssl The SSL to use to send the data.
/// @param buffer The buffer of data to send.
/// @param buffer_len The length of the data to send.
bool SendData(SSL *ssl, const void *buffer, size_t buffer_len);

/// Send data on an OpenSSL SSL.
/// @param ssl The SSL to use to send the data.
/// @param data The data to send.
bool SendData(SSL *ssl, const string &data);

/// Receive a file on an OpenSSL SSL.
/// @param ssl The SSL to use to receive the data.
/// @param path The path of the file to write with the received data.
bool ReceiveStreamData(SSL *ssl, const string &path);

/// Send a file on an OpenSSL SSL.
/// @param path The path to the file to send.
/// @param size The amount of data to send.
/// @param ssl The OpenSSL SSL to use to send the data.
bool SendStreamData(const string &path, size_t size, SSL *ssl);

/// Receive a file, encrypt it, and add integrity protection.
/// @param ssl The OpenSSL SSL to use to receive the data.
/// @param path The path of the file to write with the data.
/// @param meta_path The path of the file to write with metadata about the file,
/// including the integrity check.
/// @param object_name The name of the object to receive.
/// @param key The key to use for encryption.
/// @param hmac The HMAC key to use for integrity protection.
/// @param main_key The keyczar key to use for the metadata file.
bool ReceiveAndEncryptStreamData(SSL *ssl, const string &path,
                                 const string &meta_path,
                                 const string &object_name,
                                 const keyczar::base::ScopedSafeString &key,
                                 const keyczar::base::ScopedSafeString &hmac,
                                 const keyczar::Signer *main_key);

/// Check the integrity of a file, decrypt it, and send it on the network.
/// @param path The path of the file to send.
/// @param meta_path The path of the metadata associated with the file.
/// @param object_name The object name associated with the file.
/// @param ssl The OpenSSL SSL to use for communication.
/// @param key The key to use for decryption.
/// @param hmac The HMAC key to use for checking file integrity.
/// @param main_key The keyczar key to use for the metadata file.
bool DecryptAndSendStreamData(const string &path, const string &meta_path,
                              const string &object_name, SSL *ssl,
                              const keyczar::base::ScopedSafeString &key,
                              const keyczar::base::ScopedSafeString &hmac,
                              const keyczar::Verifier *main_key);

/// Set up an EVP_CIPHER_CTX with an IV and a key.
/// @param aes_key The encryption key to use.
/// @param iv The IV to use for encryption.
/// @param[in,out] aes The EVP_CIPHER_CTX to initialize.
bool InitEncryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes);

/// Set up an EVP_CIPHER_CTX for decryption with an IV and a key.
/// @param aes_key The decryption key to use.
/// @param iv The IV to use.
/// @param[in,out] aes The EVP_CIPHER_CTX to initialize.
bool InitDecryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes);

/// Set up an HMAC_CTX for integrity verification.
/// @param hmac_key The HMAC key to use.
/// @param[in,out] hmac The HMAC_CTX to initialize.
bool InitHmacCtx(const keyczar::base::ScopedSafeString &hmac_key,
                 HMAC_CTX *hmac);

/// Decrypt a single block in a decryption stream.
/// @param buffer The bytes to decrypt.
/// @param size The number of bytes to decrypt.
/// @param[out] out The decrypted bytes.
/// @param[in,out] out_size On input, this is the length of the out buffer. It
/// is replaced with the total count of decrypted bytes.
/// @param aes The decryption context.
/// @param hmac The HMAC context.
bool DecryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac);

/// Encrypt a single block in an encryption stream.
/// @param buffer The bytes to encrypt.
/// @param size The length of the bytes to encrypt.
/// @param[out] out The encrypted bytes.
/// @param[in,out] out_size On input, this is the length of the out buffer. It
/// is replaced with the total count of encrypted bytes.
/// @param aes The encryption context.
/// @param hmac The HMAC context.
bool EncryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac);

/// Perform final decryption operations and return any extra data that results
/// from these operations.
/// @param[out] out The decrypted bytes.
/// @param[in,out] out_size The length of the out buffer, then the total number
/// of decrypted bytes in out.
/// @param aes The decryption context.
bool GetFinalDecryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes);

/// Perform final encryption operations and return any extra data that results
/// from these operations.
/// @param[out] out The encrypted bytes.
/// @param[in,out] out_size The length of the out buffer, then the total number
/// of encrypted bytes in out.
/// @param aes The encryption context.
/// @param hmac The HMAC context.
bool GetFinalEncryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes, HMAC_CTX *hmac);

/// Get the final output from an HMAC being computed over a stream.
/// @param[out] out The hmac value.
/// @param[in,out] out_size The size of the out buffer, then the total number of
/// bytes written for the HMAC.
/// @param hmac The HMAC context to use for the operation.
bool GetHmacOutput(char *out, unsigned int *out_size, HMAC_CTX *hmac);

}  // namespace cloudproxy

#endif  // CLOUDPROXY_UTIL_H_
