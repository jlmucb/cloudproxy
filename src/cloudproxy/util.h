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

#include <glog/logging.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/openssl/util.h>

#include "tao/tao.h"
#include "tao/keyczar_public_key.pb.h"

#include <stdio.h>
#include <string>

using std::string;

namespace cloudproxy {

struct FileDestroyer {
  void operator()(FILE *ptr) const {
    if (ptr) {
      fclose(ptr);
    }
  }
};

static const int AesKeySize = 16;
static const int AesBlockSize = 16;
static const int IvSize = AesBlockSize;

// for now, we are using 128-bit HMAC keys
static const int HmacKeySize = 16;

// functions that ignore the return value from cleanup
void ecleanup(EVP_CIPHER_CTX *ctx);
void hcleanup(HMAC_CTX *ctx);

// taken from a private definition in keyczar/openssl/aes.h
typedef scoped_ptr_malloc<
    EVP_CIPHER_CTX, keyczar::openssl::OSSLDestroyer<EVP_CIPHER_CTX, ecleanup> >
    ScopedCipherCtx;
typedef scoped_ptr_malloc<HMAC_CTX, keyczar::openssl::OSSLDestroyer<
                                        HMAC_CTX, hcleanup> > ScopedHmacCtx;
typedef scoped_ptr_malloc<SSL_CTX, keyczar::openssl::OSSLDestroyer<
                                       SSL_CTX, SSL_CTX_free> > ScopedSSLCtx;
typedef scoped_ptr_malloc<
    X509, keyczar::openssl::OSSLDestroyer<X509, X509_free> > ScopedX509Ctx;

typedef scoped_ptr_malloc<
    EVP_PKEY, keyczar::openssl::OSSLDestroyer<EVP_PKEY, EVP_PKEY_free> >
    ScopedEvpPkey;

typedef scoped_ptr_malloc<FILE, FileDestroyer> ScopedFile;

int PasswordCallback(char *buf, int size, int rwflag, void *password);

bool SetUpSSLCTX(SSL_CTX *ctx, const string &public_policy_key,
                 const string &cert, const string &key, const string &password);

bool ExtractACL(const string &serialized_signed_acls, keyczar::Keyczar *key,
                string *acls);

bool SignData(const string &data, string *signature, keyczar::Keyczar *key);
bool VerifySignature(const string &data, const string &signature,
                     keyczar::Keyczar *key);

bool CopyPublicKeyset(const keyczar::Keyczar &public_key, keyczar::Keyset **keyset);
bool DeserializePublicKey(const tao::KeyczarPublicKey &kpk,
			  keyczar::Keyset **keyset);
bool SerializePublicKey(const keyczar::Keyczar &key, tao::KeyczarPublicKey *kpk);

// methods to send a receive data on a TLS BIO
bool ReceiveData(BIO *bio, void *buffer, size_t buffer_len);
bool ReceiveData(BIO *bio, string *data);
bool SendData(BIO *bio, const void *buffer, size_t buffer_len);
bool SendData(BIO *bio, const string &data);

// send or receive files on a TLS BIO
bool ReceiveStreamData(BIO *bio, const string &path);
bool SendStreamData(const string &path, size_t size, BIO *bio);

bool ReceiveAndEncryptStreamData(BIO *bio, const string &path,
                                 const string &meta_path,
                                 const string &object_name,
                                 const keyczar::base::ScopedSafeString &key,
                                 const keyczar::base::ScopedSafeString &hmac,
                                 keyczar::Keyczar *main_key);

bool DecryptAndSendStreamData(const string &path, const string &meta_path,
                              const string &object_name, BIO *bio,
                              const keyczar::base::ScopedSafeString &key,
                              const keyczar::base::ScopedSafeString &hmac,
                              keyczar::Keyczar *main_key);

// crypto functions
bool DeriveKeys(keyczar::Keyczar *main_key,
                keyczar::base::ScopedSafeString *enc_key,
                keyczar::base::ScopedSafeString *hmac_key);
bool InitEncryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes);
bool InitDecryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes);
bool InitHmacCtx(const keyczar::base::ScopedSafeString &hmac_key,
                 HMAC_CTX *hmac);
bool DecryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac);
bool EncryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac);
bool GetFinalDecryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes);
bool GetFinalEncryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes, HMAC_CTX *hmac);
bool GetHmacOutput(char *out, unsigned int *out_size, HMAC_CTX *hmac);

bool SerializeX509(X509 *x509, string *serialized_x509);

bool CreateECDSAKey(const string &private_path, const string &public_path,
                    const string &secret, const string &country_code,
                    const string &org_code, const string &cn);
bool SealOrUnsealSecret(const tao::Tao &t, const string &sealed_path, string *secret);
}

#endif  // CLOUDPROXY_UTIL_H_
