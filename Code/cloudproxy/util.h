#ifndef CLOUDPROXY_UTIL_H_
#define CLOUDPROXY_UTIL_H_

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/openssl/util.h>

#include <stdio.h>
#include <string>

using std::string;

namespace cloudproxy {

//struct FileDestroyer {
//  void operator()(FILE *ptr) const {
//    if (ptr) {
//      fclose(ptr);
//    }
//  }
//};

// taken from a private definition in keyczar/openssl/aes.h
typedef scoped_ptr_malloc<
	EVP_CIPHER_CTX, keyczar::openssl::OSSLDestroyer<EVP_CIPHER_CTX,
	EVP_CIPHER_CTX_free> > ScopedCipherCtx;
typedef scoped_ptr_malloc<
	SSL_CTX, keyczar::openssl::OSSLDestroyer<SSL_CTX,
	SSL_CTX_free> > ScopedSSLCtx;

//typedef scoped_ptr_malloc<FILE, FileDestroyer> ScopedFile;

int PasswordCallback(char *buf, int size, int rwflag, void *password);

bool SetUpSSLCTX(SSL_CTX *ctx, const string &public_policy_key,
		const string &cert, const string &key, const string &password);

bool ExtractACL(const string &serialized_signed_acls, keyczar::Keyczar *key,
		 string *acls);

bool SignData(const string &data, string *signature,
		keyczar::Keyczar *key);
bool VerifySignature(const string &data, const string &signature,
		keyczar::Keyczar *key);

bool CopyRSAPublicKeyset(keyczar::Keyczar *public_key,
               keyczar::Keyset *keyset);

bool CreateRSAPublicKeyset(const string &key, const string &metadata,
		keyczar::Keyset *keyset);

// methods to send a receive data on a TLS BIO
bool ReceiveData(BIO *bio, void *buffer, size_t buffer_len);
bool ReceiveData(BIO *bio, string *data);
bool SendData(BIO *bio, const void *buffer, size_t buffer_len);
bool SendData(BIO *bio, const string &data);

// send or receive files on a TLS BIO
bool ReceiveStreamData(BIO *bio, const string &path);
bool SendStreamData(const string &path, size_t size, BIO *bio);

}

#endif // CLOUDPROXY_UTIL_H_
