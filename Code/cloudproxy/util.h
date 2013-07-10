#ifndef CLOUDPROXY_UTIL_H_
#define CLOUDPROXY_UTIL_H_

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/openssl/util.h>

#include <string>

using std::string;

namespace cloudproxy {
// taken from a private definition in keyczar/openssl/aes.h
typedef scoped_ptr_malloc<
	EVP_CIPHER_CTX, keyczar::openssl::OSSLDestroyer<EVP_CIPHER_CTX,
	EVP_CIPHER_CTX_free> > ScopedCipherCtx;
typedef scoped_ptr_malloc<
	SSL_CTX, keyczar::openssl::OSSLDestroyer<SSL_CTX,
	SSL_CTX_free> > ScopedSSLCtx;

bool SetUpSSLCTX(SSL_CTX *ctx, const string &public_policy_key,
		const string &cert, const string &key);

bool ExtractACL(const string &serialized_signed_acls, keyczar::Keyczar *key,
		 string *acls);

bool VerifySignature(const string &data, const string &signature,
		keyczar::Keyczar *key);

bool CreateRSAPublicKeyset(const string &key, const string &metadata,
		keyczar::Keyset *keyset);
}
#endif // CLOUDPROXY_UTIL_H_
