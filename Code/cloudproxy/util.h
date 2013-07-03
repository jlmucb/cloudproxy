#ifndef CLOUDPROXY_UTIL_H_
#define CLOUDPROXY_UTIL_H_

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/openssl/util.h>

namespace cloudproxy {
// taken from a private definition in keyczar/openssl/aes.h
typedef scoped_ptr_malloc<
	EVP_CIPHER_CTX, keyczar::openssl::OSSLDestroyer<EVP_CIPHER_CTX,
	EVP_CIPHER_CTX_free> > ScopedCipherCtx;
typedef scoped_ptr_malloc<
	SSL_CTX, keyczar::openssl::OSSLDestroyer<SSL_CTX,
	SSL_CTX_free> > ScopedSSLCtx;
}
#endif // CLOUDPROXY_UTIL_H_
