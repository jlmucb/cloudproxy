//  File: util.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of useful functions for CloudProxy
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#include "cloudproxy/util.h"

#include <fstream>
#include <sstream>

#include <arpa/inet.h>

#include <keyczar/base/json_reader.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyset_metadata.h>
#include <keyczar/keyset.h>
#include <keyczar/keyczar.h>
#include <keyczar/rsa_impl.h>
#include <keyczar/rsa_public_key.h>
#include <keyczar/base/file_util.h>

#include <glog/logging.h>

#include "cloudproxy/cloudproxy.pb.h"

using keyczar::base::PathExists;
using keyczar::base::ScopedSafeString;

using tao::Tao;

using std::ifstream;
using std::ios;
using std::ofstream;
using std::stringstream;

#define READ_BUFFER_LEN 16384

namespace cloudproxy {

void ecleanup(EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_cleanup(ctx); }

void hcleanup(HMAC_CTX *ctx) { HMAC_CTX_cleanup(ctx); }

// TODO(tmroeder): change this callback will change to get the
// password from the Tao/TPM
int PasswordCallback(char *buf, int size, int rwflag, void *password) {
  strncpy(buf, (char *)(password), size);
  buf[size - 1] = '\0';
  return (strlen(buf));
}

static int AlwaysAcceptCert(int preverify_ok, X509_STORE_CTX *ctx) {
  // we always let the X.509 cert pass verification because we're
  // going to check it using a SignedQuote in the first message (and
  // fail if no SignedQuote is provided or if it doesn't pass
  // verification
  return 1;
}

bool SetUpSSLCTX(SSL_CTX *ctx, const string &public_policy_key,
                 const string &cert, const string &key,
                 const string &password) {
  CHECK(ctx) << "null ctx";

  // set up the TLS connection with the list of acceptable ciphers
  CHECK(SSL_CTX_set_cipher_list(ctx, "AES128-SHA256"))
      << "Could not set up a cipher list on the TLS context";

  // turn off compression (?)
  CHECK(SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION))
      << "Could not turn off compression on the TLS connection";

  CHECK(SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM))
      << "Could not load the certificate for this connection";

  // set up the password callback and the password itself
  SSL_CTX_set_default_passwd_cb(ctx, PasswordCallback);
  SSL_CTX_set_default_passwd_cb_userdata(ctx,
                                         const_cast<char *>(password.c_str()));

  CHECK(SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM))
      << "Could not load the private key for this connection";

  // set up verification to insist on getting a certificate from the peer
  int verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  SSL_CTX_set_verify(ctx, verify_mode, AlwaysAcceptCert);

  // set up the server to use ECDH for key agreement using ANSI X9.62
  // Prime 256 V1
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  CHECK_NOTNULL(ecdh);
  CHECK(SSL_CTX_set_tmp_ecdh(ctx, ecdh)) << "Could not set up ECDH";

  return true;
}

bool ExtractACL(const string &signed_acls_file, keyczar::Keyczar *key,
                string *acl) {

  CHECK(key) << "null key";
  CHECK(acl) << "null acl";

  // load the signature
  ifstream sig(signed_acls_file.c_str());
  stringstream sig_buf;
  sig_buf << sig.rdbuf();

  cloudproxy::SignedACL sacl;
  sacl.ParseFromString(sig_buf.str());

  if (!VerifySignature(sacl.serialized_acls(), sacl.signature(), key)) {
    return false;
  }

  acl->assign(sacl.serialized_acls());
  return true;
}

bool VerifySignature(const string &data, const string &signature,
                     keyczar::Keyczar *key) {
  if (!key->Verify(data, signature)) {
    LOG(ERROR) << "Verify failed";
    return false;
  }

  return true;
}

bool CopyRSAPublicKeyset(keyczar::Keyczar *public_key,
                         keyczar::Keyset *keyset) {
  CHECK(public_key) << "null public_key";
  CHECK(keyset) << "null keyset";
  const keyczar::Keyset *public_keyset = public_key->keyset();
  CHECK(public_keyset) << "null public keyset";
  const keyczar::Key *k1 = public_keyset->GetKey(1);
  CHECK(k1) << "Null key 1";
  scoped_ptr<Value> key_value(k1->GetValue());
  scoped_ptr<Value> meta_value(public_keyset->metadata()->GetValue(true));

  keyset->set_metadata(
      keyczar::KeysetMetadata::CreateFromValue(meta_value.get()));

  // TODO(tmroeder): read the number of the primary key from the public_key
  // metadata
  if (!keyset->AddKey(keyczar::RSAPublicKey::CreateFromValue(*key_value), 1)) {
    LOG(ERROR) << "Could not add an RSA Public Key";
    return false;
  }

  return true;
}

bool CreateRSAPublicKeyset(const string &key, const string &metadata,
                           keyczar::Keyset *keyset) {
  CHECK(keyset) << "null keyset";

  // create KeyMetadata from the metadata string
  scoped_ptr<Value> meta_value(
      keyczar::base::JSONReader::Read(metadata, false));
  keyset->set_metadata(
      keyczar::KeysetMetadata::CreateFromValue(meta_value.get()));

  // create an RSA public Key from the key JSON string
  scoped_ptr<Value> key_value(keyczar::base::JSONReader::Read(key, false));
  // Note: it is always key version 1, since this is the first key we are
  // adding.
  // TODO(tmroeder): Or do I need to read this information from the metadata?
  // Look in the file.
  if (!keyset->AddKey(keyczar::RSAPublicKey::CreateFromValue(*key_value), 1)) {
    LOG(ERROR) << "Could not add an RSA Public Key";
    return false;
  }

  return true;
}

bool ReceiveData(BIO *bio, void *buffer, size_t buffer_len) {
  CHECK(bio) << "null bio";
  CHECK(buffer) << "null buffer";

  // get the data, retrying until we get it.
  // Note: this assumes that BIO_read doesn't get partial data from the SSL
  // connection but instead blocks until it has enough data.
  int x = 0;
  while ((x = BIO_read(bio, buffer, buffer_len)) != buffer_len) {
    if (x == 0) return false;
    if ((x < 0) && !BIO_should_retry(bio)) return false;
  }

  return true;
}

bool ReceiveData(BIO *bio, string *data) {
  CHECK(bio) << "null bio";
  CHECK(data) << "null data";

  uint32_t net_len;
  if (!ReceiveData(bio, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  }

  // convert from network byte order to get the length
  uint32_t len = ntohl(net_len);
  scoped_array<char> temp_data(new char[len]);

  if (!ReceiveData(bio, temp_data.get(), len)) {
    LOG(ERROR) << "Could not get the data";
    return false;
  }

  data->assign(temp_data.get(), len);

  return true;
}

bool SendData(BIO *bio, const void *buffer, size_t buffer_len) {
  int x = 0;
  while ((x = BIO_write(bio, buffer, buffer_len)) != buffer_len) {
    if (x == 0) return false;
    if ((x < 0) && !BIO_should_retry(bio)) return false;
  }

  return true;
}

bool SendData(BIO *bio, const string &data) {
  size_t s = data.length();
  uint32_t net_len = htonl(s);

  // send the length to the client first
  if (!SendData(bio, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not send the len";
    return false;
  }

  if (!SendData(bio, data.data(), data.length())) {
    LOG(ERROR) << "Could not send the data";
    return false;
  }

  return true;
}

bool SignData(const string &data, string *signature, keyczar::Keyczar *key) {
  if (!key->Sign(data, signature)) {
    LOG(ERROR) << "Could not sign the data";
    return false;
  }

  return true;
}

bool ReceiveStreamData(BIO *bio, const string &path) {
  // open the file
  CHECK(bio) << "null bio";

  ScopedFile f(fopen(path.c_str(), "w"));
  if (nullptr == f.get()) {
    LOG(ERROR) << "Could not open the file " << path << " for writing";
    return false;
  }

  // first receive the length
  uint32_t net_len = 0;
  if (!ReceiveData(bio, &net_len, sizeof(net_len))) {
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
         (out_len = BIO_read(bio, buf.get(), len)) != 0) {
    if (out_len < 0) {
      if (!BIO_should_retry(bio)) {
        LOG(ERROR) << "Write failed after " << total_len
                   << " bytes were written";
        return false;
      }
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

bool SendStreamData(const string &path, size_t size, BIO *bio) {
  CHECK(bio) << "null bio";

  // open the file
  CHECK(bio) << "null bio";
  ScopedFile f(fopen(path.c_str(), "r"));
  if (nullptr == f.get()) {
    LOG(ERROR) << "Could not open the file " << path << " for reading";
    return false;
  }

  // send the length of the file first
  uint32_t net_len = htonl(size);

  // send the length to the client
  if (!SendData(bio, &net_len, sizeof(net_len))) {
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
    int x = 0;
    while ((x = BIO_write(bio, buf.get(), bytes_read)) < 0) {
      if (!BIO_should_retry(bio)) {
        LOG(ERROR) << "Network write operation failed";
        return false;
      }
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

bool DeriveKeys(keyczar::Keyczar *main_key,
                keyczar::base::ScopedSafeString *aes_key,
                keyczar::base::ScopedSafeString *hmac_key) {
  CHECK(main_key) << "null main_key";
  CHECK(aes_key->get()) << "null aes_key";
  CHECK(hmac_key->get()) << "null hmac_key";

  // derive the keys
  string aes_context = "1 || encryption";
  string hmac_context = "1 || hmac";

  keyczar::base::ScopedSafeString temp_aes_key(new string());
  keyczar::base::ScopedSafeString temp_hmac_key(new string());

  CHECK(main_key->Sign(aes_context, temp_aes_key.get()))
      << "Could not derive the aes key";
  CHECK(main_key->Sign(hmac_context, temp_hmac_key.get()))
      << "Could not derive the hmac key";

  // skip the header to get the bytes
  size_t header_size = keyczar::Key::GetHeaderSize();
  CHECK_LE(AesKeySize + header_size, temp_aes_key.get()->size())
      << "There were not enough bytes to get the aes key";
  CHECK_LE(HmacKeySize + header_size, temp_hmac_key.get()->size())
      << "There were not enough bytes to get the hmac key";

  aes_key->get()->assign(temp_aes_key.get()->data() + header_size, AesKeySize);
  hmac_key->get()
      ->assign(temp_hmac_key.get()->data() + header_size, HmacKeySize);

  return true;
}

bool InitEncryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes) {
  EVP_CIPHER_CTX_init(aes);
  EVP_EncryptInit_ex(
      aes, EVP_aes_128_cbc(), NULL,
      reinterpret_cast<const unsigned char *>(aes_key.get()->data()),
      reinterpret_cast<const unsigned char *>(iv.data()));

  return true;
}

bool InitDecryptEvpCipherCtx(const keyczar::base::ScopedSafeString &aes_key,
                             const string &iv, EVP_CIPHER_CTX *aes) {
  EVP_CIPHER_CTX_init(aes);
  EVP_DecryptInit_ex(
      aes, EVP_aes_128_cbc(), NULL,
      reinterpret_cast<const unsigned char *>(aes_key.get()->data()),
      reinterpret_cast<const unsigned char *>(iv.data()));

  return true;
}

bool InitHmacCtx(const keyczar::base::ScopedSafeString &hmac_key,
                 HMAC_CTX *hmac) {
  HMAC_Init(hmac, hmac_key.get()->data(), hmac_key.get()->length(),
            EVP_sha256());

  return true;
}

bool DecryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac) {
  // add the encrypted bytes to the hmac computation before decrypting
  if (!HMAC_Update(hmac, buffer, size)) {
    LOG(ERROR) << "Could not add the encrypted bytes to the hmac";
    return false;
  }

  if (!EVP_DecryptUpdate(aes, out, out_size, buffer, size)) {
    LOG(ERROR) << "Could not decrypt block";
    return false;
  }

  return true;
}

bool EncryptBlock(const unsigned char *buffer, int size, unsigned char *out,
                  int *out_size, EVP_CIPHER_CTX *aes, HMAC_CTX *hmac) {
  if (!EVP_EncryptUpdate(aes, out, out_size, buffer, size)) {
    LOG(ERROR) << "Could not encrypt a block of data";
    return false;
  }

  // add the encrypted bytes to the hmac computation
  if (!HMAC_Update(hmac, out, *out_size)) {
    LOG(ERROR) << "Could not add the encrypted bytes to the HMAC computation";
    return false;
  }

  return true;
}

// no need for the HMAC here, since the output is plaintext bytes
bool GetFinalDecryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes) {
  if (!EVP_DecryptFinal_ex(aes, out, out_size)) {
    LOG(ERROR) << "Could not get the final decrypted bytes";
    return false;
  }

  return true;
}

bool GetFinalEncryptedBytes(unsigned char *out, int *out_size,
                            EVP_CIPHER_CTX *aes, HMAC_CTX *hmac) {
  if (!EVP_EncryptFinal_ex(aes, out, out_size)) {
    LOG(ERROR) << "Could not get the final encrypted bytes";
    return false;
  }

  if (*out_size > 0) {
    if (!HMAC_Update(hmac, out, *out_size)) {
      LOG(ERROR) << "Could not add the final encrypted bytes to the hmac";
      return false;
    }
  }

  return true;
}

bool GetHmacOutput(unsigned char *out, unsigned int *out_size, HMAC_CTX *hmac) {
  if (!HMAC_Final(hmac, out, out_size)) {
    LOG(ERROR) << "Could not compute the hmac";
    return false;
  }

  return true;
}

bool ReceiveAndEncryptStreamData(
    BIO *bio, const string &path, const string &meta_path,
    const string &object_name, const keyczar::base::ScopedSafeString &aes_key,
    const keyczar::base::ScopedSafeString &hmac_key,
    keyczar::Keyczar *main_key) {
  CHECK(bio) << "null bio";
  CHECK(main_key) << "null main_key";

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
  if (!ReceiveData(bio, &net_len, sizeof(net_len))) {
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
         (out_len = BIO_read(bio, buf.get(), len)) != 0) {
    if (out_len < 0) {
      if (!BIO_should_retry(bio)) {
        LOG(ERROR) << "Write failed after " << total_len
                   << " bytes were written";
        return false;
      }
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
        LOG(ERROR) << "Could not write the encrypted bytes to disk after "
                   << total_len << " bytes were written";
        return false;
      }
    }
  }

  out_enc_len = enc_len;
  if (!GetFinalEncryptedBytes(enc_buf.get(), &out_enc_len, &aes, &hmac)) {
    LOG(ERROR) << "Could not get the final encrypted bytes";
    return false;
  }

  bytes_written = fwrite(enc_buf.get(), 1, out_enc_len, f.get());
  if (bytes_written != static_cast<size_t>(out_enc_len)) {
    LOG(ERROR) << "Could not write the final encrypted bytes to disk";
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
  if (!main_key->Sign(serialized_metadata, &metadata_hmac)) {
    LOG(ERROR) << "Could not compute an HMAC for the metadata for this file";
    return false;
  }

  HmacdObjectMetadata hom;
  hom.set_serialized_metadata(serialized_metadata);
  hom.set_hmac(metadata_hmac);

  ofstream meta(meta_path.c_str(), ofstream::out);
  hom.SerializeToOstream(&meta);

  return true;
}

bool DecryptAndSendStreamData(const string &path, const string &meta_path,
                              const string &object_name, BIO *bio,
                              const keyczar::base::ScopedSafeString &aes_key,
                              const keyczar::base::ScopedSafeString &hmac_key,
                              keyczar::Keyczar *main_key) {
  // open the file
  CHECK(bio) << "null bio";
  ScopedFile f(fopen(path.c_str(), "r"));
  if (nullptr == f.get()) {
    LOG(ERROR) << "Could not open the file " << path << " for reading";
    return false;
  }

  // recover the metadata
  ifstream mf(meta_path.c_str());
  HmacdObjectMetadata hom;
  hom.ParseFromIstream(&mf);

  // check the hmac
  string computed_hmac;
  if (!main_key->Sign(hom.serialized_metadata(), &computed_hmac)) {
    LOG(ERROR) << "Could not recompute the HMAC of the object metadata";
    return false;
  }

  if (computed_hmac.compare(hom.hmac()) != 0) {
    LOG(ERROR) << "The HMAC of the data didn't match the computed HMAC";
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
  if (!SendData(bio, &net_len, sizeof(net_len))) {
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
      int x = 0;
      while ((x = BIO_write(bio, dec_buf.get(), out_dec_len)) < 0) {
        if (!BIO_should_retry(bio)) {
          LOG(ERROR) << "Network write operation failed";
          return false;
        }
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
    int x = 0;
    while ((x = BIO_write(bio, dec_buf.get(), out_dec_len)) < 0) {
      if (!BIO_should_retry(bio)) {
        LOG(ERROR) << "Final network operation failed";
        return false;
      }
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

  computed_hmac.assign(reinterpret_cast<char *>(dec_buf.get()), out_hmac_len);
  if (om.hmac().compare(computed_hmac) != 0) {
    LOG(ERROR)
        << "The computed HMAC for the file did not match the stored hmac";
    return false;
  }

  return true;
}

bool SerializeX509(X509 *x509, string *serialized_x509) {
  CHECK_NOTNULL(x509);

  int len = i2d_X509(x509, NULL);
  if (len < 0) {
    LOG(ERROR) << "Could not get the length of an X.509 certificate";
    return false;
  }

  unsigned char *serialization = nullptr;
  len = i2d_X509(x509, &serialization);
  scoped_ptr_malloc<unsigned char> der_x509(serialization);
  if (len < 0) {
    LOG(ERROR) << "Could not encode an X.509 certificate in DER";
    return false;
  }

  serialized_x509->assign(reinterpret_cast<char *>(der_x509.get()), len);
  return true;
}

bool CreateECDSAKey(const string &private_path, const string &public_path,
                    const string &secret, const string &country_code,
                    const string &org_code, const string &cn) {
  // this function assumes that private_path and public_path do not exist as
  // files. If they do, then they'll get overwritten.
  ScopedEvpPkey key(EVP_PKEY_new());

  // generate a new ECDSA key
  EC_KEY *ec_key = EC_KEY_new();
  if (ec_key == NULL) {
    LOG(ERROR) << "Could not create an EC_KEY";
    return false;
  }

  // use the ANSI X9.62 Prime 256v1 curve
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (group == NULL) {
    LOG(ERROR) << "Could not get the elliptic curve NID_secp256k1";
    return false;
  }

  EC_KEY_set_group(ec_key, group);

  if (!EC_KEY_generate_key(ec_key)) {
    LOG(ERROR) << "Could not generate a new EC key";
    return false;
  }

  if (!EVP_PKEY_assign_EC_KEY(key.get(), ec_key)) {
    LOG(ERROR) << "Could not assign the key";
    return false;
  }

  ScopedX509Ctx x509(X509_new());

  // set up properties of the x509 object
  // the serial number (always 1, for us)
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);

  // set notBefore, and notAfter to get a 365-day validity period
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L);

  // TODO(tmroeder): does x509 get ownership of key here?
  if (!X509_set_pubkey(x509.get(), key.get())) {
    LOG(ERROR) << "Could not add the public key to the X.509 structure";
    return false;
  }

  // set up the CN and Issuer to be the same
  X509_NAME *name = X509_get_subject_name(x509.get());
  if (name == NULL) {
    LOG(ERROR) << "Could not get the name of the X.509 certificate";
    return false;
  }

  if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                  reinterpret_cast<unsigned char *>(
                                      const_cast<char *>(country_code.c_str())),
                                  -1, -1, 0)) {
    LOG(ERROR) << "Could not add a Country code";
    return false;
  }

  if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                  reinterpret_cast<unsigned char *>(
                                      const_cast<char *>(org_code.c_str())),
                                  -1, -1, 0)) {
    LOG(ERROR) << "Could not add an Organization";
    return false;
  }

  if (!X509_NAME_add_entry_by_txt(
          name, "CN", MBSTRING_ASC,
          reinterpret_cast<unsigned char *>(const_cast<char *>(cn.c_str())), -1,
          -1, 0)) {
    LOG(ERROR) << "Could not add a Common Name (CN)";
    return false;
  }

  if (!X509_set_issuer_name(x509.get(), name)) {
    LOG(ERROR) << "Could not set the issuer to be the same as the subject";
    return false;
  }

  if (!X509_sign(x509.get(), key.get(), EVP_sha256())) {
    LOG(ERROR) << "Could not perform self-signing on the X.509 cert";
    return false;
  }

  ScopedFile pub_file(fopen(public_path.c_str(), "wb"));
  if (pub_file.get() == NULL) {
    LOG(ERROR) << "Could not open file " << public_path << " for writing";
    return false;
  }

  if (!PEM_write_X509(pub_file.get(), x509.get())) {
    LOG(ERROR) << "Could not write the X.509 certificate to " << public_path;
    return false;
  }

  ScopedFile priv_file(fopen(private_path.c_str(), "wb"));
  if (priv_file.get() == NULL) {
    LOG(ERROR) << "Could not open file " << private_path << " for writing";
    return false;
  }

  // TODO(tmroeder): I'll probably need to create an HMAC on this file
  // and check it myself rather than trusting OpenSSL to do the Right
  // Thing. However, I suppose that changes to the private key would
  // cause it not to match the X.509 cert.  This still makes me
  // nervous.
  int err = PEM_write_PKCS8PrivateKey(
      priv_file.get(), key.get(), EVP_aes_256_cbc(),
      const_cast<char *>(secret.c_str()), secret.size(), NULL, NULL);
  LOG(INFO) << "Got return value " << err;
  unsigned long last_error = ERR_get_error();
  if (!err) {
    LOG(ERROR) << "The error code was " << last_error;
    string s(ERR_reason_error_string(last_error));
    LOG(ERROR) << "OpenSSL error: " << s;
    LOG(ERROR) << "Could not write the private key to an encrypted PKCS8 file";
    return false;
  }

  return true;
}

bool SealOrUnsealSecret(const Tao &t, const string &sealed_path,
			string *secret) {
  // create or unseal a secret from the Tao
  FilePath fp(sealed_path);
  if (PathExists(fp)) {
    LOG(INFO) << "The path " << sealed_path << " exists";
    // Unseal it
    ifstream sealed_file(sealed_path.c_str(), ifstream::in | ios::binary);
    stringstream sealed_buf;
    sealed_buf << sealed_file.rdbuf();

    if (!t.Unseal(sealed_buf.str(), secret)) {
      LOG(ERROR) << "Could not unseal the secret from " << sealed_path;
      return false;
    }

    LOG(INFO) << "Got a secret of length " << (int)secret->size();
  } else {
    // create and seal the secret
    const int SecretSize = 16;
    if (!t.GetRandomBytes(SecretSize, secret)) {
      LOG(ERROR) << "Could not get a random secret from the Tao";
      return false;
    }

    // seal it and write the result to the specified file
    string sealed_secret;
    if (!t.Seal(*secret, &sealed_secret)) {
      LOG(ERROR) << "Could not seal the secret";
      return false;
    }

    ofstream sealed_file(sealed_path.c_str(), ofstream::out | ios::binary);
    sealed_file.write(sealed_secret.data(), sealed_secret.size());
  }

  return true;
}

}  // namespace cloudproxy
