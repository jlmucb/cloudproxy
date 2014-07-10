//  File: keys.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Implementation of cryptographic key utilities for the Tao.
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
#include "tao/keys.h"

#include <sstream>
#include <string>

#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include "tao/attestation.pb.h"
#include "tao/keys.pb.h"
#include "tao/util.h"

using google::protobuf::TextFormat;

namespace tao {

// TODO(kwalsh) Like Keyczar, this implementation sometimes stores secrets (aes
// and hmac keys, serialized ec keys, passwords, etc.) inside std::string.
// ScopedSafeString is meant to clear such strings implicitly upon freeing them.

typedef scoped_ptr_malloc<BIGNUM, CallUnlessNull<BIGNUM, BN_clear_free> >
    ScopedBIGNUM;

typedef scoped_ptr_malloc<BN_CTX, CallUnlessNull<BN_CTX, BN_CTX_free> >
    ScopedBN_CTX;

typedef scoped_ptr_malloc<EC_POINT, CallUnlessNull<EC_POINT, EC_POINT_free> >
    ScopedEC_POINT;

typedef scoped_ptr_malloc<EVP_CIPHER_CTX,
                          CallUnlessNull<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> >
    ScopedCipherCtx;

/// These two functions should be defined in openssl, but are not.
/// @{
static HMAC_CTX *HMAC_CTX_new() {
  HMAC_CTX *ctx = new HMAC_CTX;
  HMAC_CTX_init(ctx);
  return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx) {
  HMAC_CTX_cleanup(ctx);
  delete ctx;
}
/// @}

typedef scoped_ptr_malloc<HMAC_CTX, CallUnlessNull<HMAC_CTX, HMAC_CTX_free> >
    ScopedHmacCtx;

typedef scoped_ptr_malloc<
    X509_ALGOR, CallUnlessNull<X509_ALGOR, X509_ALGOR_free> > ScopedX509Algor;

/// Extract pointer to string data. This is used for the many OpenSSL functions
/// that require pointers to unsigned chars.
/// @param s The string.
/// @{
// TODO(kwalsh) See cryptic note about string_as_array vs const_cast in Keyczar
// and elsewhere saying:
//    DO NOT USE const_cast<char*>(str->data())! See the unittest for why.
// This likely has to do with the fact that the buffer returned from data() is
// not meant to be modified and might in fact be copy-on-write shared.
static const unsigned char *str2uchar(const string &s) {
  const char *p = s.empty() ? nullptr : &*s.begin();
  return reinterpret_cast<const unsigned char *>(p);
}
static unsigned char *str2uchar(string *s) {
  char *p = s->empty() ? nullptr : &*s->begin();
  return reinterpret_cast<unsigned char *>(p);
}
/// @}

void SecureStringErase(string *s) {
  // TODO(kwalsh) Keyczar has a nice 'fixme' note about making sure the memset
  // isn't optimized away, and a commented-out call to openssl's cleanse. What
  // to do?
  OPENSSL_cleanse(str2uchar(s), s->size());
  memset(str2uchar(s), 0, s->size());
}

/// Set one detail for an openssl x509 name structure.
/// @param name The x509 name structure to modify. Must be non-null.
/// @param key The country code, e.g. "US"
/// @param id The detail id, e.g. "C" for country or "CN' for common name
/// @param val The value to be set
static bool SetX509NameDetail(X509_NAME *name, const string &id,
                              const string &val) {
  // const_cast is (maybe?) safe because X509_NAME_add_entry_by_txt does not
  // modify buffer.
  unsigned char *data =
      reinterpret_cast<unsigned char *>(const_cast<char *>(val.c_str()));
  X509_NAME_add_entry_by_txt(name, id.c_str(), MBSTRING_ASC, data, -1, -1, 0);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not set x509 " << id << " detail";
    return false;
  }
  return true;
}

/// Set the details for an openssl x509 name structure.
/// @param name The x509 name structure to modify. Must be non-null.
/// @param c The country code, e.g. "US".
/// @param o The organization code, e.g. "Google"
/// @param st The state code, e.g. "Washington"
/// @param cn The common name, e.g. "Example Tao CA Service" or "localhost"
static bool SetX509NameDetails(X509_NAME *name, const X509Details &details) {
  return (!details.has_country() ||
          SetX509NameDetail(name, "C", details.country())) &&
         (!details.has_state() ||
          SetX509NameDetail(name, "ST", details.state())) &&
         (!details.has_organization() ||
          SetX509NameDetail(name, "O", details.organization())) &&
         (!details.has_commonname() ||
          SetX509NameDetail(name, "CN", details.commonname()));
}

/// Prepare an X509 structure for signing by filling in version numbers, serial
/// numbers, the subject key, and reasonable timestamps.
/// @param x509 The certificate to modify. Must be non-null.
/// @param version The x509 version number to set. Numbers are off-by-1, so for
/// x509v3 use version=2, etc.
/// @param serial The x509 serial number to set.
/// @param The subject key to set.
static bool PrepareX509(X509 *x509, int version, int serial,
                        EVP_PKEY *subject_key) {
  X509_set_version(x509, version);

  ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);

  // set notBefore and notAfter to get a reasonable validity period
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), Tao::DefaultAttestationTimeout);

  // This method allocates a new public key for x509, and it doesn't take
  // ownership of the key passed in the second parameter.
  X509_set_pubkey(x509, subject_key);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not add the public key to the X.509 structure";
    return false;
  }

  return true;
}

/// Add an extension to an openssl x509 structure.
/// @param x509 The certificate to modify. Must be non-null.
/// @param nid The NID_* constant for this extension.
/// @param val The string value to be added.
static bool AddX509Extension(X509 *x509, int nid, const string &val) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);

  // const_cast is (maybe?) safe because X509V3_EXT_conf_nid does not modify
  // buffer.
  char *data = const_cast<char *>(val.c_str());
  X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, data);
  if (!OpenSSLSuccess() || ex == nullptr) {
    LOG(ERROR) << "Could not add x509 extension";
    return false;
  }
  X509_add_ext(x509, ex, -1);
  X509_EXTENSION_free(ex);
  return true;
}

// x509 serialization in DER format
// bool SerializeX509(X509 *x509, string *der) {
//   if (x509 == nullptr ||| der == nullptr) {
//     LOG(ERROR) << "null params";
//     return false;
//   }
//   unsigned char *serialization = nullptr;
//   len = i2d_X509(x509, &serialization);
//   scoped_ptr_malloc<unsigned char> der_x509(serialization);
//   if (!OpenSSLSuccess() || len < 0) {
//     LOG(ERROR) << "Could not encode an X.509 certificate in DER";
//     return false;
//   }
//   der->assign(reinterpret_cast<char *>(der_x509.get()), len);
//   return true;
// }

string SerializeX509(X509 *x509) {
  ScopedBio mem(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(mem.get(), x509) || !OpenSSLSuccess()) {
    LOG(ERROR) << "Could not serialize x509 to PEM";
    return "";
  }
  BUF_MEM *buf;
  BIO_get_mem_ptr(mem.get(), &buf);
  return string(buf->data, buf->length);
}

static int no_password_callback(char *buf, int size, int rwflag, void *u) {
  return 0;  // return error
}

X509 *DeserializeX509(const string &pem) {
  // const_cast is safe because we only read from the BIO.
  char *data = const_cast<char *>(pem.c_str());
  ScopedBio mem(BIO_new_mem_buf(data, -1));
  ScopedX509 x509(PEM_read_bio_X509(mem.get(), nullptr /* ptr */,
                                    no_password_callback,
                                    nullptr /* cbdata */));
  if (!OpenSSLSuccess() || x509.get() == nullptr) {
    LOG(ERROR) << "Could not deserialize x509 from PEM";
    return nullptr;
  }
  return x509.release();
}

Signer *Signer::Generate() {
  // Note: some of this code is adapted from Keyczar.
  // Currently supports only ECDSA-256 with SHA-256 and curve prime256v1 (aka
  // secp256r1). See recommendations in rfc 5480, section 4.
  int curve_nid = NID_X9_62_prime256v1;
  ScopedECKey ec_key(EC_KEY_new_by_curve_name(curve_nid));
  if (!OpenSSLSuccess() || ec_key.get() == nullptr) {
    LOG(ERROR) << "Could not allocate EC_KEY";
    return nullptr;
  }
  // Make sure the ASN1 will have curve OID should this EC_KEY be exported.
  EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);
  if (!EC_KEY_generate_key(ec_key.get())) {
    OpenSSLSuccess();
    LOG(ERROR) << "Could not generate EC_KEY";
    return nullptr;
  }
  // Sanity checks.
  if (!EC_KEY_check_key(ec_key.get()) ||
      !EC_GROUP_check(EC_KEY_get0_group(ec_key.get()), nullptr)) {
    OpenSSLSuccess();
    LOG(ERROR) << "Generated bad EC_KEY";
    return nullptr;
  }
  return new Signer(ec_key.release());
}

/// Encode EC_KEY public and private keys into a protobuf.
/// @param key The key.
/// @param[out] m The protobuf.
static bool EncodeECDSA_SHA_SigningKey(const EC_KEY *ec_key,
                                       ECDSA_SHA_SigningKey_v1 *m) {
  // Curve.
  m->set_curve(PRIME256_V1);
  // ec_private.
  const BIGNUM *n = EC_KEY_get0_private_key(ec_key);
  string *ec_private = m->mutable_ec_private();
  size_t max_n_len = BN_num_bytes(n);
  ec_private->resize(max_n_len);
  size_t n_len = BN_bn2bin(n, str2uchar(ec_private));
  // Fail on buffer overflow.
  CHECK_LE(n_len, max_n_len);
  ec_private->resize(n_len);
  // ec_public.
  const EC_POINT *ec_point = EC_KEY_get0_public_key(ec_key);
  ScopedBN_CTX bn_ctx(BN_CTX_new());
  int point_len =
      EC_POINT_point2oct(EC_KEY_get0_group(ec_key), ec_point,
                         POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx.get());
  string *ec_public = m->mutable_ec_public();
  ec_public->resize(point_len);
  EC_POINT_point2oct(EC_KEY_get0_group(ec_key), ec_point,
                     POINT_CONVERSION_COMPRESSED, str2uchar(ec_public),
                     point_len, bn_ctx.get());
  return true;
}

/// Decode EC_KEY public and private keys from a protobuf.
/// @param m The protobuf.
static EC_KEY *DecodeECDSA_SHA_SigningKey(const ECDSA_SHA_SigningKey_v1 &m) {
  // Curve.
  if (m.curve() != PRIME256_V1) {
    LOG(ERROR) << "Invalid EC curve";
    return nullptr;
  }
  // Allocate EC_KEY.
  int curve_nid = NID_X9_62_prime256v1;
  ScopedECKey ec_key(EC_KEY_new_by_curve_name(curve_nid));
  if (!OpenSSLSuccess() || ec_key.get() == nullptr) {
    LOG(ERROR) << "Could not allocate EC_KEY";
    return nullptr;
  }
  // Make sure the ASN1 will have curve OID should this EC_KEY be exported.
  EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);
  // ec_private.
  const string &ec_priv = m.ec_private();
  ScopedBIGNUM n(BN_bin2bn(str2uchar(ec_priv), ec_priv.size(), nullptr));
  if (n.get() == nullptr) {
    LOG(ERROR) << "Invalid EC private key";
    return nullptr;
  }
  if (!EC_KEY_set_private_key(ec_key.get(), n.get())) {
    LOG(ERROR) << "Could not set EC private key";
    return nullptr;
  }
  // ec_public.
  ScopedEC_POINT ec_point(EC_POINT_new(EC_GROUP_new_by_curve_name(curve_nid)));
  ScopedBN_CTX bn_ctx(BN_CTX_new());
  const string &ec_pub = m.ec_public();
  if (!EC_POINT_oct2point(EC_KEY_get0_group(ec_key.get()), ec_point.get(),
                          str2uchar(ec_pub), ec_pub.size(), bn_ctx.get())) {
    LOG(ERROR) << "Invalid EC public key";
    return nullptr;
  }
  if (!EC_KEY_set_public_key(ec_key.get(), ec_point.get())) {
    LOG(ERROR) << "Could not set EC public key";
    return nullptr;
  }
  return ec_key.release();
}

/// Encode an EC_KEY public key as a protobuf.
/// @param key The key.
/// @param[out] m The protobuf.
static bool EncodeECDSA_SHA_VerifyingKey(const EC_KEY *ec_key,
                                         ECDSA_SHA_VerifyingKey_v1 *m) {
  // Curve.
  m->set_curve(PRIME256_V1);
  // ec_public.
  const EC_POINT *ec_point = EC_KEY_get0_public_key(ec_key);
  ScopedBN_CTX bn_ctx(BN_CTX_new());
  int point_len =
      EC_POINT_point2oct(EC_KEY_get0_group(ec_key), ec_point,
                         POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx.get());
  string *ec_pub = m->mutable_ec_public();
  ec_pub->resize(point_len);
  EC_POINT_point2oct(EC_KEY_get0_group(ec_key), ec_point,
                     POINT_CONVERSION_COMPRESSED, str2uchar(ec_pub), point_len,
                     bn_ctx.get());
  return true;
}

/// Decode an EC_KEY public key from a protobuf.
/// @param m The protobuf.
static EC_KEY *DecodeECDSA_SHA_VerifyingKey(
    const ECDSA_SHA_VerifyingKey_v1 &m) {
  // Curve.
  if (m.curve() != PRIME256_V1) {
    LOG(ERROR) << "Invalid EC curve";
    return nullptr;
  }
  // Allocate EC_KEY.
  int curve_nid = NID_X9_62_prime256v1;
  ScopedECKey ec_key(EC_KEY_new_by_curve_name(curve_nid));
  if (!OpenSSLSuccess() || ec_key.get() == nullptr) {
    LOG(ERROR) << "Could not allocate EC_KEY";
    return nullptr;
  }
  // Make sure the ASN1 will have curve OID should this EC_KEY be exported.
  EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);
  // ec_public.
  ScopedEC_POINT ec_point(EC_POINT_new(EC_GROUP_new_by_curve_name(curve_nid)));
  ScopedBN_CTX bn_ctx(BN_CTX_new());
  const string ec_pub = m.ec_public();
  if (!EC_POINT_oct2point(EC_KEY_get0_group(ec_key.get()), ec_point.get(),
                          str2uchar(ec_pub), ec_pub.size(), bn_ctx.get())) {
    LOG(ERROR) << "Invalid EC public key";
    return nullptr;
  }
  if (!EC_KEY_set_public_key(ec_key.get(), ec_point.get())) {
    LOG(ERROR) << "Could not set EC public key";
    return nullptr;
  }
  return ec_key.release();
}

Verifier *Signer::GetVerifier() const {
  // TODO(kwalsh) Is there a better documented way to obtain public half?
  ECDSA_SHA_VerifyingKey_v1 m;
  if (!EncodeECDSA_SHA_VerifyingKey(key_.get(), &m)) {
    LOG(ERROR) << "Could not serialize public key";
    return nullptr;
  }
  ScopedECKey pub_key(DecodeECDSA_SHA_VerifyingKey(m));
  if (pub_key.get() == nullptr) {
    LOG(ERROR) << "could not deserialize public key";
    return nullptr;
  }
  return new Verifier(pub_key.release());
}

/// Create a single string containing both context and data.
/// @param h The header.
/// @param data The data.
/// @param context The context.
static string ContextualizeData(const CryptoHeader &h, const string &data,
                                const string &context) {
  if (context.empty()) {
    LOG(ERROR) << "Cannot use an empty context.";
    return "";
  }
  SignaturePDU pdu;
  *pdu.mutable_header() = h;
  pdu.set_context(context);
  pdu.set_data(data);
  string serialized;
  if (!pdu.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize SignaturePDU";
    return "";
  }
  return serialized;
}

/// Create truncated digest of contextualized data.
/// @param h The header.
/// @param data The data.
/// @param context The context.
/// @param digest_length The desired digest length, in bytes.
static string ContextualizedSha256(const CryptoHeader &h, const string &data,
                                   const string &context,
                                   size_t digest_length) {
  string serialized = ContextualizeData(h, data, context);
  if (serialized.empty()) {
    LOG(ERROR) << "Cannot sign data without context";
    return "";
  }
  string digest;
  if (!Sha256(serialized, &digest)) {
    LOG(ERROR) << "Hash failed";
    return "";
  }
  if (digest.length() > digest_length) digest.resize(digest_length);
  return digest;
}

// This code adapted from Keyczar.
bool Signer::Sign(const string &data, const string &context,
                  string *signature) const {
  SignedData sd;
  CryptoHeader *h = sd.mutable_header();
  if (!Header(h)) {
    LOG(ERROR) << "Can't fill header";
    return false;
  }
  size_t ecdsa_size = ECDSA_size(key_.get());
  string digest = ContextualizedSha256(*h, data, context, ecdsa_size);
  if (digest.empty()) {
    LOG(ERROR) << "Cannot sign data without context";
    return false;
  }
  // Generate signature.
  string *sig = sd.mutable_signature();
  sig->resize(ecdsa_size);  // base::STLStringResizeUninitialized()
  unsigned int sig_length = 0;
  if (!ECDSA_sign(0, str2uchar(&digest), digest.size(), str2uchar(sig),
                  &sig_length, key_.get())) {
    OpenSSLSuccess();
    LOG(ERROR) << "Can't sign";
    return false;
  }
  // Fail on buffer overflow.
  CHECK_LE(sig_length, ecdsa_size);
  sig->resize(sig_length);
  if (!sd.SerializeToString(signature)) {
    LOG(ERROR) << "Could not serialize";
    return false;
  }
  return true;
}

string Signer::ToPrincipalName() const {
  // Note: Nearly identical to Verifier::ToPrincipalName().
  CryptoKey m;
  string s, b;
  if (!EncodePublic(&m) || !m.SerializeToString(&s) || !Base64WEncode(s, &b)) {
    LOG(ERROR) << "Could not serialize to principal name";
    return "";
  }
  stringstream out;
  out << "Key(" << quotedString(b) << ")";
  return out.str();
}

string Signer::SerializeWithPassword(const string &password) const {
  ScopedEvpPkey evp_pkey(GetEvpPkey());
  if (evp_pkey.get() == nullptr) {
    LOG(ERROR) << "Could not convert to EVP_PKEY";
    return "";
  }
  // Serialize EVP_PKEY as PEM-encoded PKCS#8.
  ScopedBio mem(BIO_new(BIO_s_mem()));
  const EVP_CIPHER *cipher = EVP_aes_128_cbc();
  // const_cast is (maybe?) safe because default password callback only reads
  // pass.
  char *pass = const_cast<char *>(password.c_str());
  if (PEM_write_bio_PKCS8PrivateKey(mem.get(), evp_pkey.get(), cipher, nullptr,
                                    0, nullptr, pass) != 1) {
    LOG(ERROR) << "Could not serialize EVP_PKEY";
    return "";
  }
  BUF_MEM *buf;
  BIO_get_mem_ptr(mem.get(), &buf);
  return string(buf->data, buf->length);
}

Signer *Signer::DeserializeWithPassword(const string &serialized,
                                        const string &password) {
  // Deserialize EVP_PKEY
  // const_cast is safe because we only read from the BIO.
  char *data = const_cast<char *>(serialized.c_str());
  ScopedBio mem(BIO_new_mem_buf(data, -1));
  // const_cast is (maybe?) safe because default password callback only reads
  // pass.
  char *pass = const_cast<char *>(password.c_str());
  ScopedEvpPkey evp_pkey(
      PEM_read_bio_PrivateKey(mem.get(), nullptr, nullptr, pass));
  if (!OpenSSLSuccess() || evp_pkey.get() == nullptr) {
    LOG(ERROR) << "Could not deserialize password-protected key";
    return nullptr;
  }
  if (evp_pkey->pkey.ec == nullptr) {
    LOG(ERROR) << "Serialized key has wrong type: expecting ECDSA private key";
    return nullptr;
  }
  // Move EVP_PKEY into EC_KEY.
  ScopedECKey ec_key(EVP_PKEY_get1_EC_KEY(evp_pkey.get()));
  if (ec_key.get() == nullptr) {
    OpenSSLSuccess();
    LOG(ERROR) << "Could not extract ECDSA private key";
    return nullptr;
  }
  // Sanity checks.
  if (!EC_KEY_check_key(ec_key.get()) ||
      !EC_GROUP_check(EC_KEY_get0_group(ec_key.get()), nullptr) ||
      EC_GROUP_get_asn1_flag(EC_KEY_get0_group(ec_key.get())) !=
          OPENSSL_EC_NAMED_CURVE) {
    OpenSSLSuccess();
    LOG(ERROR) << "Deserialized bad EC_KEY";
    return nullptr;
  }
  // Check curve parameters.
  int curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key.get()));
  if (curve_nid != NID_X9_62_prime256v1) {
    LOG(ERROR) << "Unrecognized EC curve: " << curve_nid;
    return nullptr;
  }
  return new Signer(ec_key.release());
}

string Signer::CreateSelfSignedX509(const string &details_text) const {
  X509Details details;
  ScopedX509 x509(X509_new());
  int version = 2;  // self sign uses version=2 (which is x509v3)
  int serial = 1;   // self sign can always use serial 1
  ScopedEvpPkey evp_pkey(GetEvpPkey());
  if (evp_pkey.get() == nullptr ||
      !TextFormat::ParseFromString(details_text, &details) ||
      !PrepareX509(x509.get(), version, serial, evp_pkey.get()) ||
      !SetX509NameDetails(X509_get_subject_name(x509.get()), details) ||
      !SetX509NameDetails(X509_get_issuer_name(x509.get()), details) ||
      !AddX509Extension(x509.get(), NID_basic_constraints,
                        "critical,CA:TRUE") ||
      !AddX509Extension(x509.get(), NID_subject_key_identifier, "hash") ||
      !AddX509Extension(x509.get(), NID_authority_key_identifier,
                        "keyid:always") ||
      !X509_sign(x509.get(), evp_pkey.get(), EVP_sha1()) || !OpenSSLSuccess()) {
    LOG(ERROR) << "Could not create self-signed X.509 certificate";
    return "";
  }
  return SerializeX509(x509.get());
}

string Signer::CreateSignedX509(const string &ca_pem_cert, int cert_serial,
                                const Verifier &subject_key,
                                const string &subject_details) const {
  X509Details details;
  ScopedEvpPkey ca_evp_pkey(GetEvpPkey());
  ScopedEvpPkey subject_evp_pkey(subject_key.GetEvpPkey());
  ScopedX509 ca_x509(DeserializeX509(ca_pem_cert));
  ScopedX509 x509(X509_new());
  X509_NAME *subject =
      (x509.get() ? X509_get_subject_name(x509.get()) : nullptr);
  X509_NAME *issuer =
      (x509.get() ? X509_get_issuer_name(ca_x509.get()) : nullptr);
  int version = 0;  // ca-sign uses version=0 (which is x509v1)
  if (ca_evp_pkey.get() == nullptr || subject_evp_pkey.get() == nullptr ||
      ca_x509.get() == nullptr || subject == nullptr || issuer == nullptr ||
      !TextFormat::ParseFromString(subject_details, &details) ||
      !PrepareX509(x509.get(), version, cert_serial, subject_evp_pkey.get()) ||
      !SetX509NameDetails(subject, details) ||
      !X509_set_issuer_name(x509.get(), issuer) ||
      !X509_sign(x509.get(), ca_evp_pkey.get(), EVP_sha1()) ||
      !OpenSSLSuccess()) {
    LOG(ERROR) << "Could not create CA-signed X.509 certificate";
    return "";
  }
  string subject_pem_cert = SerializeX509(x509.get());
  if (subject_pem_cert == "") {
    LOG(ERROR) << "Could not serialize x509 certificates";
    return "";
  }
  return subject_pem_cert + ca_pem_cert;
}

bool Signer::Encode(CryptoKey *m) const {
  m->set_version(CRYPTO_VERSION_1);
  m->set_purpose(CryptoKey::SIGNING);
  m->set_algorithm(CryptoKey::ECDSA_SHA);
  ECDSA_SHA_SigningKey_v1 k;
  if (!EncodeECDSA_SHA_SigningKey(key_.get(), &k)) {
    LOG(ERROR) << "Could not encode EC private key";
    return false;
  }
  // Store it in m.key.
  if (!k.SerializeToString(m->mutable_key())) {
    LOG(ERROR) << "Could not serialize key";
    return false;
  }
  SecureStringErase(k.mutable_ec_private());
  return true;
}

bool Signer::EncodePublic(CryptoKey *m) const {
  // Note: Same as Verifier::Encode().
  m->set_version(CRYPTO_VERSION_1);
  m->set_purpose(CryptoKey::VERIFYING);
  m->set_algorithm(CryptoKey::ECDSA_SHA);
  ECDSA_SHA_VerifyingKey_v1 k;
  if (!EncodeECDSA_SHA_VerifyingKey(key_.get(), &k)) {
    LOG(ERROR) << "Could not encode EC public key";
    return false;
  }
  // Store it in m.key.
  if (!k.SerializeToString(m->mutable_key())) {
    LOG(ERROR) << "Could not serialize key";
    return false;
  }
  return true;
}

Signer *Signer::Decode(const CryptoKey &m) {
  if (m.version() != CRYPTO_VERSION_1) {
    LOG(ERROR) << "Bad version";
    return nullptr;
  }
  if (m.purpose() != CryptoKey::SIGNING) {
    LOG(ERROR) << "Bad purpose";
    return nullptr;
  }
  if (m.algorithm() != CryptoKey::ECDSA_SHA) {
    LOG(ERROR) << "Bad algorithm";
    return nullptr;
  }
  ECDSA_SHA_SigningKey_v1 k;
  if (!k.ParseFromString(m.key())) {
    SecureStringErase(k.mutable_ec_private());
    LOG(ERROR) << "Could not parse key";
    return nullptr;
  }
  ScopedECKey ec_key(DecodeECDSA_SHA_SigningKey(k));
  SecureStringErase(k.mutable_ec_private());
  if (ec_key.get() == nullptr) {
    LOG(ERROR) << "Could not decode EC private key";
    return nullptr;
  }
  return new Signer(ec_key.release());
}

bool Signer::Header(CryptoHeader *h) const {
  // Note: Same as Verifier::Header().
  ECDSA_SHA_VerifyingKey_v1 m;
  string s, d;
  if (!EncodeECDSA_SHA_VerifyingKey(key_.get(), &m) ||
      !m.SerializeToString(&s) || !Sha1(s, &d) || d.size() < 4) {
    LOG(ERROR) << "Could not compute key hint";
    return false;
  }
  h->set_version(CRYPTO_VERSION_1);
  h->set_key_hint(d.substr(0, 4));
  return true;
}

EVP_PKEY *Signer::GetEvpPkey() const {
  // Note: Same as Verifier::GetEvpPkey()
  ScopedEvpPkey evp_pkey(EVP_PKEY_new());
  if (!OpenSSLSuccess() || evp_pkey.get() == nullptr) {
    LOG(ERROR) << "Could not allocate EVP_PKEY";
    return nullptr;
  }
  if (!EVP_PKEY_set1_EC_KEY(evp_pkey.get(), key_.get())) {
    LOG(ERROR) << "Could not convert EC_KEY to EVP_PKEY";
    return nullptr;
  }
  return evp_pkey.release();
}

Signer *Signer::DeepCopy() const {
  CryptoKey m;
  scoped_ptr<Signer> s;
  if (!Encode(&m) || !reset(s, Decode(m))) {
    LOG(ERROR) << "Could not copy key";
    return nullptr;
  }
  SecureStringErase(m.mutable_key());
  return s.release();
}

bool Verifier::Verify(const string &data, const string &context,
                      const string &signature) const {
  SignedData sd;
  if (!sd.ParseFromString(signature)) {
    LOG(ERROR) << "Invalid signature";
    return false;
  }
  CryptoHeader h;
  if (!Header(&h) || sd.header().version() != h.version() ||
      sd.header().key_hint() != h.key_hint()) {
    LOG(ERROR) << "Invalid signature version or key hint";
    return false;
  }
  size_t ecdsa_size = ECDSA_size(key_.get());
  string digest = ContextualizedSha256(h, data, context, ecdsa_size);
  if (digest.empty()) {
    LOG(ERROR) << "Cannot verify signature without context";
    return false;
  }
  string *sig = sd.mutable_signature();
  int ret = ECDSA_verify(0, str2uchar(&digest), digest.size(), str2uchar(sig),
                         sig->size(), key_.get());
  if (ret == -1) {
    OpenSSLSuccess();
    LOG(ERROR) << "Error validating signature";
  }
  return (ret == 1);
}

string Verifier::ToPrincipalName() const {
  CryptoKey m;
  string s, b;
  if (!Encode(&m) || !m.SerializeToString(&s) || !Base64WEncode(s, &b)) {
    LOG(ERROR) << "Could not serialize to principal name";
    return "";
  }
  stringstream out;
  out << "Key(" << quotedString(b) << ")";
  return out.str();
}

Verifier *Verifier::FromPrincipalName(const string &name) {
  CryptoKey m;
  string s, b;
  stringstream in(name);
  skip(in, "Key(");
  getQuotedString(in, &b);
  skip(in, ")");
  if (!in || (in.get() && !in.eof())) {
    LOG(ERROR) << "Bad format for Tao principal name";
    return nullptr;
  }
  if (!Base64WDecode(b, &s) || !m.ParseFromString(s)) {
    LOG(ERROR) << "Could not parse the Tao principal name";
    return nullptr;
  }
  return Verifier::Decode(m);
}

Verifier *Verifier::FromX509(const string &pem_cert) {
  ScopedX509 x509(DeserializeX509(pem_cert));
  if (x509.get() == nullptr) {
    LOG(ERROR) << "Could not deserialize x509";
    return nullptr;
  }
  /*
  int nid = OBJ_obj2nid(x509->cert_info->key->algor->algorithm);
  if (nid == NID_undef || true) {
    LOG(ERROR) << "x509 has invalid key type: " << nid;
    return nullptr;
  }
  */
  ScopedEvpPkey evp_pkey(X509_get_pubkey(x509.get()));
  if (evp_pkey.get() == nullptr) {
    LOG(ERROR) << "Could not get public key from x509";
    return nullptr;
  }
  ScopedECKey ec_key(EVP_PKEY_get1_EC_KEY(evp_pkey.get()));
  if (ec_key.get() == nullptr) {
    LOG(ERROR) << "Could not get EC key from x509";
    return nullptr;
  }
  int curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key.get()));
  if (curve_nid != NID_X9_62_prime256v1) {
    LOG(ERROR) << "Unrecognized EC curve: " << curve_nid;
    return nullptr;
  }
  return new Verifier(ec_key.release());
}

bool Verifier::Encode(CryptoKey *m) const {
  m->set_version(CRYPTO_VERSION_1);
  m->set_purpose(CryptoKey::VERIFYING);
  m->set_algorithm(CryptoKey::ECDSA_SHA);
  ECDSA_SHA_VerifyingKey_v1 k;
  if (!EncodeECDSA_SHA_VerifyingKey(key_.get(), &k)) {
    LOG(ERROR) << "Could not encode EC public key";
    return false;
  }
  // Store it in m.key.
  if (!k.SerializeToString(m->mutable_key())) {
    LOG(ERROR) << "Could not serialize key";
    return false;
  }
  return true;
}

Verifier *Verifier::Decode(const CryptoKey &m) {
  if (m.version() != CRYPTO_VERSION_1) {
    LOG(ERROR) << "Bad version";
    return nullptr;
  }
  if (m.purpose() != CryptoKey::VERIFYING) {
    LOG(ERROR) << "Bad purpose";
    return nullptr;
  }
  if (m.algorithm() != CryptoKey::ECDSA_SHA) {
    LOG(ERROR) << "Bad algorithm";
    return nullptr;
  }
  ECDSA_SHA_VerifyingKey_v1 k;
  if (!k.ParseFromString(m.key())) {
    LOG(ERROR) << "Could not parse key";
    return nullptr;
  }
  ScopedECKey ec_key(DecodeECDSA_SHA_VerifyingKey(k));
  if (ec_key.get() == nullptr) {
    LOG(ERROR) << "Could not decode EC private key";
    return nullptr;
  }
  return new Verifier(ec_key.release());
}

bool Verifier::Header(CryptoHeader *h) const {
  ECDSA_SHA_VerifyingKey_v1 m;
  string s, d;
  if (!EncodeECDSA_SHA_VerifyingKey(key_.get(), &m) ||
      !m.SerializeToString(&s) || !Sha1(s, &d) || d.size() < 4) {
    LOG(ERROR) << "Could not compute key hint";
    return false;
  }
  h->set_version(CRYPTO_VERSION_1);
  h->set_key_hint(d.substr(0, 4));
  return true;
}

EVP_PKEY *Verifier::GetEvpPkey() const {
  ScopedEvpPkey evp_pkey(EVP_PKEY_new());
  if (!OpenSSLSuccess() || evp_pkey.get() == nullptr) {
    LOG(ERROR) << "Could not allocate EVP_PKEY";
    return nullptr;
  }
  if (!EVP_PKEY_set1_EC_KEY(evp_pkey.get(), key_.get())) {
    LOG(ERROR) << "Could not convert EC_KEY to EVP_PKEY";
    return nullptr;
  }
  return evp_pkey.release();
}

Verifier *Verifier::DeepCopy() const {
  CryptoKey m;
  scoped_ptr<Verifier> s;
  if (!Encode(&m) || !reset(s, Decode(m))) {
    LOG(ERROR) << "Could not copy key";
    return nullptr;
  }
  SecureStringErase(m.mutable_key());
  return s.release();
}

// TODO(kwalsh) Replace OpenSSL (and Keyczar) rand with Tao rand when possible.

Deriver *Deriver::Generate() {
  // This only supports HKDF with HMAC-SHA256.
  size_t key_size = 256;
  ScopedSafeString key(new string());
  if (!RandBytes(key_size / 8, key.get())) {
    LOG(ERROR) << "Error getting random bytes";
    return nullptr;
  }
  return new Deriver(*key);
}

/// Compute an HMAC signature.
/// @param key The key.
/// @param data The data.
/// @param[out] mac The signature.
static bool SHA256_HMAC_Sign(const string &key, const string &data,
                             string *mac) {
  const EVP_MD *md = EVP_sha256();
  ScopedHmacCtx ctx(HMAC_CTX_new());
  unsigned int mac_length = 0;  // mac->size();  // don't append
  mac->resize(mac_length + EVP_MAX_MD_SIZE);
  unsigned int sig_length = 0;
  if (!HMAC_Init_ex(ctx.get(), str2uchar(key), key.size(), md,
                    nullptr /* engine */) ||
      !HMAC_Update(ctx.get(), str2uchar(data), data.size()) ||
      !HMAC_Final(ctx.get(), str2uchar(mac) + mac_length, &sig_length)) {
    LOG(ERROR) << "Could not compute HMAC";
    return false;
  }
  // Fail on buffer overflow.
  CHECK_LE(sig_length, EVP_MAX_MD_SIZE);
  mac->resize(mac_length + sig_length);
  return true;
}

/// Verify an HMAC signature.
/// @param key The key.
/// @param data The data.
/// @param mac The signature.
static bool SHA256_HMAC_Verify(const string &key, const string &data,
                               const string &mac) {
  string mac2;
  return (SHA256_HMAC_Sign(key, data, &mac2) && mac.size() == mac2.size() &&
          CRYPTO_memcmp(str2uchar(mac), str2uchar(mac2), mac.size()) == 0);
}

bool Deriver::Derive(size_t size, const string &context, string *secret) const {
  // This omits the optional "extract" stage of HKDF and implements only the
  // second stage "expand" operation. The output is the first size bytes of:
  // T = T(1) | T(2) | ... | T(N)
  // where
  //   T(0) = emptystring
  //   T(i) = HMAC(key, T(i-1) | size | context | i)
  KeyDerivationPDU pdu;
  pdu.set_size(size);
  pdu.set_context(context);
  pdu.set_index(0);
  secret->clear();
  string d = "";
  while (secret->size() < size) {
    pdu.set_previous_hash(d);
    pdu.set_index(pdu.index() + 1);
    string s;
    if (!pdu.SerializeToString(&s) || !SHA256_HMAC_Sign(*key_, s, &d)) {
      LOG(ERROR) << "Can't compute hmac";
      return false;
    }
    secret->append(d);
  }
  secret->resize(size);
  return true;
}

bool Deriver::Encode(CryptoKey *m) const {
  m->set_version(CRYPTO_VERSION_1);
  m->set_purpose(CryptoKey::DERIVING);
  m->set_algorithm(CryptoKey::HMAC_SHA);
  HMAC_SHA_DerivingKey_v1 k;
  k.set_mode(DERIVING_MODE_HKDF);
  k.set_hmac_private(*key_);
  if (!k.SerializeToString(m->mutable_key())) {
    SecureStringErase(k.mutable_hmac_private());
    LOG(ERROR) << "Could not serialize key";
    return false;
  }
  SecureStringErase(k.mutable_hmac_private());
  return true;
}

Deriver *Deriver::Decode(const CryptoKey &m) {
  if (m.version() != CRYPTO_VERSION_1) {
    LOG(ERROR) << "Bad version";
    return nullptr;
  }
  if (m.purpose() != CryptoKey::DERIVING) {
    LOG(ERROR) << "Bad purpose";
    return nullptr;
  }
  if (m.algorithm() != CryptoKey::HMAC_SHA) {
    LOG(ERROR) << "Bad algorithm";
    return nullptr;
  }
  HMAC_SHA_DerivingKey_v1 k;
  if (!k.ParseFromString(m.key()) || k.mode() != DERIVING_MODE_HKDF) {
    SecureStringErase(k.mutable_hmac_private());
    LOG(ERROR) << "Could not parse key";
    return nullptr;
  }
  ScopedSafeString key(new string());
  key->assign(k.hmac_private());
  SecureStringErase(k.mutable_hmac_private());
  // This only supports HKDF with HMAC-SHA256.
  size_t key_size = 256;
  if (key->size() * 8 != key_size) {
    LOG(ERROR) << "Invalid hmac key size";
    return nullptr;
  }
  return new Deriver(*key);
}

// bool Deriver::Header(CryptoHeader *h) const {
//   CryptingKey m;
//   string s, d;
//   if (!Encode(&m) || !Sha1(m.key(), &d) || d.size() < 4) {
//     LOG(ERROR) << "Could not compute key hint";
//     return false;
//   }
//   h->set_version(CRYPTO_VERSION_1);
//   h->set_key_hint(d.substr(0, 4));
//   return true;
// }

Deriver *Deriver::DeepCopy() const {
  CryptoKey m;
  scoped_ptr<Deriver> s;
  if (!Encode(&m) || !reset(s, Decode(m))) {
    LOG(ERROR) << "Could not copy key";
    return nullptr;
  }
  SecureStringErase(m.mutable_key());
  return s.release();
}

Crypter *Crypter::Generate() {
  // This only supports AES-256 CBC with HMAC-SHA256.
  // See NIST SP800-57 part1, pages 63-64 for hmac key size recommendations.
  size_t aes_size = 256;
  size_t hmac_size = 256;
  ScopedSafeString aes_key(new string());
  ScopedSafeString hmac_key(new string());
  if (!RandBytes(aes_size / 8, aes_key.get()) ||
      !RandBytes(hmac_size / 8, hmac_key.get())) {
    LOG(ERROR) << "Error getting random bytes";
    return nullptr;
  }
  return new Crypter(*aes_key, *hmac_key);
}

/// Compute cipher for AES-256 CBC.
/// @param encrypt True for encryption mode.
/// @param key The aes key.
/// @param iv The random iv.
/// @param in The data to be ciphered.
/// @param[out] out The output after ciphering.
static bool AES256_CBC_Cipher(bool encrypt, const string &key, const string &iv,
                              const string &in, string *out) {
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  // Initialize with aesKey and iv.
  ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
  if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr /* engine */,
                         str2uchar(key), str2uchar(iv), encrypt ? 1 : 0)) {
    LOG(ERROR) << "Can't init cipher";
    return false;
  }
  // Update with input data.
  size_t max_out = in.size() + cipher->block_size;  // no -1 ?
  out->resize(max_out);  // base::STLStringResizeUninitialized()
  int out_data_length = 0;
  if (!EVP_CipherUpdate(ctx.get(), str2uchar(out), &out_data_length,
                        str2uchar(in), in.size())) {
    LOG(ERROR) << "Can't update cipher";
    return false;
  }
  // Fail on buffer overflow.
  CHECK_LT(out_data_length, max_out);
  out->resize(out_data_length);
  // Finalize.
  max_out = out_data_length + cipher->block_size;
  out->resize(max_out);  // base::STLStringResizeUninitialized()
  int out_finalize_length = 0;
  if (!EVP_CipherFinal_ex(ctx.get(), str2uchar(out) + out_data_length,
                          &out_finalize_length)) {
    LOG(ERROR) << "Can't finalize cipher";
    return false;
  }
  // Fail on buffer overflow.
  CHECK_LE(out_finalize_length, cipher->block_size);
  out->resize(out_data_length + out_finalize_length);
  return true;
}

bool Crypter::Encrypt(const string &data, string *encrypted) const {
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  EncryptedData ed;
  if (!Header(ed.mutable_header())) {
    LOG(ERROR) << "Can't prepare encrypt header";
    return false;
  }
  // Select iv.
  size_t iv_size =
      EVP_CIPHER_iv_length(cipher);  // AES iv size = AES block size =
                                     // 128 bits = 16 bytes
  if (!RandBytes(iv_size, ed.mutable_iv())) {
    LOG(ERROR) << "Can't generate iv";
    return false;
  }
  // Encrypt with key, iv, and data.
  if (!AES256_CBC_Cipher(true /* encrypt */, *aesKey_, ed.iv(), data,
                         ed.mutable_ciphertext())) {
    LOG(ERROR) << "Can't encrypt";
    return false;
  }
  // Serialize and HMAC.
  string s;
  if (!ed.SerializeToString(&s) ||
      !SHA256_HMAC_Sign(*hmacKey_, s, ed.mutable_mac())) {
    LOG(ERROR) << "Can't compute hmac";
    return false;
  }
  if (!ed.SerializeToString(encrypted)) {
    LOG(ERROR) << "Can't serialize encrypted data";
    return false;
  }
  return true;
}

bool Crypter::Decrypt(const string &encrypted, string *data) const {
  EncryptedData ed;
  if (!ed.ParseFromString(encrypted)) {
    LOG(ERROR) << "Invalid encryption";
    return false;
  }
  // Check headers.
  CryptoHeader h;
  if (!Header(&h) || ed.header().version() != h.version() ||
      ed.header().key_hint() != h.key_hint()) {
    LOG(ERROR) << "Invalid encryption version or key hint";
    return false;
  }
  // Deserialize and HMAC.
  string mac = ed.mac();
  ed.clear_mac();
  string s;
  if (!ed.SerializeToString(&s) || !SHA256_HMAC_Verify(*hmacKey_, s, mac)) {
    LOG(ERROR) << "Can't verify hmac";
    return false;
  }
  // Decrypt with key, iv, and ciphertext.
  if (!AES256_CBC_Cipher(false /* decrypt */, *aesKey_, ed.iv(),
                         ed.ciphertext(), data)) {
    LOG(ERROR) << "Can't decrypt";
    return false;
  }
  return true;
}

bool Crypter::Encode(CryptoKey *m) const {
  m->set_version(CRYPTO_VERSION_1);
  m->set_purpose(CryptoKey::CRYPTING);
  m->set_algorithm(CryptoKey::AES_CBC_HMAC_SHA);
  AES_CBC_HMAC_SHA_CryptingKey_v1 k;
  k.set_mode(CIPHER_MODE_CBC);
  k.set_aes_private(*aesKey_);
  k.set_hmac_private(*hmacKey_);
  if (!k.SerializeToString(m->mutable_key())) {
    SecureStringErase(k.mutable_aes_private());
    SecureStringErase(k.mutable_hmac_private());
    LOG(ERROR) << "Could not serialize key";
    return false;
  }
  SecureStringErase(k.mutable_aes_private());
  SecureStringErase(k.mutable_hmac_private());
  return true;
}

Crypter *Crypter::Decode(const CryptoKey &m) {
  if (m.version() != CRYPTO_VERSION_1) {
    LOG(ERROR) << "Bad version";
    return nullptr;
  }
  if (m.purpose() != CryptoKey::CRYPTING) {
    LOG(ERROR) << "Bad purpose";
    return nullptr;
  }
  if (m.algorithm() != CryptoKey::AES_CBC_HMAC_SHA) {
    LOG(ERROR) << "Bad algorithm";
    return nullptr;
  }
  AES_CBC_HMAC_SHA_CryptingKey_v1 k;
  if (!k.ParseFromString(m.key()) || k.mode() != CIPHER_MODE_CBC) {
    SecureStringErase(k.mutable_aes_private());
    SecureStringErase(k.mutable_hmac_private());
    LOG(ERROR) << "Could not parse key";
    return nullptr;
  }
  ScopedSafeString aes_key(new string());
  ScopedSafeString hmac_key(new string());
  aes_key->assign(k.aes_private());
  hmac_key->assign(k.hmac_private());
  SecureStringErase(k.mutable_aes_private());
  SecureStringErase(k.mutable_hmac_private());
  // This only supports AES-256 CBC with HMAC-SHA256.
  // See NIST SP800-57 part1, pages 63-64 for hmac key size recommendations.
  size_t aes_size = 256;
  size_t hmac_size = 256;
  if (aes_key->size() * 8 != aes_size || hmac_key->size() * 8 != hmac_size) {
    LOG(ERROR) << "Invalid aes or hmac key sizes";
    return nullptr;
  }
  return new Crypter(*aes_key, *hmac_key);
}

bool Crypter::Header(CryptoHeader *h) const {
  CryptoKey m;
  string s, d;
  if (!Encode(&m) || !Sha1(m.key(), &d) || d.size() < 4) {
    LOG(ERROR) << "Could not compute key hint";
    return false;
  }
  h->set_version(CRYPTO_VERSION_1);
  h->set_key_hint(d.substr(0, 4));
  return true;
}

Crypter *Crypter::DeepCopy() const {
  CryptoKey m;
  scoped_ptr<Crypter> s;
  if (!Encode(&m) || !reset(s, Decode(m))) {
    SecureStringErase(m.mutable_key());
    LOG(ERROR) << "Could not copy key";
    return nullptr;
  }
  SecureStringErase(m.mutable_key());
  return s.release();
}

bool Keys::InitTemporary() {
  bool s = key_types_ & KeyType::Signing;
  bool d = key_types_ & KeyType::Deriving;
  bool c = key_types_ & KeyType::Crypting;
  if (key_types_ == 0 ||
      key_types_ != ((s ? KeyType::Signing : 0) | (d ? KeyType::Deriving : 0) |
                     (c ? KeyType::Crypting : 0))) {
    LOG(ERROR) << "Bad key type";
    return false;
  }
  // Generate temporary keys.
  fresh_ = true;
  if ((s && !reset(signer_, Signer::Generate())) ||
      (s && !reset(verifier_, signer_->GetVerifier())) ||
      (d && !reset(deriver_, Deriver::Generate())) ||
      (c && !reset(crypter_, Crypter::Generate()))) {
    crypter_.reset();
    deriver_.reset();
    verifier_.reset();
    signer_.reset();
    LOG(ERROR) << "Could not generate keys";
    return false;
  }
  return true;
}

bool Keys::InitTemporaryHosted(Tao *tao) {
  if (!InitTemporary()) {
    LOG(ERROR) << "Could not initialize temporary keys";
    return false;
  }
  // Create a delegation for the signing key from the host Tao.
  if (signer_.get() != nullptr) {
    Statement stmt;
    stmt.set_delegate(signer_->ToPrincipalName());
    if (!tao->Attest(stmt, &delegation_)) {
      LOG(ERROR) << "Could not create delegation for signing key";
      return false;
    }
  }
  return true;
}

/// Compute cipher for AES-128 CBC using key from PBKDF2 with HMAC-SHA256.
/// @param encrypt True for encryption mode.
/// @param password The password used to generate the encryption keys.
/// @param iterations The number of iterations for PBKDF2.
/// @param salt The random salt for PBKDF2.
/// @param iv The random iv for AES.
/// @param in The data to be ciphered.
/// @param[out] out The output after ciphering.
static bool PBKDF2_SHA256_AES128_CBC_Cipher(bool encrypt,
                                            const string &password,
                                            int iterations, const string &salt,
                                            const string &iv, const string &in,
                                            string *out) {
  /// This code is adapted from Keyczar. It uses seemingly undocument OpenSSL
  /// PBE functions that (presumably) implement PKCS#5 PBKDF2 with HMAC-SHA256
  /// for
  /// key derivation and PKCS#12 AES128 encryption. It isn't clear if a MAC is
  /// added during the encryption step. Perhaps some of this code should be
  /// replaced by more explicit calls to PBKDF2, AES, and HMAC.
  if (password.empty()) {
    LOG(ERROR) << "Will not perform PBE with empty password";
    return false;
  }
  const EVP_CIPHER *cipher = EVP_aes_128_cbc();
  // AES iv size = AES block size = 128 bits = 16 bytes
  if (iterations < PKCS5_DEFAULT_ITER ||
      iv.size() != static_cast<size_t>(EVP_CIPHER_iv_length(cipher))) {
    LOG(ERROR) << "Invalid PBE parameters";
    return false;
  }
  int prf_nid = NID_hmacWithSHA256;
  /// const_cast is safe because PKCS5_pbe2_set_iv doesn't modify salt or iv.
  unsigned char *salt_buf = const_cast<unsigned char *>(str2uchar(salt));
  unsigned char *iv_buf = const_cast<unsigned char *>(str2uchar(iv));
  ScopedX509Algor algo(PKCS5_pbe2_set_iv(cipher, iterations, salt_buf,
                                         salt.size(), iv_buf, prf_nid));
  if (algo.get() == nullptr) {
    LOG(ERROR) << "Can't create PBE cipher";
    return "";
  }

  // size_t max_len = in.size() + cipher->block_size;
  // out->resize(max_len);

  unsigned char *out_ptr = nullptr;
  int out_len = 0;
  /// const_cast is safe because PKCS12_pbe_crypt doesn't modify in buffer.
  unsigned char *in_buf = const_cast<unsigned char *>(str2uchar(in));
  if (!PKCS12_pbe_crypt(algo.get(), password.c_str(), password.size(), in_buf,
                        in.size(),
                        &out_ptr,  // str2uchar(out),
                        &out_len, encrypt ? 1 : 0)) {
    LOG(ERROR) << "Can't encrypt with PBE";
    return false;
  }
  // CHECK_LT(out_len, max_len);
  // out->resize(out_len);
  out->assign(reinterpret_cast<char *>(out_ptr), out_len);
  return true;
}

/// Encrypt a string with PBE.
/// @param plaintext The string to be encrypted.
/// @param password The password used to generate the encryption keys.
/// @param[out] ciphertext The encrypted string.
static bool PBE_Encrypt(const string &plaintext, const string &password,
                        string *ciphertext) {
  PBEData pbe;
  pbe.set_version(CRYPTO_VERSION_1);
  pbe.set_cipher("aes128");
  pbe.set_hmac("sha256");
  pbe.set_iterations(4096);  // minimum 2048
  size_t salt_size = 16;     // minimum 8
  const EVP_CIPHER *cipher = EVP_aes_128_cbc();
  size_t iv_size =
      EVP_CIPHER_iv_length(cipher);  // AES iv size = AES block size =
                                     // 128 bits = 16 bytes
  if (!RandBytes(salt_size, pbe.mutable_salt()) ||
      !RandBytes(iv_size, pbe.mutable_iv())) {
    LOG(ERROR) << "Can't generate salt and iv";
    return false;
  }
  bool encrypt = true;
  if (!PBKDF2_SHA256_AES128_CBC_Cipher(encrypt, password, pbe.iterations(),
                                       pbe.salt(), pbe.iv(), plaintext,
                                       pbe.mutable_ciphertext())) {
    LOG(ERROR) << "Can't perform PBE";
    return false;
  }
  if (!pbe.SerializeToString(ciphertext)) {
    LOG(ERROR) << "Can't serialize PBE";
    return false;
  }
  return true;
}

/// Decrypt a string with PBE.
/// @param ciphertext The string to be decrypted.
/// @param password The password used to generate the encryption keys.
/// @param[out] plaintext The decrypted string.
static bool PBE_Decrypt(const string &ciphertext, const string &password,
                        string *plaintext) {
  PBEData pbe;
  bool encrypt = false;
  if (!pbe.ParseFromString(ciphertext) || pbe.version() != CRYPTO_VERSION_1 ||
      pbe.cipher() != "aes128" || pbe.hmac() != "sha256" ||
      !PBKDF2_SHA256_AES128_CBC_Cipher(encrypt, password, pbe.iterations(),
                                       pbe.salt(), pbe.iv(), pbe.ciphertext(),
                                       plaintext)) {
    LOG(ERROR) << "Can't decrypt PBE data";
    return false;
  }
  return true;
}

/// Erase all private contents of a keyset.
/// @param m The keyset to be cleansed.
static void SecureKeysetErase(CryptoKeyset *m) {
  for (int i = 0; i < m->keys_size(); i++) {
    CryptoKey *k = m->mutable_keys(i);
    SecureStringErase(k->mutable_key());
  }
  m->clear_keys();
}

bool Keys::InitWithPassword(const string &password) {
  bool s = key_types_ & KeyType::Signing;
  bool d = key_types_ & KeyType::Deriving;
  bool c = key_types_ & KeyType::Crypting;
  if (key_types_ == 0 ||
      key_types_ != ((s ? KeyType::Signing : 0) | (d ? KeyType::Deriving : 0) |
                     (c ? KeyType::Crypting : 0))) {
    LOG(ERROR) << "Bad key type";
    return false;
  }
  if (path_.get() == nullptr) {
    LOG(ERROR) << "Bad init call";
    return false;
  }
  if (password.empty()) {
    // Special case: load just a public verifying key.
    if (c || d) {
      LOG(ERROR)
          << "With no password, only a public verifying key can be loaded";
      return false;
    }
    // Load the key from a saved x509, if available.
    string pem_cert;
    if (!PathExists(FilePath(X509Path()))) {
      // Can't generate a verifier alone.
      LOG(ERROR) << "No verifier key found";
      return false;
    }
    if (!ReadFileToString(X509Path(), &pem_cert) ||
        !reset(verifier_, Verifier::FromX509(pem_cert))) {
      LOG(ERROR) << "Could not load verifying key from x509";
      return false;
    }
    fresh_ = false;
  } else {
    // Load or generate PBE-protected keys.
    if (c || d) {
      // Contains crypter or deriver, so use custom tao PBE format.
      if (PathExists(FilePath(PBEKeysetPath()))) {
        // Load PBE keyset.
        string pbe, serialized;
        CryptoKeyset keyset;
        if (!ReadFileToString(PBEKeysetPath(), &pbe) ||
            !PBE_Decrypt(pbe, password, &serialized) ||
            !keyset.ParseFromString(serialized) || !Decode(keyset, s, d, c)) {
          SecureKeysetErase(&keyset);
          crypter_.reset();
          deriver_.reset();
          verifier_.reset();
          signer_.reset();
          LOG(ERROR) << "Could not load PBE keyset";
          return false;
        }
        SecureKeysetErase(&keyset);
        fresh_ = false;
      } else {
        // Save PBE keyset.
        if (!InitTemporary()) {
          LOG(ERROR) << "Could not initialize keys";
          return false;
        }
        CryptoKeyset keyset;
        string serialized, pbe;
        if (!Encode(&keyset) || !keyset.SerializeToString(&serialized) ||
            !PBE_Encrypt(serialized, password, &pbe) ||
            !CreateDirectory(FilePath(PBEKeysetPath()).DirName()) ||
            !WriteStringToFile(PBEKeysetPath(), pbe)) {
          SecureKeysetErase(&keyset);
          LOG(ERROR) << "Could not save PBE keyset";
          return false;
        }
        SecureKeysetErase(&keyset);
        fresh_ = true;
      }
    } else {
      // A signer, but no crypter and no deriver, so use PKCS#8.
      if (PathExists(FilePath(PBESignerPath()))) {
        // Load PKCS#8.
        string serialized_key;
        if (!ReadFileToString(PBESignerPath(), &serialized_key) ||
            !reset(signer_,
                   Signer::DeserializeWithPassword(serialized_key, password)) ||
            !reset(verifier_, signer_->GetVerifier())) {
          signer_.reset();
          verifier_.reset();
          LOG(ERROR) << "Could not load PBE signing key";
          return false;
        }
        fresh_ = false;
      } else {
        // Save PKCS#8.
        string serialized_key;
        if (!reset(signer_, Signer::Generate()) ||
            !reset(verifier_, signer_->GetVerifier()) ||
            (serialized_key = signer_->SerializeWithPassword(password)) == "" ||
            !CreateDirectory(FilePath(PBESignerPath()).DirName()) ||
            !WriteStringToFile(PBESignerPath(), serialized_key)) {
          signer_.reset();
          verifier_.reset();
          LOG(ERROR) << "Could not save PBE signing key";
          return false;
        }
        fresh_ = true;
      }
    }
  }
  // Load optional x509.
  if (s && !fresh_ && PathExists(FilePath(X509Path())) &&
      !ReadFileToString(X509Path(), &x509_)) {
    LOG(ERROR) << "Could not load x509";
    return false;
  }
  return true;
}

bool Keys::InitHosted(Tao *tao, const string &policy) {
  bool s = key_types_ & KeyType::Signing;
  bool d = key_types_ & KeyType::Deriving;
  bool c = key_types_ & KeyType::Crypting;
  if (key_types_ == 0 ||
      key_types_ != ((s ? KeyType::Signing : 0) | (d ? KeyType::Deriving : 0) |
                     (c ? KeyType::Crypting : 0))) {
    LOG(ERROR) << "Bad key type";
    return false;
  }
  if (path_.get() == nullptr) {
    LOG(ERROR) << "Bad init call";
    return false;
  }
  if (PathExists(FilePath(SealedKeysetPath()))) {
    // Load Tao-sealed keyset.
    string sealed, serialized, seal_policy;
    CryptoKeyset keyset;
    if (!ReadFileToString(SealedKeysetPath(), &sealed) ||
        !tao->Unseal(sealed, &serialized, &seal_policy) ||
        seal_policy != policy || !keyset.ParseFromString(serialized) ||
        !Decode(keyset, s, d, c)) {
      SecureKeysetErase(&keyset);
      crypter_.reset();
      deriver_.reset();
      verifier_.reset();
      signer_.reset();
      LOG(ERROR) << "Could not load sealed keyset";
      return false;
    }
    SecureKeysetErase(&keyset);
    fresh_ = false;
  } else {
    // Save Tao-sealed keyset.
    if (!InitTemporary()) {
      LOG(ERROR) << "Could not initialize keys";
      return false;
    }
    CryptoKeyset keyset;
    string serialized, sealed;
    if (!Encode(&keyset) || !keyset.SerializeToString(&serialized) ||
        !tao->Seal(serialized, policy, &sealed) ||
        !CreateDirectory(FilePath(SealedKeysetPath()).DirName()) ||
        !WriteStringToFile(SealedKeysetPath(), sealed)) {
      SecureKeysetErase(&keyset);
      LOG(ERROR) << "Could not serialize and seal keyset";
      return false;
    }
    SecureKeysetErase(&keyset);
    fresh_ = true;
  }
  if (s && fresh_) {
    // Save delegation.
    Statement stmt;
    stmt.set_delegate(signer_->ToPrincipalName());
    if (!tao->Attest(stmt, &delegation_) ||
        !CreateDirectory(FilePath(DelegationPath()).DirName()) ||
        !WriteStringToFile(DelegationPath(), delegation_)) {
      LOG(ERROR) << "Could not create delegation for signing key";
      return false;
    }
  } else if (s && !fresh_) {
    // Load delegation.
    if (!ReadFileToString(DelegationPath(), &delegation_)) {
      LOG(ERROR) << "Could not load tao delegation";
      return false;
    }
  }
  // Load optional x509.
  if (s && !fresh_ && PathExists(FilePath(X509Path())) &&
      !ReadFileToString(X509Path(), &x509_)) {
    LOG(ERROR) << "Could not load x509";
    return false;
  }
  return true;
}

bool Keys::SetX509(const string &pem_cert) {
  // Add sanity checks for cert? E.g. check for key mismatch?
  if (path_.get() != nullptr &&
      (!CreateDirectory(FilePath(X509Path()).DirName()) ||
       !WriteStringToFile(X509Path(), pem_cert))) {
    LOG(ERROR) << "Could not save x509";
    return false;
  }
  x509_ = pem_cert;
  return true;
}

Keys *Keys::DeepCopy() const {
  scoped_ptr<Keys> other(new Keys(key_types_));
  other->fresh_ = fresh_;
  other->delegation_ = delegation_;
  other->x509_ = x509_;
  if (path_.get() != nullptr) {
    other->path_.reset(new string(*path_));
  }
  if ((signer_.get() != nullptr &&
       !reset(other->signer_, signer_->DeepCopy())) ||
      (verifier_.get() != nullptr &&
       !reset(other->verifier_, verifier_->DeepCopy())) ||
      (deriver_.get() != nullptr &&
       !reset(other->deriver_, deriver_->DeepCopy())) ||
      (crypter_.get() != nullptr &&
       !reset(other->crypter_, crypter_->DeepCopy()))) {
    LOG(ERROR) << "Could not copy key set";
    return nullptr;
  }
  return other.release();
}

string Keys::GetPath(const string &suffix) const {
  if (path_.get() == nullptr) return "";
  return FilePath(*path_).Append(suffix).value();
}

bool Keys::Decode(const CryptoKeyset &m, bool signer, bool deriver,
                  bool crypter) {
  for (int i = 0; i < m.keys_size(); i++) {
    const CryptoKey &k = m.keys(i);
    if (k.purpose() == CryptoKey::SIGNING) {
      if (!signer || signer_.get() != nullptr ||
          !reset(signer_, Signer::Decode(k)) ||
          !reset(verifier_, signer_->GetVerifier())) {
        LOG(ERROR) << "Could not load signer";
        return false;
      }
    } else if (k.purpose() == CryptoKey::DERIVING) {
      if (!deriver || deriver_.get() != nullptr ||
          !reset(deriver_, Deriver::Decode(k))) {
        LOG(ERROR) << "Could not load deriver";
        return false;
      }
    } else if (k.purpose() == CryptoKey::CRYPTING) {
      if (!crypter || crypter_.get() != nullptr ||
          !reset(crypter_, Crypter::Decode(k))) {
        LOG(ERROR) << "Could not load crypter";
        return false;
      }
    } else {
      LOG(ERROR) << "Unrecognized key type";
      return false;
    }
  }
  // Make sure all the keys are loaded
  if ((signer && signer_.get() == nullptr) ||
      (signer && verifier_.get() == nullptr) ||
      (deriver && deriver_.get() == nullptr) ||
      (crypter && crypter_.get() == nullptr)) {
    LOG(ERROR) << "Missing keys";
    return false;
  }
  return true;
}

bool Keys::Encode(CryptoKeyset *m) const {
  if ((signer_.get() != nullptr && !signer_->Encode(m->add_keys())) ||
      (deriver_.get() != nullptr && !deriver_->Encode(m->add_keys())) ||
      (crypter_.get() != nullptr && !crypter_->Encode(m->add_keys()))) {
    LOG(ERROR) << "Could not encode keyset";
    return false;
  }
  return true;
}

}  // namespace tao
