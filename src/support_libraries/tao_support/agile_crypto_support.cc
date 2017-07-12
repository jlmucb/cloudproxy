//  Copyright (c) 2014, Google Inc.  All rights reserved.
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

#include <string>
#include <vector>
#include <stdlib.h>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <sys/types.h>

#include "agile_crypto_support.h"
#include "ssl_helpers.h"

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/err.h>

const string Basic128BitCipherSuite("sign:ecdsap256,crypt:aes128-ctr-hmacsha256,derive:hdkf-sha256");
const string Basic192BitCipherSuite("sign:ecdsap384,crypt:aes256-ctr-hmacsha384,derive:hdkf-sha256");
const string Basic256BitCipherSuite("sign:ecdsap521,crypt:aes256-ctr-hmacsha512,derive:hdkf-sha256");


void PrintBytes(int size, byte* buf) {
  for (int i = 0; i < size; i++) {
    printf("%02x", buf[i]);
  }
}

bool EqualBytes(byte* in1, int size1, byte* in2, int size2) {
  if (size1 != size2)
    return false;
  for (int i = 0; i < size1; i++) {
    if (in1[i] != in2[i])
      return false;
  }
  return true;
}

bool ReadFile(string& file_name, string* out) {
  struct stat file_info;
  int k = stat(file_name.c_str(), &file_info);
  if (k < 0) {
    return false;
  }

  int fd = open(file_name.c_str(), O_RDONLY);
  if (fd < 0)
    return false;
  byte* buf = (byte*) malloc(file_info.st_size);
  if (buf == nullptr) {
    close(fd);
    return false;
  }
  int n = read(fd, buf, file_info.st_size);
  if (n < file_info.st_size) {
    free(buf);
    close(fd);
    return false;
  }
  free(buf);
  close(fd);
  out->assign((const char*)buf, n);
  return true;
}

bool WriteFile(string& file_name, string& in) {
  int fd = creat(file_name.c_str(), S_IRWXU | S_IRWXG);
  if (fd <= 0)
    return false;
  write(fd, (byte*)in.data(), in.size());
  return true;
}

Verifier* CryptoKeyToVerifier(tao::CryptoKey& ck) {

  EVP_PKEY* pk = EVP_PKEY_new();
  EC_KEY* ec_key = nullptr;
  int k;

  if (ck.key_header().key_type()  == string("ecdsap256-public")) {
    k = OBJ_txt2nid("prime256v1");
    ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
        printf("GenerateKey: couldn't generate ECC program key (1).\n");
        return nullptr;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  } else if (ck.key_header().key_type() == string("ecdsap384-public")) {
    k = OBJ_txt2nid("secp384r1");
    ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
        printf("GenerateKey: couldn't generate ECC program key (1).\n");
        return nullptr;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  } else if (ck.key_header().key_type() == string("ecdsap521-public")) {
    k = OBJ_txt2nid("secp521r1");
    ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
        printf("GenerateKey: couldn't generate ECC program key (1).\n");
        return nullptr;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  } else {
    return nullptr;
  }
  int n = ck.key_components().size();
  if (!DeserializeECCKeyComponents(ck.key_components(0), ec_key)) {
    return nullptr;
  }
  Verifier* v = new(Verifier);
  v->ch_ = new(tao::CryptoHeader);
  *v->ch_ = ck.key_header();
  EVP_PKEY_set1_EC_KEY(pk, ec_key);
  v->vk_ = pk;
  return v;
}

Signer* CryptoKeyToSigner(tao::CryptoKey& ck) {

  EVP_PKEY* pk = EVP_PKEY_new();
  EC_KEY* ec_key = nullptr;
  int k;

  if (ck.key_header().key_type()  == string("ecdsap256")) {
    k = OBJ_txt2nid("prime256v1");
    ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
        printf("GenerateKey: couldn't generate ECC program key (1).\n");
        return nullptr;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  } else if (ck.key_header().key_type() == string("ecdsap384")) {
    k = OBJ_txt2nid("secp384r1");
    ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
        printf("GenerateKey: couldn't generate ECC program key (1).\n");
        return nullptr;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  } else if (ck.key_header().key_type() == string("ecdsap521")) {
    k = OBJ_txt2nid("secp521r1");
    ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
        printf("GenerateKey: couldn't generate ECC program key (1).\n");
        return nullptr;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
  } else {
    return nullptr;
  }
  if (ck.key_components().size() < 1) {
    return nullptr;
  }
  if (!DeserializeECCKeyComponents(ck.key_components(0), ec_key)) {
    return nullptr;
  }
  Signer* s = new(Signer);
  s->ch_ = new(tao::CryptoHeader);
  *s->ch_ = ck.key_header();
  EVP_PKEY_set1_EC_KEY(pk, ec_key);
  s->sk_ = pk;
  return s;
}

Verifier* VerifierFromSigner(Signer* s) {
  Verifier* v = new(Verifier);
  EC_KEY* ec_pub_key = nullptr;
  if (s->ch_->key_type() == string("aes128-ctr-hmacsha256")) {
        ec_pub_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  } else if (s->ch_->key_type() != string("aes256-ctr-hmacsha384")) {
        int k = OBJ_txt2nid("secp384r1");
        ec_pub_key = EC_KEY_new_by_curve_name(k);
  } else if (s->ch_->key_type() == string("aes256-ctr-hmacsha512")) {
        int k = OBJ_txt2nid("secp521r1");
        ec_pub_key = EC_KEY_new_by_curve_name(k);
  } else {
    return nullptr;
  }
  tao::CryptoHeader* ch = new(tao::CryptoHeader);
  *ch = *(s->ch_);
  ch->set_key_type(ch->key_type() + "-public");
  v->ch_ = ch;
  v->vk_ = EVP_PKEY_new();
  EC_KEY* priv_key = EVP_PKEY_get1_EC_KEY(s->sk_);
  const EC_POINT* pub_key = EC_KEY_get0_public_key(priv_key);
  EVP_PKEY_set1_EC_KEY(v->vk_, ec_pub_key);
  return v;
}

Verifier* VerifierFromCertificate(string& der) {
  X509 *cert;
  byte buf[2048];
  int len = 2048;
  byte* p = buf;
  memcpy(buf, (byte*) der.data(), der.size());
  len = der.size();

  if (d2i_X509(&cert, (const byte**) &p, len) == NULL) {
    return nullptr;
  }
  Verifier* v = new(Verifier);
  v->vk_ = X509_get_pubkey(cert);
  tao::CryptoHeader* ch = new(tao::CryptoHeader);
  ch->set_version(tao::CRYPTO_VERSION_2);
  // Figure out type from vk_
  if (v->vk_->type != EVP_PKEY_EC) {
    return nullptr;
  }
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(v->vk_);
  const EC_GROUP *ecgrp = EC_KEY_get0_group(ec_key);
  const char* s_type = OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp));
  ch->set_key_epoch(1);
  ch->set_key_purpose("verifying");
  ch->set_key_status("active");
  if (s_type == nullptr) {
    return nullptr;
  }
  if (strcmp(s_type, "prime256v1") == 0) {
    ch->set_key_type("ecdsap256-public");
  } else if (strcmp(s_type, "secp384r1") == 0) {
    ch->set_key_type("ecdsap384-public");
  } else if (strcmp(s_type, "secp521r1") == 0) {
    ch->set_key_type("ecdsap521-public");
  } else {
    return nullptr;
  }
  v->ch_ = ch;
  return v;
}

Crypter* CryptoKeyToCrypter(tao::CryptoKey& ck) {
  if (ck.key_header().key_type() != string("aes128-ctr-hmacsha256") &&
      ck.key_header().key_type() != string("aes256-ctr-hmacsha384") &&
      ck.key_header().key_type() != string("aes256-ctr-hmacsha512")) {
    return nullptr;
  }
  Crypter* c = new(Crypter);
  c->ch_ = new(tao::CryptoHeader);
  *(c->ch_) = ck.key_header();
  c->encryptingKeyBytes_ = new(string);
  c->encryptingKeyBytes_->assign(ck.key_components(0));
  c->hmacKeyBytes_ = new(string);
  c->hmacKeyBytes_->assign(ck.key_components(1));
  return c;
}

tao::CryptoKey* SignerToCryptoKey(Signer* s) {
  if (s->ch_->key_type() != string("aes128-ctr-hmacsha256") &&
      s->ch_->key_type() != string("aes256-ctr-hmacsha384") &&
      s->ch_->key_type() == string("aes256-ctr-hmacsha512")) {
    return nullptr;
  }
  tao::CryptoKey* ck = new(tao::CryptoKey);
  tao::CryptoHeader* ch = new(tao::CryptoHeader);
  *ch = *(s->ch_);
  ck->set_allocated_key_header(ch);
  string component;
  EC_KEY* ec_key= EVP_PKEY_get1_EC_KEY(s->sk_);
  if (!SerializeECCKeyComponents(ec_key, &component)) {
    return nullptr;
  }
  string* kc = ck->add_key_components();
  *kc = component;
  return ck;
}

tao::CryptoKey* VerifierToCryptoKey(Verifier* v) {
  if (v->ch_->key_type() != string("ecdsap256-public") &&
      v->ch_->key_type() != string("ecdsap384-public") &&
      v->ch_->key_type() != string("ecdsap521-public")) {
    return nullptr;
  }
  tao::CryptoKey* ck = new(tao::CryptoKey);
  tao::CryptoHeader* ch = new(tao::CryptoHeader);
  *ch = *(v->ch_);
  ck->set_allocated_key_header(ch);
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(v->vk_);
  string component;
  if (!SerializeECCKeyComponents(ec_key, &component)) {
    return nullptr;
  }
  string* kc = ck->add_key_components();
  *kc = component;
  return ck;
}

tao::CryptoKey* CrypterToCryptoKey(Crypter* c) {
  tao::CryptoKey* ck = new(tao::CryptoKey);
  tao::CryptoHeader* ch = new(tao::CryptoHeader);
  *ch = *(c->ch_);
  if (c->ch_->key_type() != string("aes128-ctr-hmacsha256") &&
      c->ch_->key_type() != string("aes256-ctr-hmacsha384") &&
      c->ch_->key_type() != string("aes256-ctr-hmacsha512")) {
    return nullptr;
  }
  string* kc = ck->add_key_components();
  *kc = *c->encryptingKeyBytes_;
  kc = ck->add_key_components();
  *kc = *c->hmacKeyBytes_;
  return ck;
}

bool SerializeECCKeyComponents(EC_KEY* ec_key, string* component) {
  byte buf[512];
  byte* pb = buf;

  int size_der = i2d_ECPrivateKey(ec_key, nullptr);
  size_der = i2d_ECPrivateKey(ec_key, (byte**)&pb);
  component->assign((const char*)buf, size_der);
  return 1;
}

bool DeserializeECCKeyComponents(string component, EC_KEY* ec_key) {
  byte buf[4096];
  byte* pb = buf;
  memcpy(buf, component.data(), component.size());
  EC_KEY* ec = d2i_ECPrivateKey(&ec_key, (const byte**)&pb, component.size());
  return true;
}

bool GenerateCryptoKey(string& type, tao::CryptoKey* ck) {

  byte buf[128];
  string component;

  tao::CryptoHeader* ch = ck->mutable_key_header();
  ch->set_key_epoch(1);
  ch->set_key_status("active");
  ch->set_version(tao::CRYPTO_VERSION_2);
  ch->set_key_type(type);
  if (type == string("ecdsap256")) {
    ch->set_key_purpose("signing");
    int k = OBJ_txt2nid("prime256v1");
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
      printf("GenerateKey: couldn't generate ECC program key (1).\n");
      return false;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    if (1 != EC_KEY_generate_key(ec_key)) {
      printf("GenerateKey: couldn't generate ECC program key(2).\n");
      return false;
    }
    if (!SerializeECCKeyComponents(ec_key, &component)) {
      printf("GenerateKey: couldn't serialize ECC key.\n");
      return false;
    }
    string* kc = ck->add_key_components();
    *kc = component;
  } else if (type == string("ecdsap384")) {
    ch->set_key_purpose("signing");
    int k = OBJ_txt2nid("secp384r1");
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(k);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    if (ec_key == nullptr) {
      printf("GenerateKey: couldn't generate ECC program key (1).\n");
      return false;
    }
    if (1 != EC_KEY_generate_key(ec_key)) {
      printf("GenerateKey: couldn't generate ECC program key(2).\n");
      return false;
    }
    if (!SerializeECCKeyComponents(ec_key, &component)) {
      printf("GenerateKey: couldn't generate ECC program key(2).\n");
      return false;
    }
  } else if (type == string("ecdsap521")) {
    ch->set_key_purpose("signing");
    int k = OBJ_txt2nid("secp521r1");
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(k);
    if (ec_key == nullptr) {
      printf("GenerateKey: couldn't generate ECC program key (1).\n");
      return false;
    }
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    if (1 != EC_KEY_generate_key(ec_key)) {
      printf("GenerateKey: couldn't generate ECC program key(2).\n");
      return false;
    }
    if (!SerializeECCKeyComponents(ec_key, &component)) {
      printf("GenerateKey: couldn't serialize ECC key.\n");
      return false;
    }
  } else if (type == string("aes128-ctr-hmacsha256")) {
    ch->set_key_purpose("crypting");
#ifdef FAKE_RAND_BYTES
    int rc = RAND_pseudo_bytes(buf, 48);
#else
    int rc = RAND_bytes(buf, 48);
#endif
    if (rc != 1) {
      printf("GenerateKey: couldn't generate random bytes %d.\n", rc);
      return false;
    }
    string* kc = ck->add_key_components();
    kc->assign((const char*)&buf[0], 16);
    kc = ck->add_key_components();
    kc->assign((const char*)&buf[16], 32);
  } else if (type == string("aes256-ctr-hmacsha384")) {
    ch->set_key_purpose("crypting");
#ifdef FAKE_RAND_BYTES
    int rc = RAND_pseudo_bytes(buf, 80);
#else
    int rc = RAND_bytes(buf, 80);
#endif
    if (rc != 1) {
      printf("GenerateKey: couldn't generate random bytes.\n");
      return false;
    }
    string* kc = ck->add_key_components();
    kc->assign((const char*)&buf[0], 32);
    kc = ck->add_key_components();
    kc->assign((const char*)&buf[32], 48);
  } else if (type == string("aes256-ctr-hmacsha512")) {
    ch->set_key_purpose("crypting");
#ifdef FAKE_RAND_BYTES
    int rc = RAND_pseudo_bytes(buf, 96);
#else
    int rc = RAND_bytes(buf, 96);
#endif
    if (rc != 1) {
      printf("GenerateKey: couldn't generate random bytes.\n");
      return false;
    }
    string* kc = ck->add_key_components();
    kc->assign((const char*)&buf[0], 32);
    kc = ck->add_key_components();
    kc->assign((const char*)&buf[32], 64);
  } else {
    return false;
  }
  return true;
}

void PrintCryptoHeader(const tao::CryptoHeader& ch) {
  if (ch.has_version()) {
    printf("Version %d\n", ch.version());
  }
  if (ch.has_key_name()) {
    printf("Key name: %s\n", ch.key_name().c_str());
  }
  if (ch.has_key_epoch()) {
    printf("Key epoch: %d\n", ch.key_epoch());
  }
  if (ch.has_key_type()) {
    printf("Key type: %s\n", ch.key_type().c_str());
  }
  if (ch.has_key_purpose()) {
    printf("Key purpose: %s\n", ch.key_purpose().c_str());
  }
  if (ch.has_key_status()) {
    printf("Key status: %s\n", ch.key_status().c_str());
  }
}

void PrintCryptoKey(const tao::CryptoKey& ck) {
  PrintCryptoHeader(ck.key_header());
  for (int j = 0; j < ck.key_components_size(); j++) {
    const string& kc = ck.key_components(j);
    printf("Key component %d: ", j);
    PrintBytes(kc.size(), (byte*)kc.data());
    printf("\n");
  }
}

bool Signer::Sign(string& in, string* out) {
  if (ch_ == nullptr) {
    return false;
  }
  if (!ch_->has_key_type()) {
    return false;
  }
  if (!ch_->has_key_purpose()) {
    return false;
  }
  if (ch_->key_purpose() != string("signing")) {
    return false;
  }

  byte digest[128];
  int dig_len;
  byte signature[2048];
  int sig_len;
  if (ch_->key_type() == string("ecdsap256")) {
    dig_len = 32;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (byte*)in.data(), in.size());
    SHA256_Final(digest, &sha256);
  } else if (ch_->key_type() != string("ecdsap384")) {
    dig_len = 48;
    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, (byte*)in.data(), in.size());
    SHA384_Final(digest, &sha384);
  } else if (ch_->key_type() != string("ecdsap521")) {
    dig_len = 64;
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, (byte*)in.data(), in.size());
    SHA512_Final(digest, &sha512);
  } else {
    return false;
  }
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(sk_);
  ECDSA_SIG* sig = ECDSA_do_sign((const byte*) digest, dig_len, ec_key);
  if (!EC_SIG_serialize(sig, out)) {
    return false;
  }
  return true;
}

bool Signer::Verify(string& msg, string& serialized_sig) {
  if (ch_ == nullptr) {
    return false;
  }
  if (!ch_->has_key_type()) {
    return false;
  }
  if (!ch_->has_key_purpose()) {
    return false;
  }
  if (ch_->key_purpose() != string("signing")) {
    return false;
  }

  byte digest[128];
  int dig_len;
  byte signature[2048];
  int sig_len;
  if (ch_->key_type() == string("ecdsap256")) {
    dig_len = 32;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (byte*)msg.data(), msg.size());
    SHA256_Final(digest, &sha256);
  } else if (ch_->key_type() != string("ecdsap384")) {
    dig_len = 48;
    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, (byte*)msg.data(), msg.size());
    SHA384_Final(digest, &sha384);
  } else if (ch_->key_type() != string("ecdsap521")) {
    dig_len = 64;
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, (byte*)msg.data(), msg.size());
    SHA512_Final(digest, &sha512);
  } else {
    return false;
  }

  ECDSA_SIG sig;
  if (!EC_SIG_deserialize(serialized_sig, &sig)) {
    return false;
  }
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(sk_);
  int result = ECDSA_do_verify((const byte*) digest, dig_len, (const ECDSA_SIG *) &sig, ec_key);
  return result == 1;
}

bool Verifier::Verify(string& msg, string& serialized_sig) {
  if (ch_ == nullptr) {
    return false;
  }
  if (!ch_->has_key_type()) {
    return false;
  }
  if (!ch_->has_key_purpose()) {
    return false;
  }
  if (ch_->key_purpose() != string("verifying")) {
    return false;
  }

  byte digest[128];
  int dig_len;
  byte signature[2048];
  int sig_len;
  if (ch_->key_type() == string("ecdsap256")) {
    dig_len = 32;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (byte*)msg.data(), msg.size());
    SHA256_Final(digest, &sha256);
  } else if (ch_->key_type() != string("ecdsap384")) {
    dig_len = 48;
    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, (byte*)msg.data(), msg.size());
    SHA384_Final(digest, &sha384);
  } else if (ch_->key_type() != string("ecdsap521")) {
    dig_len = 64;
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, (byte*)msg.data(), msg.size());
    SHA512_Final(digest, &sha512);
  } else {
    return false;
  }

  ECDSA_SIG sig;
  if (!EC_SIG_deserialize(serialized_sig, &sig)) {
    return false;
  }
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(vk_);
  int result = ECDSA_do_verify((const byte*) digest, dig_len, (const ECDSA_SIG *) &sig, ec_key);
  return result == 1;
}

bool Crypter::Encrypt(string& in, string* iv, string* mac_out, string* out) {
  if (ch_ == nullptr) {
    return false;
  }
  if (!ch_->has_key_type()) {
    return false;
  }
  if (!ch_->has_key_purpose()) {
    return false;
  }
  if (ch_->key_purpose() != string("crypting")) {
    return false;
  }

  uint64_t ctr[2] = {0ULL, 0ULL};
  iv->assign((const char*)ctr, 16);
  if (ch_->key_type() == string("aes128-ctr-hmacsha256")) {
    byte* t_buf = (byte*) malloc(in.size());
    byte mac[32];
    unsigned int mac_size = 32;

    if (!AesCtrCrypt(ctr, 128, (byte*)encryptingKeyBytes_->data(), in.size(), (byte*) in.data(), t_buf)) {
      return false;
    }
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, (byte*)hmacKeyBytes_->data(), hmacKeyBytes_->size(), EVP_sha256(), NULL);
    HMAC_Update(&ctx, (byte*)iv->data(), iv->size());
    HMAC_Update(&ctx, t_buf, in.size());
    HMAC_Final(&ctx, (byte*)mac, &mac_size);
    HMAC_CTX_cleanup(&ctx);
    out->assign((const char*)t_buf, in.size());
    mac_out->assign((const char*)mac, mac_size);
    free(t_buf);
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha384")) {
    byte* t_buf = (byte*) malloc(in.size());
    byte mac[48];
    unsigned int mac_size = 48;

    if (!AesCtrCrypt(ctr, 256, (byte*)encryptingKeyBytes_->data(), in.size(), (byte*) in.data(), t_buf)) {
      return false;
    }

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, hmacKeyBytes_->data(), hmacKeyBytes_->size(), EVP_sha384(), NULL);
    HMAC_Update(&ctx, (byte*)iv->data(), iv->size());
    HMAC_Update(&ctx, t_buf, in.size());
    HMAC_Final(&ctx, (byte*)mac, &mac_size);
    HMAC_CTX_cleanup(&ctx);
    out->assign((const char*)t_buf, in.size());
    mac_out->assign((const char*)mac, mac_size);
    free(t_buf);
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha512")) {
    byte* t_buf = (byte*) malloc(in.size());
    byte mac[64];
    unsigned int mac_size = 64;

    if (!AesCtrCrypt(ctr, 256, (byte*)encryptingKeyBytes_->data(), in.size(), (byte*) in.data(), t_buf)) {
      return false;
    }

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, hmacKeyBytes_->data(), hmacKeyBytes_->size(), EVP_sha512(), NULL);
    HMAC_Update(&ctx, (byte*)iv->data(), iv->size());
    HMAC_Update(&ctx, t_buf, in.size());
    HMAC_Final(&ctx, (byte*)mac, &mac_size);
    HMAC_CTX_cleanup(&ctx);

    out->assign((const char*)t_buf, in.size());
    mac_out->assign((const char*)mac, mac_size);
    free(t_buf);
  } else {
    return false;
  }
  return true;
}

bool Crypter::Decrypt(string& in, string& iv, string& mac_in, string* out) {
  if (ch_ == nullptr) {
    return false;
  }
  if (!ch_->has_key_type()) {
    return false;
  }
  if (!ch_->has_key_purpose()) {
    return false;
  }
  if (ch_->key_purpose() != string("crypting")) {
    return false;
  }

  uint64_t ctr[2] = {0ULL, 0ULL};
  memcpy((byte*)ctr, (byte*) iv.data(), iv.size());

  if (ch_->key_type() == string("aes128-ctr-hmacsha256")) {
    byte* t_buf = (byte*) malloc(in.size());
    byte mac[32];
    unsigned int mac_size = 32;

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, hmacKeyBytes_->data(), hmacKeyBytes_->size(), EVP_sha256(), NULL);
    HMAC_Update(&ctx, (byte*)iv.data(), iv.size());
    HMAC_Update(&ctx, (byte*) in.data(), in.size());
    HMAC_Final(&ctx, (byte*)mac, &mac_size);
    HMAC_CTX_cleanup(&ctx);

    if (!AesCtrCrypt(ctr, 128, (byte*)encryptingKeyBytes_->data(), in.size(), (byte*) in.data(), t_buf)) {
      printf("AesCtrCrypt decrypt failed\n");
      return false;
    }
    out->assign((const char*)t_buf, in.size());
    if (!EqualBytes(mac, mac_size, (byte*)mac_in.data(), mac_in.size())) {
      printf("mac 128 mismatch\n");
      return false;
    }
    free(t_buf);
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha384")) {
    byte* t_buf = (byte*) malloc(in.size());
    byte mac[48];
    unsigned int mac_size = 48;

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, hmacKeyBytes_->data(), hmacKeyBytes_->size(), EVP_sha384(), NULL);
    HMAC_Update(&ctx, (byte*)iv.data(), iv.size());
    HMAC_Update(&ctx, (byte*) in.data(), in.size());
    HMAC_Final(&ctx, (byte*)mac, &mac_size);
    HMAC_CTX_cleanup(&ctx);

    if (!EqualBytes(mac, mac_size, (byte*)mac_in.data(), mac_in.size())) {
      printf("mac 256-384 mismatch\n");
      return false;
    }
    if (!AesCtrCrypt(ctr, 256, (byte*)encryptingKeyBytes_->data(), in.size(), (byte*) in.data(), t_buf)) {
      printf("AesCtrCrypt decrypt failed\n");
      return false;
    }
    out->assign((const char*)t_buf, in.size());
    free(t_buf);
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha512")) {
    byte* t_buf = (byte*) malloc(in.size());
    byte mac[128];
    unsigned int mac_size = 64;
    memset(mac, 0, 64);

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, hmacKeyBytes_->data(), hmacKeyBytes_->size(), EVP_sha512(), NULL);
    HMAC_Update(&ctx, (byte*)iv.data(), iv.size());
    HMAC_Update(&ctx, (byte*) in.data(), in.size());
    HMAC_Final(&ctx, mac, &mac_size);
    HMAC_CTX_cleanup(&ctx);

    if (!EqualBytes(mac, mac_size, (byte*)mac_in.data(), mac_in.size())) {
      printf("mac 256-512 mismatch\n");
      return false;
    }
    if (!AesCtrCrypt(ctr, 256, (byte*)encryptingKeyBytes_->data(), in.size(), (byte*) in.data(), t_buf)) {
      printf("AesCtrCrypt decrypt failed\n");
      return false;
    }
    out->assign((const char*)t_buf, in.size());
    free(t_buf);
  } else {
    return false;
  }
  return true;
}

bool Deriver::Derive(string& salt, string& context, string& in,  string* out) {
  *out = in;
  return true;
}

string* CryptoSuiteName_to_CrypterName(string& cipher_suite) {
  if (cipher_suite == Basic128BitCipherSuite) {
    return new string("aes128-ctr-hmacsha256");
  } else if (cipher_suite == Basic192BitCipherSuite) {
    return new string("aes256-ctr-hmacsha384");
  } else if (cipher_suite == Basic256BitCipherSuite) {
    return new string("aes256-ctr-hmacsha512");
  } else {
    return nullptr;
  }
}

string* CryptoSuiteName_to_SignerName(string& cipher_suite) {
  if (cipher_suite == Basic128BitCipherSuite) {
    return new string("ecdsap256");
  } else if (cipher_suite == Basic192BitCipherSuite) {
    return new string("ecdsap384");
  } else if (cipher_suite == Basic256BitCipherSuite) {
    return new string("ecdsap521");
  } else {
    return nullptr;
  }
}

string* CryptoSuiteName_to_VerifierName(string& cipher_suite) {
  if (cipher_suite == Basic128BitCipherSuite) {
    return new string("ecdsap256-public");
  } else if (cipher_suite == Basic192BitCipherSuite) {
    return new string("ecdsap384-public");
  } else if (cipher_suite == Basic256BitCipherSuite) {
    return new string("ecdsap521-public");
  } else {
    return nullptr;
  }
}

string* MarshalCryptoKey(tao::CryptoKey& ck) {
  string out;
  
  if (!ck.SerializeToString(&out))
    return nullptr;
  return new string(out);
}

bool UnmarshalCryptoKey(tao::CryptoKey* ck, string in) {
  string out;
  
  if (!ck->ParseFromString(in))
    return false;
  return true;
}

string* MarshalSaveSavedProgramData(tao_support::SavedProgramData& pd) {
  string out;
  
  if (!pd.SerializeToString(&out))
    return nullptr;
  return new string(out);
}

bool UnmarshalSavedProgramData(tao_support::SavedProgramData* pd, string in) {
  string out;
  
  if (!pd->ParseFromString(in))
    return false;
  return true;
}

bool Protect(Crypter& c, string& in, string* out) {
  string iv;
  string mac_out;
  string t_out;
  if (!c.Encrypt(in, &iv, &mac_out, &t_out))
    return false;
  tao::EncryptedData* ed = new(tao::EncryptedData);
  tao::CryptoHeader* ch = new(tao::CryptoHeader);
  *ch = *c.ch_;
  ed->set_allocated_header(ch);
  ed->set_iv(iv);
  ed->set_ciphertext(t_out);
  ed->set_mac(mac_out);
  ed->SerializeToString(out);
  return true;
}

bool Unprotect(Crypter& c, string& in, string* out) {
  tao::EncryptedData ed;
  if (!ed.ParseFromString(in)) {
    return false;
  }
  string in_buf = ed.ciphertext();
  string iv = ed.iv();
  string mac_in = ed.iv();
  if (c.Decrypt(in_buf, iv, mac_in, out))
    return false;
  return true;
}

bool UniversalKeyName(Verifier* v, string* out) {
  string t_out;
  if (!KeyPrincipalBytes(v, &t_out))
    return false;
  byte mac[32];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, t_out.data(), t_out.size());
  SHA256_Final(mac, &sha256);
  out->assign((const char*)mac, 32);
  return true;
}

bool KeyPrincipalBytes(Verifier* v, string* out) {
  byte buf[512];
  byte* pb = buf;
  int size_der = i2d_PUBKEY(v->vk_, (byte**)&pb);
  out->assign((const char*)buf, size_der);
  return true;
}
