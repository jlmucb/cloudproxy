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

#include "agile_crypto_support.h"

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
  return nullptr;
}

Signer* CryptoKeyToSigner(tao::CryptoKey& ck) {
  return nullptr;
}

Crypter* CryptoKeyToCrypter(tao::CryptoKey& ck) {
  return nullptr;
}

tao::CryptoKey* SignerToCryptoKey(tao::CryptoKey& ck) {
  return nullptr;
}

tao::CryptoKey* VerifierToCryptoKey(tao::CryptoKey& ck) {
  return nullptr;
}

tao::CryptoKey* CrypterToCryptoKey(tao::CryptoKey& ck) {
  return nullptr;
}

int SerializeECCKeyComponents(EC_KEY* ec_key, string* components[]) {
  byte buf[512];
  byte* pb = buf;

  int size_der = i2d_ECPrivateKey(ec_key, nullptr);
  size_der = i2d_ECPrivateKey(ec_key, (byte**)&pb);
  components[0]->assign((const char*)buf, size_der);
  return 1;
}

bool DeserializeECCKeyComponents(EC_KEY* ec_key, int n, string components[]) {
  byte buf[4096];
  memcpy(buf, components[0].data(), components[0].size());
  EC_KEY* ec = d2i_ECPrivateKey(&ec_key, (const byte**)&buf, components[0].size());
  return true;
}

bool GenerateCryptoKey(string& type, tao::CryptoKey* ck) {

  byte buf[128];

  // Fix this leak
  string *components[5];
  for (int j = 0; j < 5; j++) {
    components[j] = new(string);
  }

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
    int n = SerializeECCKeyComponents(ec_key, components);
    for (int i = 0; i < n; i++) {
        string* kc = ck->add_key_components();
        *kc = *components[i];
    }
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
    int n = SerializeECCKeyComponents(ec_key, components);
    for (int i = 0; i < n; i++) {
        string* kc = ck->add_key_components();
        *kc = *components[i];
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
    int n = SerializeECCKeyComponents(ec_key, components);
    for (int i = 0; i < n; i++) {
        string* kc = ck->add_key_components();
        *kc = *components[i];
    }
  } else if (type == string("aes128-ctr-hmacsha256")) {
    ch->set_key_purpose("crypting");
    int rc = RAND_bytes(buf, 48);
    unsigned long err = ERR_get_error();
    if (err != 1) {
      printf("GenerateKey: couldn't generate random bytes.\n");
      return false;
    }
    string* kc = ck->add_key_components();
    kc->assign((const char*)&buf[0], 16);
    kc = ck->add_key_components();
    kc->assign((const char*)&buf[16], 32);
  } else if (type == string("aes256-ctr-hmacsha384")) {
    ch->set_key_purpose("crypting");
    int rc = RAND_bytes(buf, 80);
    unsigned long err = ERR_get_error();
    if (err != 1) {
      printf("GenerateKey: couldn't generate random bytes.\n");
      return false;
    }
    string* kc = ck->add_key_components();
    kc->assign((const char*)&buf[0], 32);
    kc = ck->add_key_components();
    kc->assign((const char*)&buf[32], 48);
  } else if (type == string("aes256-ctr-hmacsha512")) {
    ch->set_key_purpose("crypting");
    int rc = RAND_bytes(buf, 96);
    unsigned long err = ERR_get_error();
    if (err != 1) {
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
  if (ch_->key_purpose() != string("verifying")) {
    return false;
  }
  if (ch_->key_type() == string("ecdsap256")) {
  } else if (ch_->key_type() == string("ecdsap384")) {
  } else if (ch_->key_type() == string("ecdsap521")) {
  } else {
    return false;
  }
  
  *out = in;
  return true;
}

bool Signer::Verify(string& in, string* out) {
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
  if (ch_->key_type() == string("ecdsap256")) {
  } else if (ch_->key_type() == string("ecdsap384")) {
  } else if (ch_->key_type() == string("ecdsap521")) {
  } else {
    return false;
  }
  
  *out = in;
  return true;
}

bool Verifier::Verify(string& in, string* out) {
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
  if (ch_->key_type() == string("ecdsap256-public")) {
  } else if (ch_->key_type() == string("ecdsap384-public")) {
  } else if (ch_->key_type() == string("ecdsap521-public")) {
  } else {
    return false;
  }
  
  *out = in;
  return true;
}

bool Crypter::Encrypt(string& in, string* out) {
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
  if (ch_->key_type() == string("aes128-ctr-hmacsha256")) {
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha384")) {
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha512")) {
  } else {
    return false;
  }
  
  *out = in;
  return true;
}

bool Crypter::Decrypt(string& in, string* out) {
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
  if (ch_->key_type() == string("aes128-ctr-hmacsha256")) {
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha384")) {
  } else if (ch_->key_type() == string("aes256-ctr-hmacsha512")) {
  } else {
    return false;
  }
  
  *out = in;
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

bool Protect(Crypter& crypter, string& in, string* out) {
  return crypter.Encrypt(in, out);
}

bool Unprotect(Crypter& crypter, string& in, string* out) {
  return crypter.Decrypt(in, out);
}

bool UniversalKeyName(Verifier* v, string* out) {
  return true;
}

bool KeyPrincipalBytes(Verifier* v, string* out) {
  // EVP_PKEY* evp_key = EVP_PKEY_new();
  // EVP_PKEY_set1_EC_KEY(evp_key, ec_key);
  // EC_POINT* pub_key = EC_KEY_get0_public_key(ec_key);
  // int size_der = i2d_PUBKEY(evp_key, (byte**)&buf);
  return true;
}
