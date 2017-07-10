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

bool Protect(Crypter& crypter, string& in, string* out);

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
  return true;
}
