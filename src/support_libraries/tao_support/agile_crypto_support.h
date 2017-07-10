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
#include <stdlib.h>

#ifndef __AGILE_CRYPTO_SUPPORT_H__
#define __AGILE_CRYPTO_SUPPORT_H__

#include "taosupport.pb.h"
#include "keys.pb.h"

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>
#include <list>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef byte
typedef unsigned char byte;
#endif

using std::string;
using std::unique_ptr;

class Signer {
public:
  tao::CryptoHeader* ch_;
  EVP_PKEY* sk_;

  bool Sign(string& in, string* out);
  bool Verify(string& in, string* out);
};

class Verifier {
public:
  tao::CryptoHeader* ch_;
  EVP_PKEY* sk_;

  bool Verify(string& in, string* out);
};

tao::CryptoKey* CrypterToCryptoKey(tao::CryptoKey& ck) {
  return nullptr;
}

class Crypter {
public:
  tao::CryptoHeader* ch_;
  string* encryptingKeyBytes_;
  string* hmacKeyBytes_;

  bool Encrypt(string& in, string* out);
  bool Decrypt(string& in, string* out);
};

class Deriver {
  tao::CryptoHeader* ch_;
  string* secretBytes_;

  bool Derive(string& salt, string& context, string& in,  string* out);
};

Verifier* CryptoKeyToVerifier(tao::CryptoKey& ck);
Signer* CryptoKeyToSigner(tao::CryptoKey& ck);
Crypter* CryptoKeyToCrypter(tao::CryptoKey& ck);
tao::CryptoKey* SignerToCryptoKey(tao::CryptoKey& ck);
tao::CryptoKey* VerifierToCryptoKey(tao::CryptoKey& ck);

bool Protect(Crypter& crypter, string& in, string* out);
bool Unprotect(Crypter& crypter, string& in, string* out);
bool UniversalKeyName(Verifier* v, string* out);

void PrintBytes(int size, byte* buf);
bool ReadFile(string& file_name, string* out);
bool WriteFile(string& file_name, string& in);
#endif


