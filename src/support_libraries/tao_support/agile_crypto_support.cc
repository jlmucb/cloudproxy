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

bool Signer::Sign(string& in, string* out) {
	*out = in;
	return true;
}

bool Signer::Verify(string& in, string* out) {
	*out = in;
	return true;
}

bool Verifier::Verify(string& in, string* out) {
	*out = in;
	return true;
}

bool Crypter::Encrypt(string& in, string* out) {
	*out = in;
	return true;
}

bool Crypter::Decrypt(string& in, string* out) {
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

#if 0
// For ec name, KeyBytes should be marshalled version of:
//   enum NamedEllipticCurve { PRIME256_V1 = 1;}
//   ECDSA_SHA_VerifyingKeyV1
//     Curve:    NamedEllipticCurve_PRIME256_V1.Enum(),
//     EcPublic: elliptic.Marshal(k.Curve, k.X, k.Y),
// Points marshalled as in section 4.3.6 of ANSI X9.62.

#pragma pack(push, 1)
struct ecMarshal {
  byte compress_;
  byte X_[32];
  byte Y_[32];
};
#pragma pack(pop)

bool GetKeyBytes(EVP_PKEY* pKey, string* bytes_out) {
  string key_bytes;
  byte key_hash[32];
  byte out[4096];
  byte* ptr = out;
  int n;

  if (pKey->type == EVP_PKEY_RSA) {
    RSA* rsa_key = EVP_PKEY_get1_RSA(pKey);
    // FIX: change to however Rsa keys are serialized internally.
    n = i2d_RSA_PUBKEY(rsa_key, &ptr);
    if (n <= 0) {
      printf("GetKeyBytes: Can't i2d RSA public key\n");
      return false;
    }
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, out, n);
    SHA256_Final(key_hash, &sha256);
    bytes_out->assign((const char*)key_hash, 32);
  } else if (pKey->type == EVP_PKEY_EC) {
    // Use get0?
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pKey);

    ecMarshal ec_params;
    ec_params.compress_ = 4;
    BN_CTX* bn_ctx = BN_CTX_new();
    if (bn_ctx == nullptr) {
      printf("Can't get BN_CTX\n");
      return false;
    }
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    string vk_proto;
    string ec_params_str;

    // Get curve, X and Y
    const EC_POINT* public_point = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    if (1 != EC_POINT_get_affine_coordinates_GFp(group, public_point, x, y, bn_ctx)) {
      printf("Can't EC_POINT_get_affine_coordinates_GFp\n");
      return false;
    }
    string x_str;
    string y_str;
    if (!BN_to_string(*x, &x_str)) {
      printf("Can't convert x\n");
      return false;
    }
    if (!BN_to_string(*y, &y_str)) {
      printf("Can't convert y\n");
      return false;
    }
    memcpy(ec_params.X_, (byte*)x_str.data(), x_str.size());
    memcpy(ec_params.Y_, (byte*)y_str.data(), y_str.size());
    BN_CTX_free(bn_ctx); BN_free(x); BN_free(y);

    // set and marshal verifying key
    tao::ECDSA_SHA_VerifyingKey_v1 vk;
    vk.set_curve(tao::NamedEllipticCurve::PRIME256_V1);
    ec_params_str.assign((const char*) &ec_params, sizeof(ec_params));
    vk.set_ec_public(ec_params_str);
    vk.SerializeToString(&vk_proto);

    // set and marshal cryptokey
    tao::CryptoKey ck;
    ck.set_version(ck.version());  // crypto version
    ck.set_purpose(tao::CryptoKey_CryptoPurpose::CryptoKey_CryptoPurpose_VERIFYING);
    ck.set_algorithm(tao::CryptoKey_CryptoAlgorithm::CryptoKey_CryptoAlgorithm_ECDSA_SHA);
    ck.set_key(vk_proto);
    ck.SerializeToString(&key_bytes);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key_bytes.data(), key_bytes.size());
    SHA256_Final(key_hash, &sha256);
    bytes_out->assign((const char*)key_hash, 32);
  } else {
    printf("GetKeyBytes: unsupported key type.\n");
    return false;
  }
  return true;
}
#endif
