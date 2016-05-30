// Copyright 2015 Google Corporation, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// File: openssl_helpers.cc

// standard buffer size

#ifndef __OPENSSL_HELPERS__
#define __OPENSSL_HELPERS__
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include "taosupport.pb.h"

#include <string>
#include <memory>

using std::string;

#define AESBLKSIZE 16

#ifndef byte
typedef unsigned char byte;
typedef long long unsigned int64;
#endif

void PrintBytes(int n, byte* in);
bool ReadFile(string& file_name, string* out);
bool WriteFile(string& file_name, string& in);

bool SerializePrivateKey(string& key_type, EVP_PKEY* key, string* out_buf);
bool DeserializePrivateKey(string& in_buf, string* key_type, EVP_PKEY** key);

EVP_PKEY* GenerateKey(string& keyType, int keySize);
bool GenerateX509CertificateRequest(string& key_type, string& common_name,
            EVP_PKEY* subjectKey, bool sign_request, X509_REQ* req);
bool SignX509Certificate(EVP_PKEY* signingKey, bool f_isCa, bool f_canSign,
                         string& signing_issuer,string& keyUsage,
                         string& extendedKeyUsage,
                         int64 duration, EVP_PKEY* signedKey,
                         X509_REQ* req, bool verify_req_sig, X509* cert);
bool VerifyX509CertificateChain(X509* cacert, X509* cert);

BIGNUM* bin_to_BN(int len, byte* buf);
string* BN_to_bin(BIGNUM& n);
void XorBlocks(int size, byte* in1, byte* in2, byte* out);
bool AesCtrCrypt(int key_size_bits, byte* key, int size,
                 byte* in, byte* out);
bool AesCFBEncrypt(byte* key, int in_size, byte* in, int iv_size, byte* iv,
                   int* out_size, byte* out);
bool AesCFBDecrypt(byte* key, int in_size, byte* in, int iv_size, byte* iv,
                   int* out_size, byte* out);

#define SSL_NO_SERVER_VERIFY_NO_CLIENT_AUTH 0
#define SSL_NO_SERVER_VERIFY_NO_CLIENT_VERIFY 1
#define SSL_SERVER_VERIFY_NO_CLIENT_VERIFY 2
#define SSL_SERVER_VERIFY_CLIENT_VERIFY 3

int SslMessageRead(SSL* ssl, int size, byte* buf);
int SslMessageWrite(SSL* ssl, int size, byte* buf);
int SslRead(SSL* ssl, int size, byte* buf);
int SslWrite(SSL* ssl, int size, byte* buf);

class SslChannel {
private:
  bool server_role_;
  int fd_;
  SSL_CTX *ssl_ctx_;
  SSL* ssl_;
  X509* peer_cert_;
  X509_STORE *store_;
  EVP_PKEY* private_key_;
public:
  SslChannel();
  ~SslChannel();

  int CreateClientSocket(string& addr, string& port);
  int CreateServerSocket(string& addr, string& port);
  bool InitClientSslChannel(string& network, string& address, string& port,
                                X509* caCert, X509* programCert,
                                string& keyType, EVP_PKEY* key,
                                int verify = SSL_SERVER_VERIFY_CLIENT_VERIFY);
  bool InitServerSslChannel(string& network, string& address, string& port,
                                X509* caCert, X509* programCert,
                                string& keyType, EVP_PKEY* key,
                                int verify = SSL_SERVER_VERIFY_CLIENT_VERIFY);
  bool ServerLoop(void(*Handle)(SslChannel*,  SSL*, int));
  void Close();
  SSL* GetSslChannel() {return ssl_;};

  X509* GetPeerCert();
};

char ValueToHex(byte x);
byte HexToValue(char x);

string* ByteToHexLeftToRight(int, byte*);
string* ByteToHexRightToLeft(int, byte*);
int HexToByteLeftToRight(char*, int, byte*);
int HexToByteRightToLeft(char*, int, byte*);

#endif

