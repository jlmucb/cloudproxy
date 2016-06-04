#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <helpers.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <string>
#include <thread>

#include <taosupport.pb.h>

using std::string;
using std::unique_ptr;
using std::thread;
using std::vector;

//
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
// File: helpers.cc


void PrintBytes(int n, byte* in) {
  for (int i = 0; i < n; i++) printf("%02x", in[i]);
}

bool ReadFile(string& file_name, string* out) {
  struct stat file_info;
  int k = stat(file_name.c_str(), &file_info);
  if (k != 0)
    return false;
  unique_ptr<byte> buf(new byte[file_info.st_size]);
  int fd = open(file_name.c_str(), O_RDONLY);
  if (fd < 0)
    return false;
  size_t n = read(fd, buf.get(), file_info.st_size);
  out->assign((const char*)buf.get(), n);
  close(fd);
  return true;
}

bool WriteFile(string& file_name, string& in) {
  int fd = creat(file_name.c_str(), S_IRWXU | S_IRWXG);
  if (fd < 0)
    return false;
  int n = write(fd, (byte*)in.data(), in.size());
  close(fd);
  return n > 0;
  return true;
}

bool SerializePrivateKey(string& key_type, EVP_PKEY* key, string* out_buf) {
  taosupport::PrivateKeyMessage msg;

  if (key_type == "RSA") {
    RSA* rsa_key = EVP_PKEY_get1_RSA(key);
    msg.set_allocated_rsa_key(new taosupport::RsaPrivateKeyMessage());
    string* m_str = BN_to_bin(*rsa_key->n);
    msg.mutable_rsa_key()->set_m(*m_str);
    string* e_str = BN_to_bin(*rsa_key->e);
    msg.mutable_rsa_key()->set_e(*e_str);
    string* d_str = BN_to_bin(*rsa_key->d);
    msg.mutable_rsa_key()->set_d(*d_str);
    msg.set_key_type("RSA");
  } else if (key_type == "ECC") {
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key);
    msg.set_allocated_ec_key(new taosupport::EcPrivateKeyMessage());
    byte out[4096];
    byte* ptr = out;
    int n = i2d_ECPrivateKey(ec_key, &ptr);
    if (n <= 0) {
      printf("Can't i2d ECC private key\n");
      return false;
    }
    msg.mutable_ec_key()->set_der_blob((void*)out, (size_t)n);
    msg.set_key_type("ECC");
  } else {
    printf("SerializePrivateKey: Unknown key type\n");
    return false;
  }

  if (!msg.SerializeToString(out_buf)) {
    return false;
  }
  return true;
}

bool DeserializePrivateKey(string& in_buf, string* key_type, EVP_PKEY** key) {
  taosupport::PrivateKeyMessage msg;

  if (!msg.ParseFromString(in_buf)) {
    return false;
  }
  key_type->assign(msg.key_type());
  if (msg.key_type() == "RSA") {
    if (!msg.has_rsa_key()) {
      return false;
    }
    RSA* rsa_key = RSA_new();
    if (msg.rsa_key().has_m())
      rsa_key->n = bin_to_BN(msg.rsa_key().m().size(), (byte*)msg.rsa_key().m().data());
    if (msg.rsa_key().has_e())
      rsa_key->e = bin_to_BN(msg.rsa_key().e().size(), (byte*)msg.rsa_key().e().data());
    if (msg.rsa_key().has_d())
      rsa_key->d = bin_to_BN(msg.rsa_key().d().size(), (byte*)msg.rsa_key().d().data());
      EVP_PKEY* pKey = new EVP_PKEY();
      EVP_PKEY_assign_RSA(pKey, rsa_key);
      *key = pKey;
  } else if (msg.key_type() == "ECC") {
    if (!msg.has_ec_key()) {
      return false;
    }
    const byte* ptr = (byte*)msg.ec_key().der_blob().data();
    EC_KEY* ec_key = d2i_ECPrivateKey(nullptr, &ptr,
                                      msg.ec_key().der_blob().size());
    if (ec_key == nullptr) {
      printf("Can't i2d ECC private key\n");
      return false;
    }
    EVP_PKEY* pKey = new EVP_PKEY();
    EVP_PKEY_assign_EC_KEY(pKey, ec_key);
    *key = pKey;
  } else {
    printf("DeserializePrivateKey: Unknown key type\n");
    return false;
  }
  return true;
}

// standard buffer size
#define MAX_SIZE_PARAMS 4096

void PrintPrivateRSAKey(RSA& key) {
  if (key.n != nullptr) {
    printf("\nModulus: \n");
    BN_print_fp(stdout, key.n);
    printf("\n");
  }
  if (key.e != nullptr) {
    printf("\ne: \n");
    BN_print_fp(stdout, key.e);
    printf("\n");
  }
  if (key.d != nullptr) {
    printf("\nd: \n");
    BN_print_fp(stdout, key.d);
    printf("\n");
  }
  if (key.p != nullptr) {
    printf("\np: \n");
    BN_print_fp(stdout, key.p);
    printf("\n");
  }
  if (key.q != nullptr) {
    printf("\nq: \n");
    BN_print_fp(stdout, key.q);
    printf("\n");
  }
#if 0
  if (key.dmp1 != nullptr) {
    printf("\ndmp1: \n");
    BN_print_fp(stdout, key.dmp1);
    printf("\n");
  }
  if (key.dmq1 != nullptr) {
    printf("\ndmq1: \n");
    BN_print_fp(stdout, key.dmq1);
    printf("\n");
  }
  if (key.iqmp != nullptr) {
    printf("\niqmp: \n");
    BN_print_fp(stdout, key.iqmp);
    printf("\n");
  }
#endif
}

BIGNUM* bin_to_BN(int len, byte* buf) {
  BIGNUM* bn = BN_bin2bn(buf, len, nullptr);
  return bn;
}

string* BN_to_bin(BIGNUM& n) {
  byte buf[MAX_SIZE_PARAMS];

  int len = BN_bn2bin(&n, buf);
  return new string((const char*)buf, len);
}

EVP_PKEY* GenerateKey(string& keyType, int keySize) {
  EVP_PKEY* pKey = EVP_PKEY_new();
  if (pKey == nullptr) {
    return nullptr;
  }
  if (keyType == "RSA") {
    RSA* rsa_key = RSA_generate_key(keySize, 0x010001ULL, nullptr, nullptr);
    if (rsa_key == nullptr) {
      printf("GenerateKey: couldn't generate RSA key.\n");
      return nullptr;
    }
    EVP_PKEY_assign_RSA(pKey, rsa_key);
    pKey->type = EVP_PKEY_RSA;
  } else if (keyType == "ECC") {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    if (ec_key == nullptr) {
      printf("GenerateKey: couldn't generate ECC program key (1).\n");
      return nullptr;
    }
    if (1 != EC_KEY_generate_key(ec_key)) {
      printf("GenerateKey: couldn't generate ECC program key(2).\n");
      return nullptr;
    }
    EVP_PKEY_assign_EC_KEY(pKey, ec_key);
    pKey->type = EVP_PKEY_EC;
  } else {
    printf("GenerateKey: unsupported key type.\n");
    return nullptr;
  }
  return pKey;
}

class extEntry {
public:
  char* key_;
  char* value_;

  extEntry(const char* k, const char* v);
  extEntry();
  char* getKey();
  char* getValue();
};

extEntry::extEntry(const char* k, const char* v) {
  key_ = (char*)strdup(k);
  value_ = (char*)strdup(v);
}

extEntry::extEntry() {
  key_ = nullptr;
  value_ = nullptr;
}

char* extEntry::getKey() {
  return key_;
}

char* extEntry::getValue() {
  return value_;
}

bool addExtensionsToCert(int num_entry, extEntry** entries, X509* cert) {
  // add extensions
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  for (int i = 0; i < num_entry; i++) {
    if (entries[i]->getValue() == nullptr || strlen(entries[i]->getValue()) ==0)
      continue;
    int nid = OBJ_txt2nid(entries[i]->getKey());
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, entries[i]->getValue());
    if (ext == 0) {
      printf("Bad ext_conf %d\n", i);
      printf("ERR: %s\n", ERR_lib_error_string(ERR_get_error()));
      return false;
    }
    if (!X509_add_ext(cert, ext, -1)) {
      printf("Bad add ext %d\n", i);
      printf("ERR: %s\n", ERR_lib_error_string(ERR_get_error()));
      return false;
    }
    X509_EXTENSION_free(ext);
  }
  return true;
}

bool GenerateX509CertificateRequest(string& key_type, string& common_name,
            EVP_PKEY* subjectKey, bool sign_request, X509_REQ* req) {
  X509_NAME* subject = X509_NAME_new();
  X509_REQ_set_version(req, 2L);
  if (subject == nullptr) {
    printf("Can't alloc x509 name\n");
    return false;
  }
  if (common_name.size() > 0) {
    int nid = OBJ_txt2nid("CN");
    X509_NAME_ENTRY* ent = X509_NAME_ENTRY_create_by_NID(nullptr, nid,
        MBSTRING_ASC, (byte*)common_name.c_str(), -1);
    if (ent == nullptr) {
      printf("X509_NAME_ENTRY return is null, nid: %d\n", nid);
      return false;
    }
    if (X509_NAME_add_entry(subject, ent, -1, 0) != 1) {
      printf("Can't add name ent\n");
      return false;
    }
  }
  // TODO: do the foregoing for the other name components
  if (X509_REQ_set_subject_name(req, subject) != 1)  {
    printf("Can't set x509 subject\n");
    return false;
  }

  // fill key parameters in request
  if (sign_request) {
    const EVP_MD* digest = EVP_sha256();
    if (!X509_REQ_sign(req, subjectKey, digest)) {
      printf("Sign request fails\n");
      printf("ERR: %s\n", ERR_lib_error_string(ERR_get_error()));
    }
  }
  if (X509_REQ_set_pubkey(req, subjectKey) ==0) {
      printf("X509_REQ_set_pubkey failed\n");
  }
  return true;
}

bool SignX509Certificate(EVP_PKEY* signingKey, bool f_isCa,
                         bool f_canSign, string& signing_issuer,
                         string& keyUsage, string& extendedKeyUsage,
                         int64 duration, EVP_PKEY* signedKey,
                         X509_REQ* req, bool verify_req_sig, X509* cert) {
  if (signedKey == nullptr)
    signedKey = X509_REQ_get_pubkey(req);
  if (signedKey == nullptr) {
    printf("Can't get pubkey\n");
    return false;
  }

  if (verify_req_sig) {
    if (X509_REQ_verify(req, signedKey) != 1) {
      printf("Req does not verify\n");
      return false;
    }
  }
  
  uint64_t serial = 1;
  const EVP_MD* digest = EVP_sha256();
  X509_NAME* name;
  X509_set_version(cert, 2L);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);

  name = X509_REQ_get_subject_name(req);
  if (X509_set_subject_name(cert, name) != 1) {
    printf("Can't set subject name\n");
    return false;
  }
  if (X509_set_pubkey(cert, signedKey) != 1) {
    printf("Can't set pubkey\n");
    return false;
  }
  if (!X509_gmtime_adj(X509_get_notBefore(cert), 0)) {
    printf("Can't adj notBefore\n");
    return false;
  }
  if (!X509_gmtime_adj(X509_get_notAfter(cert), duration)) {
    printf("Can't adj notAfter\n");
    return false;
  }
  X509_NAME* issuer = X509_NAME_new();
  int nid = OBJ_txt2nid("CN");
  X509_NAME_ENTRY* ent = X509_NAME_ENTRY_create_by_NID(nullptr, nid,
      MBSTRING_ASC, (byte*)signing_issuer.c_str(), -1);
  if (X509_NAME_add_entry(issuer, ent, -1, 0) != 1) {
    printf("Can't add issuer name ent: %s, %ld\n",
           signing_issuer.c_str(), (long unsigned)ent);
    printf("ERR: %s\n", ERR_lib_error_string(ERR_get_error()));
    return false;
  }
  if (X509_set_issuer_name(cert, issuer) != 1) {
    printf("Can't set issuer name\n");
    return false;
  }

  // Add extensions which should be
  //    X509v3 extensions:
  //        X509v3 Key Usage: critical
  //            Key Agreement, Certificate Sign
  //        X509v3 Extended Key Usage: 
  //            TLS Web Server Authentication, TLS Web Client Authentication
  //        X509v3 Basic Constraints: critical
  //            CA:TRUE
  extEntry* entries[128];
  int n = 0;
  if (f_isCa) {
    entries[n++] = new extEntry("basicConstraints", "critical,CA:TRUE");
  }
  entries[n++] = new extEntry("keyUsage", keyUsage.c_str());
  entries[n++] = new extEntry("extendedKeyUsage", extendedKeyUsage.c_str());
  if (!addExtensionsToCert(n, entries, cert)) {
    printf("Can't add extensions\n");
    return false;
  }

  if (!X509_sign(cert, signingKey, digest)) {
    printf("Bad PKEY type\n");
    return false;
  }
  return true;
}

void XorBlocks(int size, byte* in1, byte* in2, byte* out) {
  int i;

  for (i = 0; i < size; i++)
    out[i] = in1[i] ^ in2[i];
}

bool AesCtrCrypt(int key_size_bits, byte* key, int size,
                 byte* in, byte* out) {
  AES_KEY ectx;
  uint64_t ctr[2] = {0ULL, 0ULL};
  byte block[32];

  if (key_size_bits != 128) {
    return false;
  }
  
  AES_set_encrypt_key(key, 128, &ectx);
  while (size > 0) {
    ctr[1]++;
    AES_encrypt((byte*)ctr, block, &ectx);
    XorBlocks(16, block, in, out);
    in += 16;
    out += 16;
    size -= 16;
  }
  return true;
}

#define AESBLKSIZE 16

bool AesCFBEncrypt(byte* key, int in_size, byte* in, int iv_size, byte* iv,
                   int* out_size, byte* out) {
  byte last_cipher[32];
  byte cipher_block[32];
  int size = 0;
  int current_size;

  AES_KEY ectx;
  AES_set_encrypt_key(key, 128, &ectx);

  // Don't write iv, called already knows it
  if(iv_size != AESBLKSIZE) return false;
  memcpy(last_cipher, iv, AESBLKSIZE);

  while (in_size > 0) {
    if ((size + AESBLKSIZE) > *out_size) return false; 
    // C[0] = IV, C[i] = P[i] ^ E(K, C[i-1])
    AES_encrypt(last_cipher, cipher_block, &ectx);
    if (in_size >= AESBLKSIZE)
      current_size = AESBLKSIZE;
    else
      current_size = in_size;
    XorBlocks(AESBLKSIZE, cipher_block, in, last_cipher);
    memcpy(out, last_cipher, current_size);
    out += current_size;
    size += current_size;
    in += current_size;
    in_size -= current_size;
  }
  *out_size = size;
  return true;
}

bool AesCFBDecrypt(byte* key, int in_size, byte* in, int iv_size, byte* iv,
                   int* out_size, byte* out) {
  byte last_cipher[32];
  byte cipher_block[32];
  int size = 0;
  int current_size;

  AES_KEY ectx;
  AES_set_encrypt_key(key, 128, &ectx);

  // Don't write iv, called already knows it
  if(iv_size != AESBLKSIZE) return false;
  memcpy(last_cipher, iv, AESBLKSIZE);

  while (in_size > 0) {
    if ((size + AESBLKSIZE) > *out_size) return false; 
    // P[i] = C[i] ^ E(K, C[i-1])
    AES_encrypt(last_cipher, cipher_block, &ectx);
    if (in_size >= AESBLKSIZE)
      current_size = AESBLKSIZE;
    else
      current_size = in_size;
    XorBlocks(current_size, cipher_block, in, out);
    memcpy(last_cipher, in, current_size);
    out += current_size;
    size += current_size;
    in += current_size;
    in_size -= current_size;
  }
  *out_size = size;
  return true;
}

bool VerifyX509CertificateChain(X509* cacert, X509* cert) {
  X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
  X509_STORE *store = X509_STORE_new();
  X509_STORE_add_cert(store, cacert);
  // int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain);
  X509_STORE_CTX_init(store_ctx, store, cacert, nullptr);
  int ret = X509_verify_cert(store_ctx);
  if (ret <= 0)
    printf("Error: %s\n", X509_verify_cert_error_string(store_ctx->error));
  return ret;
}

SslChannel::SslChannel() {
  fd_ = -1;
  ssl_ctx_ = nullptr;
  ssl_ = nullptr;
  peer_cert_ = nullptr;
  store_ = nullptr;
  private_key_ = nullptr;
}

SslChannel::~SslChannel() {
  if (fd_ > 0) {
    close(fd_);
  }
  fd_ = -1;
  // clear private_key_;
#if 0
  // Doesn't need to be freed, context free takes care of it.
  if (ssl_ != nullptr) {
    SSL_free(ssl_);
  }
  ssl_ = nullptr;
#endif
  if (peer_cert_ != nullptr) {
    X509_free(peer_cert_);
  }
  peer_cert_ = nullptr;
  if (ssl_ctx_ != nullptr) {
    SSL_CTX_free(ssl_ctx_);
  }
  ssl_ctx_ = nullptr;
  if (store_ != nullptr) {
    X509_STORE_free(store_);
  }
  store_ = nullptr;
}

int SslChannel::CreateServerSocket(string& address, string& port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in dest_addr;
  uint16_t s_port = atoi(port.c_str());
  memset((byte*)&dest_addr, 0, sizeof(dest_addr));

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(s_port);
  dest_addr.sin_addr.s_addr = INADDR_ANY;
  inet_aton(address.c_str(), &dest_addr.sin_addr);

  if (bind(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
    printf("Unable to bind\n");
    return -1;
  }

  if (listen(sockfd, 1) < 0) {
    printf("Unable to listen\n");
    return -1;
  }
  return sockfd;
}


int SslChannel::CreateClientSocket(string& addr, string& port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in dest_addr;
  uint16_t s_port = atoi(port.c_str());
  memset((byte*)&dest_addr, 0, sizeof(dest_addr));

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(s_port);
  dest_addr.sin_addr.s_addr = INADDR_ANY;
  inet_aton(addr.c_str(), &dest_addr.sin_addr);

  if (connect(sockfd, (struct sockaddr *) &dest_addr,
              sizeof(struct sockaddr)) == -1) {
    printf("Error: Cannot connect to host\n");
    return -1;
  }
  return sockfd;
}

bool SslChannel::InitServerSslChannel(string& network, string& address,
                string& port, X509* policyCert, X509* programCert,
                string& keyType, EVP_PKEY* privateKey, int verify) {
   SSL_library_init();
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

  // I'm a server.
  server_role_ = true;

  if (privateKey == nullptr) {
    printf("Private key is null.\n");
    return false;
  }

  // Create socket and contexts.
  fd_ = CreateServerSocket(address, port);
  if(fd_ <= 0) {
    printf("CreateServerSocket failed.\n");
    return false;
  }

  ssl_ctx_ = SSL_CTX_new(TLSv1_2_server_method());
  if (ssl_ctx_ == nullptr) {
    printf("SSL_CTX_new failed(server).\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  SSL_CTX_clear_extra_chain_certs(ssl_ctx_);
  private_key_ = privateKey;
  SSL_CTX_use_certificate(ssl_ctx_, programCert);
  if (EVP_PKEY_id(private_key_) == EVP_PKEY_EC) {
    if (!SSL_CTX_set_tmp_ecdh(ssl_ctx_, EVP_PKEY_get1_EC_KEY(private_key_))) {
       printf("SSL_CTX_set_tmp_ecdh failed.\n");
       return false;
    }
    SSL_CTX_set_options(ssl_ctx_, SSL_OP_SINGLE_ECDH_USE);
  }
  if(SSL_CTX_use_PrivateKey(ssl_ctx_, private_key_) <= 0) {
    printf("SSL_CTX_use_PrivateKey failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  // Setup verification stuff.
  switch(verify) {
    case SSL_NO_SERVER_VERIFY_NO_CLIENT_AUTH:
    case SSL_NO_SERVER_VERIFY_NO_CLIENT_VERIFY:
    case SSL_SERVER_VERIFY_NO_CLIENT_VERIFY:
      SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
      SSL_CTX_set_verify_depth(ssl_ctx_, 3);
      break;
    case SSL_SERVER_VERIFY_CLIENT_VERIFY:
      SSL_CTX_add_extra_chain_cert(ssl_ctx_, programCert);
      SSL_CTX_add_extra_chain_cert(ssl_ctx_, policyCert);
      store_ = X509_STORE_new();
      if (store_ == nullptr) {
        printf("X509_STORE_new failed.\n");
        return false;
      }
      X509_STORE_add_cert(store_, policyCert);
      SSL_CTX_set_cert_store(ssl_ctx_, store_);
      SSL_CTX_set_verify(ssl_ctx_,
          SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
      SSL_CTX_set_verify_depth(ssl_ctx_, 3);
      break;
    default:
      printf("Unknown verification mode.\n");
      return false;
  }
  return true;
}

bool SslChannel::InitClientSslChannel(string& network, string& address,
                string& port, X509* policyCert, X509* programCert,
                string& keyType, EVP_PKEY* privateKey, int verify) {
   SSL_library_init();
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

  // I'm a client.
  server_role_ = false;

  // Create socket and contexts.
  fd_ = CreateClientSocket(address, port);
  if(fd_ <= 0) {
    printf("CreateClientSocket failed.\n");
    return false;
  }

  ssl_ctx_ = SSL_CTX_new(TLSv1_2_client_method());
  if (ssl_ctx_ == nullptr) {
    printf("SSL_CTX_new failed(client).\n");
    return false;
  }
  SSL_CTX_clear_extra_chain_certs(ssl_ctx_);
  if (privateKey == nullptr) {
    printf("Private key is null\n");
    return false;
  }
  private_key_ = privateKey;

  // Setup verification stuff.
  switch(verify) {
    case SSL_NO_SERVER_VERIFY_NO_CLIENT_AUTH:
      SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
      SSL_CTX_set_verify_depth(ssl_ctx_, 3);
      break;
    case SSL_NO_SERVER_VERIFY_NO_CLIENT_VERIFY:
    case SSL_SERVER_VERIFY_NO_CLIENT_VERIFY:
    case SSL_SERVER_VERIFY_CLIENT_VERIFY:
      if (privateKey == nullptr) {
        printf("Private key is null\n");
        return false;
      }
      if (EVP_PKEY_id(private_key_) == EVP_PKEY_EC) {
        if (!SSL_CTX_set_tmp_ecdh(ssl_ctx_,
                EVP_PKEY_get1_EC_KEY(private_key_))) {
          printf("SSL_CTX_set_tmp_ecdh failed.\n");
          return false;
        }
        SSL_CTX_set_options(ssl_ctx_, SSL_OP_SINGLE_ECDH_USE);
      }
      if(SSL_CTX_use_PrivateKey(ssl_ctx_, private_key_) <= 0) {
        printf("SSL_CTX_use_PrivateKey failed.\n");
        ERR_print_errors_fp(stderr);
        return false;
      }
      SSL_CTX_use_certificate(ssl_ctx_, programCert);
      SSL_CTX_add_extra_chain_cert(ssl_ctx_, programCert);
      SSL_CTX_add_extra_chain_cert(ssl_ctx_, policyCert);
      store_ = X509_STORE_new();
      if (store_ == nullptr) {
        printf("X509_STORE_new failed.\n");
        return false;
      }
      X509_STORE_add_cert(store_, policyCert);
      SSL_CTX_set_cert_store(ssl_ctx_, store_);
      SSL_CTX_set_verify(ssl_ctx_,
        SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
      SSL_CTX_set_verify_depth(ssl_ctx_, 3);
      if (verify == SSL_NO_SERVER_VERIFY_NO_CLIENT_VERIFY)
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr); 
      break;
    default:
      printf("Unknown verification mode.\n");
      return false;
  }

  ssl_ = SSL_new(ssl_ctx_);
  if (ssl_ == nullptr) {
    printf("SSL_new failed(client).\n");
    return false;
  }

  SSL_set_fd(ssl_, fd_);
  SSL_set_connect_state(ssl_);

  // Connect.
  if (SSL_connect(ssl_) != 1) {
    printf("SSL_connect failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  peer_cert_ = SSL_get_peer_certificate(ssl_);
  return true;
}

bool SslChannel::ServerLoop(void(*server_loop)(SslChannel*,  SSL*, int)) {
  bool fContinue = true;
  printf("ServerLoop\n");

  while(fContinue) {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    memset((byte*)&addr, 0, len);

    int client = accept(fd_, (struct sockaddr*)&addr, &len);
    if (client < 0) {
      printf("Unable to accept\n");
      printf("ERR: %s\n", ERR_lib_error_string(ERR_get_error()));
      continue;
    }

    SSL* ssl = SSL_new(ssl_ctx_);
    if (private_key_ == nullptr) {
      printf("private_key_ is null.\n");
      return false;
    }
    SSL_set_fd(ssl, client);
    SSL_set_accept_state(ssl);
    if (SSL_accept(ssl) <= 0) {
      printf("Unable to ssl_accept\n");
      ERR_print_errors_fp(stderr);
      continue;
    } 
    server_loop(this, ssl, client);
    // thread t(server_loop, this, ssl, client);
  }
  return true;
}

void SslChannel::Close() {
  if (fd_ > 0) {
    close(fd_);
  }
  fd_ = -1;
  if (ssl_ != nullptr) {
    SSL_free(ssl_);
  }
  ssl_ = nullptr;
  if (peer_cert_ != nullptr) {
    X509_free(peer_cert_);
  }
  peer_cert_ = nullptr;
  if (ssl_ctx_ != nullptr) {
    SSL_CTX_free(ssl_ctx_);
  }
  ssl_ctx_ = nullptr;
  if (store_ != nullptr) {
    X509_STORE_free(store_);
  }
  store_ = nullptr;
}

X509* SslChannel::GetPeerCert() {
  return peer_cert_;
}

int SslMessageRead(SSL* ssl, int size, byte* buf) {
  byte new_buf[8192];
  int tmp_size = SslRead(ssl, size, new_buf);
  if (tmp_size <= 0)
    return tmp_size;
  int real_size = __builtin_bswap32(*((int*)new_buf));
  if (tmp_size == sizeof(int)) {
    return SslRead(ssl, real_size, buf);
  }
  memcpy(buf, &new_buf[4], real_size);
  return real_size;
}

int SslMessageWrite(SSL* ssl, int size, byte* buf) {
  // write 32 bit size and buffer
  int big_endian_size = __builtin_bswap32(size);
  byte new_buf[4096];
  memcpy(new_buf, (byte*)&big_endian_size, sizeof(int));
  memcpy(&new_buf[sizeof(int)], buf, size);
  return SslWrite(ssl, size + sizeof(int), new_buf) - sizeof(int);
}

int SslRead(SSL* ssl, int size, byte* buf) {
  return SSL_read(ssl, buf, size);
}

int SslWrite(SSL* ssl, int size, byte* buf) {
  return SSL_write(ssl, buf, size);
}

// TODO: consider using std::to_string
int NumHexInBytes(int size, byte* in) { return 2 * size; }

int NumBytesInHex(char* in) {
  if (in == nullptr)
    return -1;
  int len = strlen(in);
  return ((len + 1) / 2);
}

char ValueToHex(byte x) {
  if (x >= 0 && x <= 9) {
    return x + '0';
  } else if (x >= 10 && x <= 15) {
    return x - 10 + 'a';
  } else {
    return ' ';
  }
}

byte HexToValue(char x) {
  if (x >= '0' && x <= '9') {
    return x - '0';
  } else if (x >= 'a' && x <= 'f') {
    return x + 10 - 'a';
  } else {
    return 0;
  }
}

string* ByteToHexLeftToRight(int size, byte* in) {
  if (in == nullptr)
    return nullptr;
  int n = NumHexInBytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();
  byte a, b;

  while (size > 0) {
    a = (*in) >> 4;
    b = (*in) & 0xf;
    in++;
    *(str++) = ValueToHex(a);
    *(str++) = ValueToHex(b);
    size--;
  }
  return out;
}

int HexToByteLeftToRight(char* in, int size, byte* out) {
  if (in == nullptr)
    return -1;
  int n = NumBytesInHex(in);
  int m = strlen(in);
  byte a, b;

  if (n > size) {
    return -1;
  }
  while (m > 0) {
    a = HexToValue(*(in++));
    b = HexToValue(*(in++));
    *(out++) = (a << 4) | b;
    m -= 2;
  }
  return n;
}

string* ByteToHexRightToLeft(int size, byte* in) {
  if (in == nullptr)
    return nullptr;
  int n = NumHexInBytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();
  byte a, b;

  in += size - 1;
  while (size > 0) {
    a = (*in) >> 4;
    b = (*in) & 0xf;
    in--;
    *(str++) = ValueToHex(a);
    *(str++) = ValueToHex(b);
    size--;
  }
  return out;
}

int HexToByteRightToLeft(char* in, int size, byte* out) {
  if (in == nullptr) {
    return -1;
  }
  int n = NumBytesInHex(in);
  int m = strlen(in);
  byte a, b;

  out += n - 1;
  if (m < 0) {
    return -1;
  }
  while (m > 0) {
    a = HexToValue(*(in++));
    b = HexToValue(*(in++));
    *(out--) = (a << 4) | b;
    m -= 2;
  }
  return n;
}
