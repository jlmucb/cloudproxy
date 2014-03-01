//
//  File: modesandpadding.cpp
//  Description:  modes and padding functions
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Some contributions (c) John Manferdelli.  All rights reserved.
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

#include "common.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "keys.h"
#include "modesandpadding.h"
#ifdef NOAESNI
#include "aes.h"
#else
#include "aesni.h"
#endif
#include "sha256.h"

#include <string.h>

//
//  Headers with DER encoding
//
byte md5_header[] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                     0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
byte sha1_header[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
                      0x1a, 0x05, 0x00, 0x04, 0x14};
byte sha256_header[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                      0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
                      0x20};
byte sha384_header[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                        0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
                        0x30};
byte sha512_header[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                        0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
                        0x40};

// ---------------------------------------------------------------------------------

//  Signature Padding
//      pkcs 1.5 for now
//      use pss later: Todo

//  PKCS1-v1_5-ENCODE(M, emLen)
//      Option: Hash    hash function (hLen is length in bytes)
//      Input:  M       message to be encoded
//      emLen   intended length of the encoded message (size of modulus)
//          at least tLen + 11
//      tLen is octet length of the DER encoding (T)
//  Steps:
//      1.  H = Hash (M) .
//      2.  Encode the algorithm ID for the hash function and the hash value (T)
//      3.  If emLen<tLen+11, error
//      4.  Generate PS consisting of emLen–tLen–3 octets with value 0xff.
//              The length of PS will be at least 8 octets.
//      5.  EM = 0x00 || 0x01 || PS || 0x00 || T .
//  MD2:      (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10 || H.
//  MD5:      (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H.
//  SHA-1:    (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
//  SHA-256:  (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
//  SHA-384:  (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
//  SHA-512:  (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.

bool EmsapkcsPad(int hash_type, byte* hash_block, 
                    int sig_size, byte* sig_block) {
  int     n = 0;
  int     hash_len = 0;
  int     header_len = 0;
  int     pad_len = 0;
  int     minsig_size = 0;
  byte*   header = NULL;

  switch (hash_type) {
    case SHA256HASH:
      hash_len = SHA256DIGESTBYTESIZE;
      header_len = sizeof(sha256_header);
      header = sha256_header;
      break;
    case SHA1HASH:
      hash_len = SHA1DIGESTBYTESIZE;
      header_len = sizeof(sha1_header);
      header = sha1_header;
      break;
    case SHA512HASH:
      hash_len = SHA512DIGESTBYTESIZE;
      header_len = sizeof(sha512_header);
      header = sha512_header;
      break;
    case SHA384HASH:
    case MD5HASH:
    default:
      LOG(ERROR)<<"pkcs padding, unsupported hash type\n";
      return false;
  }

  minsig_size = 11 + hash_len + header_len;
  if (minsig_size > sig_size) {
    LOG(ERROR) <<"padded output buffer too small\n";
    return false;
  }

  // 2 byte header
  sig_block[n++] = 0x00;
  sig_block[n++] = 0x01;

  // PS
  pad_len = sig_size - 3 - hash_len - header_len;
  memset(&sig_block[n], 0xff, pad_len);
  n += pad_len;

  // 0
  sig_block[n++] = 0x00;

  // header
  memcpy(&sig_block[n], header, header_len);
  n += header_len;

  // hash
  memcpy(&sig_block[n], hash_block, hash_len);

#ifdef CRYPTOTEST
  PrintBytes("Padded block\n", sig_block, sig_size);
#endif
  return true;
}

bool EmsapkcsVerify(int hash_type, byte* hash_block, 
                      int sig_size, byte* sig_block) {
  int n = 0;
  int hash_len = 0;
  int header_len = 0;
  int pad_len = 0;
  int minsig_size = 0;
  byte* header = NULL;
  byte prefix[2] = {0x00, 0x01};

#ifdef CRYPTOTEST
  LOG(INFO) << "EmsapkcsVerify, hash type " << hash_type << "blocksize "<< sig_size <<"\n";
  PrintBytes("Padded block\n", sig_block, sig_size);
  PrintBytes("Hash\n", hash_block, 32);
#endif
  switch (hash_type) {
    case SHA256HASH:
      hash_len = SHA256DIGESTBYTESIZE;
      header_len = sizeof(sha256_header);
      header = sha256_header;
      break;
    case SHA1HASH:
      hash_len = SHA1DIGESTBYTESIZE;
      header_len = sizeof(sha1_header);
      header = sha1_header;
      break;
    case SHA512HASH:
      hash_len = SHA512DIGESTBYTESIZE;
      header_len = sizeof(sha512_header);
      header = sha512_header;
      break;
    case SHA384HASH:
    case MD5HASH:
    default:
      LOG(ERROR)<<"pkcs padding, unsupported hash type\n";
      return false;
  }

  minsig_size = 11 + hash_len + header_len;
  if (minsig_size > sig_size) {
    LOG(ERROR)<< "padded input buffer too small " << minsig_size << " " << sig_size <<"\n";
    return false;
  }

  // preamble
  if (memcmp(&sig_block[n], prefix, 2) != 0) {
    LOG(ERROR)<< "Bad preamble\n";
    return false;
  }
  n += 2;

  // PS
  pad_len = sig_size - 3 - hash_len - header_len;
  for (int i = n; i < (n + pad_len); i++) {
    if (sig_block[i] != 0xff) {
      LOG(ERROR) << "PS wrong at "<< i <<"\n";
      LOG(ERROR) <<"fflen: " << pad_len << "\n";
      LOG(ERROR)<< "sigsize: " << sig_size<<"\n";
      LOG(ERROR)<< "hash_len: "<< hash_len<<"\n";
      LOG(ERROR) << "header_len: "<< header_len << "\n";
      return false;
    }
  }
  n += pad_len;

  // 0 byte
  if (sig_block[n] != 0x00) {
    LOG(ERROR)<< "verify off in byte " << n << sig_block[n] << "\n";
    return false;
  }
  n++;

  // Header
  if (memcmp(&sig_block[n], header, header_len) != 0) {
    LOG(ERROR)<<"Bad header\n";
    return false;
  }
  n += header_len;

  // Hash
  if (memcmp(&sig_block[n], hash_block, hash_len) != 0) {
    LOG(ERROR) << "Bad hash\n";
#ifdef CRYPTOTEST
    PrintBytes("decoded hash\n", &sig_block[n], hash_len);
    PrintBytes("computed hash\n", hash_block, hash_len);
#endif
    return false;
  }
  n += header_len;

  return true;
}

// ----------------------------------------------------------------

//  PK Message Padding
//  EME-PKCS1-v1_5 decoding: Separate the encoded message EM into an
//  octet string PS consisting of nonzero octets and a message M as
//
//           EM = 0x00 || 0x02 || PS || 0x00 || M.
//
//  If the first octet of EM does not have hexadecimal value 0x00, if
//  the second octet of EM does not have hexadecimal value 0x02, if
//  there is no octet with hexadecimal value 0x00 to separate PS from
//  M, or if the length of PS is less than 8 octets, output
//  "decryption error" and stop.

#define NORANDPKCSPAD
bool PkcsmessagePad(int input_size, byte* message_block, 
                      int sig_size, byte* sig_block) {
  int n = 0;
  int pad_len = sig_size - 3 - input_size;

#ifdef CRYPTOTEST
  LOG(INFO) << "PkcsmessagePad, insize "  << input_size << " sig size " <<sig_size<<"\n";
#endif

  // 2 byte header
  sig_block[n++] = 0x00;
  sig_block[n++] = 0x02;

// get non-zero bytes
#ifdef NORANDPKCSPAD
  memset(&sig_block[n], 0xff, pad_len);
  n += pad_len;
#else
  int pad_end = 2 + pad_len;
  int k = 0;
  while (n < pad_end) {
    if (!getCryptoRandom(sig_size - n, &sig_block[n])) {
      LOG(ERROR) <<"PkcsmessagePad: can't get random bits\n";
      return false;
    }
    while (sig_block[n] != 0x00 && n < pad_end) n++;
    if (n >= pad_end) break;
    k = n + 1;
    while (n < pad_end && k < sig_size) {
      if (sig_block[k] != 0x00) sig_block[n++] = sig_block[k];
      k++;
    }
  }
#endif

  // single 0x00 byte
  sig_block[n++] = 0x00;

  // copy message
  memcpy(&sig_block[n], message_block, input_size);

#ifdef CRYPTOTEST
  PrintBytes("PkcsmessagePad: Padded block\n", sig_block, sig_size);
#endif
  return true;
}

bool PkcsmessageExtract(int* out_size, byte* out_block, 
                          int sig_size, byte* sig_block) {
  int n = 0;
  int m = 0;
  int i = 0;
  byte prefix[2] = {0x00, 0x02};

#ifdef CRYPTOTEST
  LOG(INFO) << "PkcsmessageExtract, sigsize " << sig_size << "\n";
#endif

  // preamble wrong?
  if (memcmp(&sig_block[n], prefix, 2) != 0) {
    LOG(ERROR) << "PkcsmessageExtract: Bad preamble\n";
    return false;
  }
  n += 2;

  // PS
  for (i = n; i < sig_size; i++) {
    if (sig_block[i] == 0x00) break;
  }

  // overflow?
  if (i >= sig_size) {
    LOG(ERROR) << "PkcsmessageExtract: no zero bytes\n";
    return false;
  }

  // 0 byte
  if (sig_block[i] != 0x00) {
    LOG(ERROR) << "PkcsmessageExtract: no zero byte\n";
    return false;
  }
  i++;
  n = i;

  m = sig_size - n;
  if (m > *out_size) {
    LOG(ERROR) << "PkcsmessageExtract: output buffer too small\n";
    return false;
  }
  *out_size = m;
  memcpy(out_block, &sig_block[n], m);

#ifdef CRYPTOTEST
  LOG(INFO) << "PkcsmessageExtract, output size is "<< *out_size << "\n";
#endif
  return true;
}

// ----------------------------------------------------------------

/*
 *  CBC
 *      C[0]= IV, C[i]= E_K(C[i-1] xor P[i])
 */

cbc::cbc() {
  block_size_ = 0;
  num_plain_bytes_ = 0;
  num_cipher_bytes_ = 0;
  encrypt_key_size_ = 0;
  integrity_key_size_ = 0;
  iv_valid_ = false;
  encrypt_alg_ = 0;
  last_block_ = NULL;
  first_block_ = NULL;
  last_blocks_ = NULL;
  computed_hmac_ = NULL;
  received_hmac_ = NULL;
  integrity_key_ = NULL;
}

cbc::~cbc() {
  aesencrypt_.CleanKeys();
  aesdecrypt_.CleanKeys();
  memset(integrity_key_, 0, integrity_key_size_);
  if (first_block_ != NULL) {
    free(first_block_);
    first_block_ = NULL;
  }
  if (last_block_ != NULL) {
    free(last_block_);
    last_block_ = NULL;
  }
  if (last_blocks_ != NULL) {
    free(last_blocks_);
    last_blocks_ = NULL;
  }
  if (computed_hmac_ != NULL) {
    free(computed_hmac_);
    computed_hmac_ = NULL;
  }
  if (received_hmac_ != NULL) {
    free(received_hmac_);
    received_hmac_ = NULL;
  }
  if (integrity_key_ != NULL) {
    free(integrity_key_);
    integrity_key_ = NULL;
  }
}

bool cbc::ComputePlainLen() {
  num_plain_bytes_ =
      num_cipher_bytes_ - 2 * block_size_ - SHA256_DIGESTSIZE_BYTES;
  return true;
}

bool cbc::ComputeCipherLen() {
  int k;

  if ((num_plain_bytes_ % block_size_) == 0) {
    num_cipher_bytes_ =
        num_plain_bytes_ + 2 * block_size_ + SHA256_DIGESTSIZE_BYTES;
  } else {
    k = (num_plain_bytes_ + block_size_ - 1) /block_size_;
    num_cipher_bytes_ =
        k * block_size_ +block_size_ + SHA256_DIGESTSIZE_BYTES;
  }
  return true;
}

bool cbc::InitDec(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
                  int intkeysize, byte* intkey, int cipherLen) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::InitDec\n";
#endif
  if (!Init(alg, pad, hashalg, keysize, key, intkeysize, intkey)) return false;
  num_cipher_bytes_ = cipherLen;
  ComputePlainLen();
  if (aesdecrypt_.KeySetupDec(key, keysize * NBITSINBYTE) < 0) {
    return false;
  }
  return true;
}

#ifdef CRYPTOTEST
void printCBCState(cbc* pMode) {
  LOG(INFO)<< "CBC State:\n";
  LOG(INFO)<<"\tBlock size: "<< pMode->block_size_<<"\n";
  LOG(INFO)<<"\tPlain bytes: "<< pMode->num_plain_bytes_<<"\n";
  LOG(INFO)<<"\tCipher bytes: "<< pMode->num_cipher_bytes_<<"\n";
  LOG(INFO) << "\tKey size: " << pMode->encrypt_key_size_;
  LOG(INFO) << ", integrity key size: " << pMode->integrity_key_size_ << "\n";

  if (pMode->iv_valid_)
    LOG(INFO) << "\tIV valid\n";
  else
    LOG(ERROR) << "\tIV invalid\n";
  LOG(INFO) << "\tEnc: "<< pMode->encrypt_alg_;
  LOG(INFO) << ", mac: " << pMode->mac_alg_;
  LOG(INFO) << ", pad: " << pMode->pad_alg_ << "\n";
}
#endif

bool cbc::InitEnc(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
                  int intkeysize, byte* intkey, int plainLen, int ivSize,
                  byte* iv) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::InitEnc\n";
#endif
  if (!Init(alg, pad, hashalg, keysize, key, intkeysize, intkey)) return false;
  if (iv != NULL) {
    memcpy(first_block_, iv, block_size_);
    memcpy(last_block_, iv, block_size_);
    iv_valid_ = true;
  }
  num_plain_bytes_ = plainLen;
  ComputeCipherLen();
  if (aesencrypt_.KeySetupEnc(key, keysize * NBITSINBYTE) < 0) {
    return false;
  }
  return true;
}

bool cbc::Init(u32 alg, u32 pad, u32 macalg, int keysize, byte* key,
               int intkeysize, byte* intkey) {
  num_plain_bytes_ = 0;
  num_cipher_bytes_ = 0;
  iv_valid_ = false;

  if (alg != AES128) return false;
  encrypt_alg_ = alg;
  block_size_ = 16;

  if (macalg != HMACSHA256) return false;
  mac_alg_ = macalg;

  if (pad != SYMPAD) return false;
  pad_alg_ = pad;

  if (first_block_ == NULL) first_block_ = (byte*)malloc(block_size_);
  if (last_blocks_ == NULL)
    last_blocks_ = (byte*)malloc(4 * block_size_);
  if (last_block_ == NULL) last_block_ = (byte*)malloc(block_size_);
  if (computed_hmac_ == NULL)
    computed_hmac_ = (byte*)malloc(SHA256_DIGESTSIZE_BYTES);
  if (received_hmac_ == NULL)
    received_hmac_ = (byte*)malloc(SHA256_DIGESTSIZE_BYTES);
  if (integrity_key_ != NULL) {
    if (integrity_key_size_ != intkeysize) {
      free(integrity_key_);
      integrity_key_ = NULL;
    }
  }
  integrity_key_size_ = intkeysize;
  if (integrity_key_ == NULL) integrity_key_ = (byte*)malloc(integrity_key_size_);

  if (first_block_ == NULL || last_blocks_ == NULL ||
      last_block_ == NULL || computed_hmac_ == NULL ||
      received_hmac_ == NULL || integrity_key_ == NULL)
    return false;

  memcpy(integrity_key_, intkey, encrypt_key_size_);
  hmac_.Init(intkey, intkeysize);

  return true;
}

int cbc::GetMac(int size, byte* mac) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::GetMac\n";
#endif
  memcpy(mac, computed_hmac_, SHA256_DIGESTSIZE_BYTES);
  return SHA256_DIGESTSIZE_BYTES;
}

void cbc::NextMac(byte* block)  { // always full block at a time
#ifdef CRYPTOTEST
  PrintBytes("cbc::NextMac: ", block, block_size_);
#endif
  hmac_.Update(block, block_size_);
}

bool cbc::NextPlainBlockIn(byte* in, byte* out) {
  byte oldX[GLOBALMAXSYMKEYSIZE];

#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::NextPlainBlockIn\n";
  PrintBytes("In: ", in, 16);
#endif
  inlineXor(oldX, last_block_, in, block_size_);
  aesencrypt_.Encrypt(oldX, out);
  memcpy(last_block_, out, block_size_);
#ifdef MACTHENENCRYPT  // should never do this
  NextMac(in);
#else
  NextMac(out);
#endif
  return true;
}

bool cbc::NextCipherBlockIn(byte* in, byte* out) {
  byte oldX[GLOBALMAXSYMKEYSIZE];

#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::NextCipherBlockIn\n";
  PrintBytes("In: ", in, 16);
#endif
  aesdecrypt_.Decrypt(in, oldX);
  inlineXor(out, last_block_, oldX, block_size_);
  memcpy(last_block_, in, block_size_);
#ifdef MACTHENENCRYPT  // should never do this
  NextMac(out);
#else
  NextMac(in);
#endif
  return true;
}

bool cbc::FirstCipherBlockIn(byte* in) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::FirstCipherBlockIn\n";
  PrintBytes("IV: ", in, block_size_);
#endif
  memcpy(first_block_, in, block_size_);
  memcpy(last_block_, in, block_size_);
  iv_valid_ = true;
  return true;
}

bool cbc::FirstCipherBlockOut(byte* out) {
#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::FirstCipherBlockOut\n";
  PrintBytes("IV: ", last_block_, block_size_);
#endif
  memcpy(out, last_block_, block_size_);
  return true;
}

bool cbc::ValidateMac() {
#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::ValidateMac\n";
#endif
  return isEqual(computed_hmac_, received_hmac_, SHA256_DIGESTSIZE_BYTES);
}

int cbc::LastPlainBlockIn(int size, byte* in, byte* out) {
  int num = 0;
  int i;

#ifdef CRYPTOTEST
  PrintBytes("cbc::LastPlainBlockIn\n", in, size);
#endif
  memcpy(last_blocks_, in, size);
  // pad
  if (size == block_size_) {
    last_blocks_[block_size_] = 0x80;
    for (i = 1; i < block_size_; i++) 
      last_blocks_[block_size_+ i] = 0x00;
    num = 2;
    NextPlainBlockIn(last_blocks_, out);
    NextPlainBlockIn(last_blocks_ + block_size_, out +block_size_);
    hmac_.Final(computed_hmac_);
  } else {
    last_blocks_[size] = 0x80;
    for (i = (size + 1); i < block_size_; i++) last_blocks_[i] = 0x00;
    num = 1;
    NextPlainBlockIn(last_blocks_, out);
    hmac_.Final(computed_hmac_);
  }
  memcpy(out + num * block_size_, computed_hmac_,
         SHA256_DIGESTSIZE_BYTES);
  num += 2;

#ifdef CRYPTOTEST
  PrintBytes("cbc::LastPlainBlockIn, mac: \n", computed_hmac_,
             SHA256_DIGESTSIZE_BYTES);
#endif
  // Note that the HMAC (whether encrypted or not) is returned as part of cipher
  // stream
  return block_size_ * num;
}

int cbc::LastCipherBlockIn(int size, byte* in, byte* out)
    // last three or four blocks
    {
  int residue = 0;
  int expectedsize = SHA256_DIGESTSIZE_BYTES + block_size_;

#ifdef CRYPTOTEST
  PrintBytes("cbc::LastCipherBlockIn: ", in, size);
#endif

  if (!iv_valid_) {
    LOG(ERROR)<<"cbc::LastCipherBlockIn: first cipherblock was not processed\n";
    return -1;
  }

  if (size != expectedsize) {
    LOG(ERROR)<<"cbc::LastCipherBlockIn: wrong lastBlock size, got " << size << " bytes\n";
    return -1;
  }

  // decrypt pad block
  NextCipherBlockIn(in, last_blocks_);
  in += block_size_;
  hmac_.Final(computed_hmac_);

#ifdef CRYPTOTEST
  PrintBytes("last cipher block decoded: ", last_blocks_, block_size_);
#endif

#ifdef MACTHENENCRYPT  // should never do this
  // decrypt Mac
  byte oldX[GLOBALMAXSYMKEYSIZE];

  aesdecrypt_.Decrypt(in, oldX);
  inlineXor(received_hmac_, last_block_, oldX, block_size_);
  memcpy(last_block_, in, block_size_);
  in += block_size_;
  aesdecrypt_.Decrypt(in, oldX);
  inlineXor(received_hmac_ + block_size_, last_block_, oldX,
            block_size_);
  memcpy(last_block_, in, block_size_);
  in += block_size_;
#else
  // Copy mac
  memcpy(received_hmac_, in, SHA256DIGESTBYTESIZE);
#endif

  // depad
  for (residue = block_size_ - 1; residue >= 0; residue--) {
    if (last_blocks_[residue] != 0) {
      if (last_blocks_[residue] != 0x80) {
        LOG(ERROR)<< "cbc::LastCipherBlockIn: bad pad error\n";
        return -1;
      }
      break;
    }
  }
  if (residue < 0) {
   LOG(ERROR)<<"cbc::LastCipherBlockIn: CBC bad pad error\n";
    return -1;
  }
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::LastCipherBlockIn, residue: " << residue<<"\n";
#endif
  num_plain_bytes_ += residue;
  memcpy(out, last_blocks_, residue);
  return residue;
}

// ---------------------------------------------------------------

