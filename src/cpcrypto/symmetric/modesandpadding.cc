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
byte rgMD5Hdr[] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                   0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
byte rgSHA1Hdr[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
                    0x1a, 0x05, 0x00, 0x04, 0x14};
byte rgSHA256Hdr[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                      0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
                      0x20};
byte rgSHA384Hdr[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                      0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
                      0x30};
byte rgSHA512Hdr[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
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

bool emsapkcspad(int hashType, byte* rgHash, int sigSize, byte* rgSig) {
  int n = 0;
  int hashLen = 0;
  int hdrLen = 0;
  int psLen = 0;
  int minsigSize = 0;
  byte* pHdr = NULL;

  switch (hashType) {
    case SHA256HASH:
      hashLen = SHA256DIGESTBYTESIZE;
      hdrLen = sizeof(rgSHA256Hdr);
      pHdr = rgSHA256Hdr;
      break;
    case SHA1HASH:
      hashLen = SHA1DIGESTBYTESIZE;
      hdrLen = sizeof(rgSHA1Hdr);
      pHdr = rgSHA1Hdr;
      break;
    case SHA512HASH:
      hashLen = SHA512DIGESTBYTESIZE;
      hdrLen = sizeof(rgSHA512Hdr);
      pHdr = rgSHA512Hdr;
      break;
    case SHA384HASH:
    case MD5HASH:
    default:
      LOG(ERROR)<<"pkcs padding, unsupported hash type\n";
      return false;
  }

  minsigSize = 11 + hashLen + hdrLen;
  if (minsigSize > sigSize) {
    LOG(ERROR) <<"padded output buffer too small\n";
    return false;
  }

  // 2 byte header
  rgSig[n++] = 0x00;
  rgSig[n++] = 0x01;

  // PS
  psLen = sigSize - 3 - hashLen - hdrLen;
  memset(&rgSig[n], 0xff, psLen);
  n += psLen;

  // 0
  rgSig[n++] = 0x00;

  // header
  memcpy(&rgSig[n], pHdr, hdrLen);
  n += hdrLen;

  // hash
  memcpy(&rgSig[n], rgHash, hashLen);

#ifdef CRYPTOTEST
  PrintBytes("Padded block\n", rgSig, sigSize);
  fflush(g_logFile);
#endif
  return true;
}

bool emsapkcsverify(int hashType, byte* rgHash, int sigSize, byte* rgSig) {
  int n = 0;
  int hashLen = 0;
  int hdrLen = 0;
  int psLen = 0;
  int minsigSize = 0;
  byte* pHdr = NULL;
  byte rgPre[2] = {0x00, 0x01};

#ifdef CRYPTOTEST
  LOG(INFO) << "emsapkcsverify, hash type " << hashType << "blocksize "<< sigSize <<"\n";
  PrintBytes("Padded block\n", rgSig, sigSize);
  PrintBytes("Hash\n", rgHash, 32);
  fflush(g_logFile);
#endif
  switch (hashType) {
    case SHA256HASH:
      hashLen = SHA256DIGESTBYTESIZE;
      hdrLen = sizeof(rgSHA256Hdr);
      pHdr = rgSHA256Hdr;
      break;
    case SHA1HASH:
      hashLen = SHA1DIGESTBYTESIZE;
      hdrLen = sizeof(rgSHA1Hdr);
      pHdr = rgSHA1Hdr;
      break;
    case SHA512HASH:
      hashLen = SHA512DIGESTBYTESIZE;
      hdrLen = sizeof(rgSHA512Hdr);
      pHdr = rgSHA512Hdr;
      break;
    case SHA384HASH:
    case MD5HASH:
    default:
      LOG(ERROR)<<"pkcs padding, unsupported hash type\n";
      return false;
  }

  minsigSize = 11 + hashLen + hdrLen;
  if (minsigSize > sigSize) {
    LOG(ERROR)<< "padded input buffer too small " << minsigSize << " " << sigSize <<"\n";
    return false;
  }

  // preamble
  if (memcmp(&rgSig[n], rgPre, 2) != 0) {
    LOG(ERROR)<< "Bad preamble\n";
    return false;
  }
  n += 2;

  // PS
  psLen = sigSize - 3 - hashLen - hdrLen;
  for (int i = n; i < (n + psLen); i++) {
    if (rgSig[i] != 0xff) {
      LOG(ERROR) << "PS wrong at "<< i <<"\n";
      LOG(ERROR) <<"fflen: " << psLen << "\n";
      LOG(ERROR)<< "sigsize: " << sigSize<<"\n";
      LOG(ERROR)<< "hashLen: "<< hashLen<<"\n";
      LOG(ERROR) << "hdrLen: "<< hdrLen << "\n";
      return false;
    }
  }
  n += psLen;

  // 0 byte
  if (rgSig[n] != 0x00) {
    LOG(ERROR)<< "verify off in byte " << n << rgSig[n] << "\n";
    return false;
  }
  n++;

  // Header
  if (memcmp(&rgSig[n], pHdr, hdrLen) != 0) {
    LOG(ERROR)<<"Bad header\n";
    return false;
  }
  n += hdrLen;

  // Hash
  if (memcmp(&rgSig[n], rgHash, hashLen) != 0) {
    LOG(ERROR) << "Bad hash\n";
#ifdef CRYPTOTEST
    PrintBytes("decoded hash\n", &rgSig[n], hashLen);
    PrintBytes("computed hash\n", rgHash, hashLen);
    fflush(g_logFile);
#endif
    return false;
  }
  n += hdrLen;

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
bool pkcsmessagepad(int sizeIn, byte* rgMsg, int sigSize, byte* rgSig) {
  int n = 0;
  int psLen = sigSize - 3 - sizeIn;

#ifdef CRYPTOTEST
  LOG(INFO) << "pkcsmessagepad, insize "  << sizeIn << " sig size " <<sigSize<<"\n";
#endif

  // 2 byte header
  rgSig[n++] = 0x00;
  rgSig[n++] = 0x02;

// get non-zero bytes
#ifdef NORANDPKCSPAD
  memset(&rgSig[n], 0xff, psLen);
  n += psLen;
#else
  int padEnd = 2 + psLen;
  int k = 0;
  while (n < padEnd) {
    if (!getCryptoRandom(sigSize - n, &rgSig[n])) {
      LOG(ERROR) <<"pkcsmessagepad: can't get random bits\n";
      return false;
    }
    while (rgSig[n] != 0x00 && n < padEnd) n++;
    if (n >= padEnd) break;
    k = n + 1;
    while (n < padEnd && k < sigSize) {
      if (rgSig[k] != 0x00) rgSig[n++] = rgSig[k];
      k++;
    }
  }
#endif

  // single 0x00 byte
  rgSig[n++] = 0x00;

  // copy message
  memcpy(&rgSig[n], rgMsg, sizeIn);

#ifdef CRYPTOTEST
  PrintBytes("pkcsmessagepad: Padded block\n", rgSig, sigSize);
#endif
  return true;
}

bool pkcsmessageextract(int* psizeOut, byte* rgOut, int sigSize, byte* rgSig) {
  int n = 0;
  int m = 0;
  int i = 0;
  byte rgPre[2] = {0x00, 0x02};

#ifdef CRYPTOTEST
  LOG(INFO) << "pkcsmessageextract, sigsize " << sigSize << "\n";
#endif

  // preamble wrong?
  if (memcmp(&rgSig[n], rgPre, 2) != 0) {
    LOG(ERROR) << "pkcsmessageextract: Bad preamble\n";
    return false;
  }
  n += 2;

  // PS
  for (i = n; i < sigSize; i++) {
    if (rgSig[i] == 0x00) break;
  }

  // overflow?
  if (i >= sigSize) {
    LOG(ERROR) << "pkcsmessageextract: no zero bytes\n";
    return false;
  }

  // 0 byte
  if (rgSig[i] != 0x00) {
    LOG(ERROR) << "pkcsmessageextract: no zero byte\n";
    return false;
  }
  i++;
  n = i;

  m = sigSize - n;
  if (m > *psizeOut) {
    LOG(ERROR) << "pkcsmessageextract: output buffer too small\n";
    return false;
  }
  *psizeOut = m;
  memcpy(rgOut, &rgSig[n], m);

#ifdef CRYPTOTEST
  LOG(INFO) << "pkcsmessageextract, output size is "<< *psizeOut << "\n";
#endif
  return true;
}

// ----------------------------------------------------------------

/*
 *  CBC
* 
 *      C[0]= IV, C[i]= E_K(C[i-1] xor P[i])
 */

cbc::cbc() {
  m_iBlockSize = 0;
  m_iNumPlainBytes = 0;
  m_iNumCipherBytes = 0;
  m_iKeySize = 0;
  m_iIntKeySize = 0;
  m_fIVValid = false;
  m_uEncAlg = 0;
  m_rgLastBlock = NULL;
  m_rguFirstBlock = NULL;
  m_rguLastBlocks = NULL;
  m_rguHMACComputed = NULL;
  m_rguHMACReceived = NULL;
  m_rguIntKey = NULL;
}

cbc::~cbc() {
  m_oAESEnc.CleanKeys();
  m_oAESDec.CleanKeys();
  memset(m_rguIntKey, 0, m_iIntKeySize);
  if (m_rguFirstBlock != NULL) {
    free(m_rguFirstBlock);
    m_rguFirstBlock = NULL;
  }
  if (m_rgLastBlock != NULL) {
    free(m_rgLastBlock);
    m_rgLastBlock = NULL;
  }
  if (m_rguLastBlocks != NULL) {
    free(m_rguLastBlocks);
    m_rguLastBlocks = NULL;
  }
  if (m_rguHMACComputed != NULL) {
    free(m_rguHMACComputed);
    m_rguHMACComputed = NULL;
  }
  if (m_rguHMACReceived != NULL) {
    free(m_rguHMACReceived);
    m_rguHMACReceived = NULL;
  }
  if (m_rguIntKey != NULL) {
    free(m_rguIntKey);
    m_rguIntKey = NULL;
  }
}

bool cbc::computePlainLen() {
  m_iNumPlainBytes =
      m_iNumCipherBytes - 2 * m_iBlockSize - SHA256_DIGESTSIZE_BYTES;
  return true;
}

bool cbc::computeCipherLen() {
  int k;

  if ((m_iNumPlainBytes % m_iBlockSize) == 0) {
    m_iNumCipherBytes =
        m_iNumPlainBytes + 2 * m_iBlockSize + SHA256_DIGESTSIZE_BYTES;
  } else {
    k = (m_iNumPlainBytes + m_iBlockSize - 1) / m_iBlockSize;
    m_iNumCipherBytes =
        k * m_iBlockSize + m_iBlockSize + SHA256_DIGESTSIZE_BYTES;
  }
  return true;
}

bool cbc::initDec(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
                  int intkeysize, byte* intkey, int cipherLen) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::initDec\n";
#endif
  if (!init(alg, pad, hashalg, keysize, key, intkeysize, intkey)) return false;
  m_iNumCipherBytes = cipherLen;
  computePlainLen();
  if (m_oAESDec.KeySetupDec(key, keysize * NBITSINBYTE) < 0) {
    return false;
  }
  return true;
}

#ifdef CRYPTOTEST
void printCBCState(cbc* pMode) {
  LOG(INFO)<< "CBC State:\n";
  LOG(INFO)<<"\tBlock size: "<< pMode->m_iBlockSize<<"\n";
  LOG(INFO)<<"\tPlain bytes: "<< pMode->m_iNumPlainBytes<<"\n";
  LOG(INFO)<<"\tCipher bytes: "<< pMode->m_iNumCipherBytes<<"\n";
  LOG(INFO) << "\tKey size: " << pMode->m_iKeySize;
  LOG(INFO) << ", integrity key size: " << pMode->m_iIntKeySize << "\n";

  if (pMode->m_fIVValid)
    LOG(INFO) << "\tIV valid\n";
  else
    LOG(ERROR) << "\tIV invalid\n";
  LOG(INFO) << "\tEnc: "<< pMode->m_uEncAlg;
  LOG(INFO) << ", mac: " << pMode->m_uMacAlg;
  LOG(INFO) << ", pad: " << pMode->m_uPadAlg << "\n";

  // m_rguIV;
  // m_rgLastBlock;
  // m_rguFirstBlock;
  // m_rguLastBlocks;
  // m_rguHMACComputed;
  // m_rguHMACReceived;
  // m_rguIntKey;
}
#endif

bool cbc::initEnc(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
                  int intkeysize, byte* intkey, int plainLen, int ivSize,
                  byte* iv) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::initEnc\n";
#endif
  if (!init(alg, pad, hashalg, keysize, key, intkeysize, intkey)) return false;
  if (iv != NULL) {
    memcpy(m_rguFirstBlock, iv, m_iBlockSize);
    memcpy(m_rgLastBlock, iv, m_iBlockSize);
    m_fIVValid = true;
  }
  m_iNumPlainBytes = plainLen;
  computeCipherLen();
  if (m_oAESEnc.KeySetupEnc(key, keysize * NBITSINBYTE) < 0) {
    return false;
  }
  return true;
}

bool cbc::init(u32 alg, u32 pad, u32 macalg, int keysize, byte* key,
               int intkeysize, byte* intkey) {
  m_iNumPlainBytes = 0;
  m_iNumCipherBytes = 0;
  m_fIVValid = false;

  if (alg != AES128) return false;
  m_uEncAlg = alg;
  m_iBlockSize = 16;

  if (macalg != HMACSHA256) return false;
  m_uMacAlg = macalg;

  if (pad != SYMPAD) return false;
  m_uPadAlg = pad;

  if (m_rguFirstBlock == NULL) m_rguFirstBlock = (byte*)malloc(m_iBlockSize);
  if (m_rguLastBlocks == NULL)
    m_rguLastBlocks = (byte*)malloc(4 * m_iBlockSize);
  if (m_rgLastBlock == NULL) m_rgLastBlock = (byte*)malloc(m_iBlockSize);
  if (m_rguHMACComputed == NULL)
    m_rguHMACComputed = (byte*)malloc(SHA256_DIGESTSIZE_BYTES);
  if (m_rguHMACReceived == NULL)
    m_rguHMACReceived = (byte*)malloc(SHA256_DIGESTSIZE_BYTES);
  if (m_rguIntKey != NULL) {
    if (m_iIntKeySize != intkeysize) {
      free(m_rguIntKey);
      m_rguIntKey = NULL;
    }
  }
  m_iIntKeySize = intkeysize;
  if (m_rguIntKey == NULL) m_rguIntKey = (byte*)malloc(m_iIntKeySize);

  if (m_rguFirstBlock == NULL || m_rguLastBlocks == NULL ||
      m_rgLastBlock == NULL || m_rguHMACComputed == NULL ||
      m_rguHMACReceived == NULL || m_rguIntKey == NULL)
    return false;

  memcpy(m_rguIntKey, intkey, m_iKeySize);
  m_ohMac.Init(intkey, intkeysize);

  return true;
}

int cbc::getMac(int size, byte* puMac) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::getMac\n";
  fflush(g_logFile);
#endif
  memcpy(puMac, m_rguHMACComputed, SHA256_DIGESTSIZE_BYTES);
  return SHA256_DIGESTSIZE_BYTES;
}

void cbc::nextMac(byte* puA)
    // always full block at a time
    {
#ifdef CRYPTOTEST
  PrintBytes("cbc::nextMac: ", puA, m_iBlockSize);
  fflush(g_logFile);
#endif
  m_ohMac.Update(puA, m_iBlockSize);
}

bool cbc::nextPlainBlockIn(byte* puIn, byte* puOut) {
  byte oldX[GLOBALMAXSYMKEYSIZE];

#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::nextPlainBlockIn\n";
  PrintBytes("In: ", puIn, 16);
  fflush(g_logFile);
#endif
  inlineXor(oldX, m_rgLastBlock, puIn, m_iBlockSize);
  m_oAESEnc.Encrypt(oldX, puOut);
  memcpy(m_rgLastBlock, puOut, m_iBlockSize);
#ifdef MACTHENENCRYPT  // should never do this
  nextMac(puIn);
#else
  nextMac(puOut);
#endif
  return true;
}

bool cbc::nextCipherBlockIn(byte* puIn, byte* puOut) {
  byte oldX[GLOBALMAXSYMKEYSIZE];

#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::nextCipherBlockIn\n";
  PrintBytes("In: ", puIn, 16);
#endif
  m_oAESDec.Decrypt(puIn, oldX);
  inlineXor(puOut, m_rgLastBlock, oldX, m_iBlockSize);
  memcpy(m_rgLastBlock, puIn, m_iBlockSize);
#ifdef MACTHENENCRYPT  // should never do this
  nextMac(puOut);
#else
  nextMac(puIn);
#endif
  return true;
}

bool cbc::firstCipherBlockIn(byte* puIn) {
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::firstCipherBlockIn\n";
  PrintBytes("IV: ", puIn, m_iBlockSize);
#endif
  memcpy(m_rguFirstBlock, puIn, m_iBlockSize);
  memcpy(m_rgLastBlock, puIn, m_iBlockSize);
  m_fIVValid = true;
  return true;
}

bool cbc::firstCipherBlockOut(byte* puOut) {
#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::firstCipherBlockOut\n";
  PrintBytes("IV: ", m_rgLastBlock, m_iBlockSize);
#endif
  memcpy(puOut, m_rgLastBlock, m_iBlockSize);
  return true;
}

bool cbc::validateMac() {
#ifdef CRYPTOTEST
  LOG(INFO) <<"cbc::validateMac\n";
#endif
  return isEqual(m_rguHMACComputed, m_rguHMACReceived, SHA256_DIGESTSIZE_BYTES);
}

int cbc::lastPlainBlockIn(int size, byte* puIn, byte* puOut) {
  int num = 0;
  int i;

#ifdef CRYPTOTEST
  PrintBytes("cbc::lastPlainBlockIn\n", puIn, size);
  fflush(g_logFile);
#endif
  memcpy(m_rguLastBlocks, puIn, size);
  // pad
  if (size == m_iBlockSize) {
    m_rguLastBlocks[m_iBlockSize] = 0x80;
    for (i = 1; i < m_iBlockSize; i++) m_rguLastBlocks[m_iBlockSize + i] = 0x00;
    num = 2;
    nextPlainBlockIn(m_rguLastBlocks, puOut);
    nextPlainBlockIn(m_rguLastBlocks + m_iBlockSize, puOut + m_iBlockSize);
    m_ohMac.Final(m_rguHMACComputed);
  } else {
    m_rguLastBlocks[size] = 0x80;
    for (i = (size + 1); i < m_iBlockSize; i++) m_rguLastBlocks[i] = 0x00;
    num = 1;
    nextPlainBlockIn(m_rguLastBlocks, puOut);
    m_ohMac.Final(m_rguHMACComputed);
  }
  memcpy(puOut + num * m_iBlockSize, m_rguHMACComputed,
         SHA256_DIGESTSIZE_BYTES);
  num += 2;

#ifdef CRYPTOTEST
  PrintBytes("cbc::lastPlainBlockIn, mac: \n", m_rguHMACComputed,
             SHA256_DIGESTSIZE_BYTES);
  fflush(g_logFile);
#endif
  // Note that the HMAC (whether encrypted or not) is returned as part of cipher
  // stream
  return m_iBlockSize * num;
}

int cbc::lastCipherBlockIn(int size, byte* puIn, byte* puOut)
    // last three or four blocks
    {
  int residue = 0;
  int expectedsize = SHA256_DIGESTSIZE_BYTES + m_iBlockSize;

#ifdef CRYPTOTEST
  PrintBytes("cbc::lastCipherBlockIn: ", puIn, size);
  fflush(g_logFile);
#endif

  if (!m_fIVValid) {
    LOG(ERROR)<<"cbc::lastCipherBlockIn: first cipherblock was not processed\n";
    return -1;
  }

  if (size != expectedsize) {
    LOG(ERROR)<<"cbc::lastCipherBlockIn: wrong lastBlock size, got " << size << " bytes\n";
    return -1;
  }

  // decrypt pad block
  nextCipherBlockIn(puIn, m_rguLastBlocks);
  puIn += m_iBlockSize;
  m_ohMac.Final(m_rguHMACComputed);

#ifdef CRYPTOTEST
  PrintBytes("last cipher block decoded: ", m_rguLastBlocks, m_iBlockSize);
  fflush(g_logFile);
#endif

#ifdef MACTHENENCRYPT  // should never do this
  // decrypt Mac
  byte oldX[GLOBALMAXSYMKEYSIZE];

  m_oAESDec.Decrypt(puIn, oldX);
  inlineXor(m_rguHMACReceived, m_rgLastBlock, oldX, m_iBlockSize);
  memcpy(m_rgLastBlock, puIn, m_iBlockSize);
  puIn += m_iBlockSize;
  m_oAESDec.Decrypt(puIn, oldX);
  inlineXor(m_rguHMACReceived + m_iBlockSize, m_rgLastBlock, oldX,
            m_iBlockSize);
  memcpy(m_rgLastBlock, puIn, m_iBlockSize);
  puIn += m_iBlockSize;
#else
  // Copy mac
  memcpy(m_rguHMACReceived, puIn, SHA256DIGESTBYTESIZE);
#endif

  // depad
  for (residue = m_iBlockSize - 1; residue >= 0; residue--) {
    if (m_rguLastBlocks[residue] != 0) {
      if (m_rguLastBlocks[residue] != 0x80) {
        LOG(ERROR)<< "cbc::lastCipherBlockIn: bad pad error\n";
        return -1;
      }
      break;
    }
  }
  if (residue < 0) {
   LOG(ERROR)<<"cbc::lastCipherBlockIn: CBC bad pad error\n";
    return -1;
  }
#ifdef CRYPTOTEST
  LOG(INFO)<<"cbc::lastCipherBlockIn, residue: " << residue<<"\n";
#endif
  m_iNumPlainBytes += residue;
  memcpy(puOut, m_rguLastBlocks, residue);
  return residue;
}

// ---------------------------------------------------------------

