//  File: modesandpadding.h
//  Description:  Modes and Padding
//
//  Copyright (c) 2011, Intel Corporation. Some contributions
//    (c) John Manferdelli.  All rights reserved.
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
#include "keys.h"
#ifdef NOAESNI
#include "aes.h"
#else
#include "aesni.h"
#endif
#include "sha256.h"
#include "hmacsha256.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

// -----------------------------------------------------------------------

#ifndef _MODESANDPADDING__H
#define _MODESANDPADDING__H

#define MAXAUTHSIZE 32
bool emsapkcspad(int hashType, byte* rgHash, int sigSize, byte* rgSig);
bool emsapkcsverify(int hashType, byte* rgHash, int iSigSize, byte* rgSig);
bool pkcsmessagepad(int sizeIn, byte* rgMsg, int sigSize, byte* rgSig);
bool pkcsmessageextract(int* psizeOut, byte* rgOut, int sigSize, byte* rgSig);

class cbc {
 public:
  int block_size_;
  int num_plain_bytes_;
  int num_cipher_bytes_;
  int encrypt_key_size_;
  int integrity_key_size_;

  bool iv_valid_;

  u32 encrypt_alg_;
  u32 mac_alg_;
  u32 pad_alg_;

#ifdef NOAESNI
  aes aesencrypt_;
  aes aesdecrypt_;
#else
  aesni aesencrypt_;
  aesni aesdecrypt_;
#endif
  hmacsha256 hmac_;

  byte* iv_block_;
  byte* last_block_;
  byte* first_block_;
  byte* last_blocks_;
  byte* computed_hmac_;
  byte* received_hmac_;
  byte* integrity_key_;

  cbc();
  ~cbc();

  bool ComputePlainLen();
  bool ComputeCipherLen();

  bool Init(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
            int intkeysize, byte* intkey);
  bool InitEnc(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
               int intkeysize, byte* intkey, int plainLen, int iv_size,
               byte* iv);
  bool InitDec(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
               int intkeysize, byte* intkey, int cipher_size);

  void NextMac(byte* puMac);
  int  GetMac(int bufSize, byte* puMac);

  bool FirstCipherBlockIn(byte* in);
  bool NextPlainBlockIn(byte* in, byte* out);
  int  LastPlainBlockIn(int size, byte* in, byte* out);

  bool FirstCipherBlockOut(byte* out);
  bool NextCipherBlockIn(byte* in, byte* out);
  int  LastCipherBlockIn(int size, byte* in, byte* out);

  bool ValidateMac();
};


#endif

// ----------------------------------------------------------------------
