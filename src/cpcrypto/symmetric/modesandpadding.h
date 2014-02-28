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
  int m_iBlockSize;
  int m_iNumPlainBytes;
  int m_iNumCipherBytes;
  int m_iKeySize;
  int m_iIntKeySize;

  bool m_fIVValid;

  u32 m_uEncAlg;
  u32 m_uMacAlg;
  u32 m_uPadAlg;

#ifdef NOAESNI
  aes m_oAESEnc;
  aes m_oAESDec;
#else
  aesni m_oAESEnc;
  aesni m_oAESDec;
#endif
  hmacsha256 m_ohMac;

  byte* m_rguIV;
  byte* m_rgLastBlock;
  byte* m_rguFirstBlock;
  byte* m_rguLastBlocks;
  byte* m_rguHMACComputed;
  byte* m_rguHMACReceived;
  byte* m_rguIntKey;

  cbc();
  ~cbc();

  bool computePlainLen();
  bool computeCipherLen();

  bool init(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
            int intkeysize, byte* intkey);
  bool initEnc(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
               int intkeysize, byte* intkey, int plainLen, int ivSize,
               byte* iv);
  bool initDec(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key,
               int intkeysize, byte* intkey, int cipherLen);

  void nextMac(byte* puMac);
  int getMac(int bufSize, byte* puMac);

  bool firstCipherBlockIn(byte* puIn);
  bool nextPlainBlockIn(byte* puIn, byte* puOut);
  int lastPlainBlockIn(int size, byte* puIn, byte* puOut);

  bool firstCipherBlockOut(byte* puOut);
  bool nextCipherBlockIn(byte* puIn, byte* puOut);
  int lastCipherBlockIn(int size, byte* puIn, byte* puOut);

  bool validateMac();
};


#endif

// ----------------------------------------------------------------------
