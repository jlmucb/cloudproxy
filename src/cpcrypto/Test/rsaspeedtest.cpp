//
//  File: rsaspeedtest.cpp
//  Description: rsa speed test
//
//  Copyright (c) John Manferdelli.  All rights reserved.
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
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "sha256.h"
#include "aes.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "modesandpadding.h"
#include "cryptoHelper.h"
#include "fastArith.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <time.h>

#define MAXREQUESTSIZE 2048
#define MAXADDEDSIZE 64
#define MAXREQUESTSIZEWITHPAD (MAXREQUESTSIZE + MAXADDEDSIZE)

#define DEBUG4

#define MONTGOMERYENABLED
#define SLIDINGWINDOW
// ---------------------------------------------------------------------

KeyInfo* ReadKeyfromFile(const char* szKeyFile) {
  KeyInfo* pParseKey = new KeyInfo;
  RSAKey* pRSAKey = NULL;
  symKey* pAESKey = NULL;
  KeyInfo* pRetKey = NULL;
  int iKeyType;

  TiXmlDocument* pDoc = new TiXmlDocument();
  if (pDoc == NULL) {
    printf("Cant get new an Xml Document\n");
    return NULL;
  }

  if (!pDoc->LoadFile(szKeyFile)) {
    printf("Cant load keyfile\n");
    return NULL;
  }
  iKeyType = pParseKey->getKeyType(pDoc);

  switch (iKeyType) {
    case AESKEYTYPE:
      pAESKey = new symKey();
      if (pAESKey == NULL) {
        printf("Cant new symKey\n");
        break;
      } else
        pAESKey->m_pDoc = pDoc;
      pAESKey->getDataFromDoc();
      pRetKey = (KeyInfo*)pAESKey;
      break;
    case RSAKEYTYPE:
      pRSAKey = new RSAKey();
      if (pRSAKey == NULL) {
        printf("Cant new RSAKey\n");
        break;
      } else
        pRSAKey->m_pDoc = pDoc;
      pRSAKey->getDataFromDoc();
      pRetKey = (KeyInfo*)pRSAKey;
      break;
    default:
      printf("Unknown key type in ReadFromFile\n");
      break;
  }
  delete pParseKey;
  // Dont forget to delete pDoc;

  return pRetKey;
}

bool MontEncryptTest(RSAKey* pKey, int numBlocks, bool fEncrypt) {
  int i;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double opspersecond = 0.0;

  bnum bnIn(pKey->m_iByteSizeM);
  bnum bnEncrypted(pKey->m_iByteSizeM);
  bnum bnDecrypted(pKey->m_iByteSizeM + 1);
  bnum bnRmodM(pKey->m_iByteSizeM);
  bnum bnRsqmodM(pKey->m_iByteSizeM);
  bnum bnMPrime(pKey->m_iByteSizeM);

  memset(bnIn.m_pValue, 0, pKey->m_iByteSizeM);
  memset(bnEncrypted.m_pValue, 0, pKey->m_iByteSizeM);
  memset(bnDecrypted.m_pValue, 0, pKey->m_iByteSizeM);
  u64* puIn = (u64*)bnIn.m_pValue;
  *puIn = 237ULL;

  int r = pKey->m_iByteSizeM / sizeof(u64);

  if (!fEncrypt)
    printf("RSA Montgomery Decrypt, %d blocks\n", numBlocks);
  else
    printf("RSA Montgomery Encrypt, %d blocks\n", numBlocks);

  if (!mpMontInit(r, *(pKey->m_pbnM), bnMPrime, bnRmodM, bnRsqmodM)) {
    printf("RSA Montgomery Encrypt: can't initialize Montgomery components\n");
    return false;
  }

  time(&start);
  if (numBlocks == 1) {
#ifndef SLIDINGWINDOW
    if (!mpModExp(bnIn, *(pKey->m_pbnE), *(pKey->m_pbnM), bnEncrypted)) {
      printf("Can't encrypt\n");
      return false;
    }
#ifdef MONTGOMERYENABLED
    printf("\n***Montgomery decrypt\n");
    if (!mpMontModExp(bnEncrypted, *(pKey->m_pbnD), *(pKey->m_pbnM),
                      bnDecrypted, r, bnMPrime, bnRmodM, bnRsqmodM)) {
      printf("Can't decrypt\n");
      return false;
    }
#else
    printf("\n***Regular decrypt\n");
    if (!mpModExp(bnEncrypted, *(pKey->m_pbnD), *(pKey->m_pbnM), bnDecrypted)) {
      printf("Can't decrypt\n");
      return false;
    }
#endif
#else
    if (!mpModExp(bnIn, *(pKey->m_pbnE), *(pKey->m_pbnM), bnEncrypted)) {
      printf("Can't encrypt\n");
      return false;
    }
    printf("\n***Sliding window decrypt\n");
    if (!mpSlidingModExp(bnEncrypted, *(pKey->m_pbnD), *(pKey->m_pbnM),
                         bnDecrypted, r, bnMPrime, bnRmodM, bnRsqmodM)) {
      printf("Can't decrypt\n");
      return false;
    }
#endif
    printf("\nIn       : ");
    printNum(bnIn);
    printf("\n");
    printf("Encrypted: ");
    printNum(bnEncrypted);
    printf("\n");
    printf("Decrypted: ");
    printNum(bnDecrypted);
    printf("\n\n");
  } else if (fEncrypt) {
    for (i = 0; i < numBlocks; i++) {
#ifndef SLIDINGWINDOW
      if (!mpMontModExp(bnIn, *(pKey->m_pbnE), *(pKey->m_pbnM), bnEncrypted, r,
                        bnMPrime, bnRmodM, bnRsqmodM)) {
        printf("Can't encrypt\n");
        return false;
      }
#else
      if (!mpSlidingModExp(bnIn, *(pKey->m_pbnE), *(pKey->m_pbnM), bnEncrypted,
                           r, bnMPrime, bnRmodM, bnRsqmodM)) {
        printf("Can't encrypt\n");
        return false;
      }
#endif
      (*puIn)++;
    }
  } else {
    for (i = 0; i < numBlocks; i++) {
#ifndef SLIDINGWINDOW
      if (!mpMontModExp(bnIn, *(pKey->m_pbnD), *(pKey->m_pbnM), bnDecrypted, r,
                        bnMPrime, bnRmodM, bnRsqmodM)) {
        printf("Can't decrypt\n");
        return false;
      }
#else
      if (!mpSlidingModExp(bnIn, *(pKey->m_pbnD), *(pKey->m_pbnM), bnDecrypted,
                           r, bnMPrime, bnRmodM, bnRsqmodM)) {
        printf("Can't decrypt\n");
        return false;
      }
#endif
      (*puIn)++;
    }
  }
  time(&finish);

  elapsedseconds = difftime(finish, start);
  opspersecond = ((double)numBlocks) / elapsedseconds;
  if (fEncrypt)
    printf("RSA Mont Encrypt: %10.2f seconds, %10d operations, %10.1f "
           "ops/second\n",
           elapsedseconds, numBlocks, opspersecond);
  else
    printf("RSA Mont Decrypt: %10.2f seconds, %10d operations, %10.1f "
           "ops/second\n",
           elapsedseconds, numBlocks, opspersecond);
  return true;
}

bool EncryptTest(RSAKey* pKey, int numBlocks, bool fFast = false,
                 bool fEncrypt = true) {
  int i;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn(pKey->m_iByteSizeM);
  bnum bnEncrypted(pKey->m_iByteSizeM + 1);
  bnum bnDecrypted(pKey->m_iByteSizeM + 1);
  bnum R(128);
  bnum bnDP(pKey->m_iByteSizeM / 2);
  bnum bnDQ(pKey->m_iByteSizeM / 2);
  bnum bnPM1(pKey->m_iByteSizeM / 2);
  bnum bnQM1(pKey->m_iByteSizeM / 2);

  bnum bnPPrime(pKey->m_iByteSizeM / 2);
  bnum bnRmodP(pKey->m_iByteSizeM / 2);
  bnum bnRsqmodP(pKey->m_iByteSizeM / 2);
  bnum bnQPrime(pKey->m_iByteSizeM / 2);
  bnum bnRmodQ(pKey->m_iByteSizeM / 2);
  bnum bnRsqmodQ(pKey->m_iByteSizeM / 2);

#ifdef MONTGOMERYENABLED
  int r;
#endif
  memset(bnIn.m_pValue, 0, pKey->m_iByteSizeM);
  memset(bnEncrypted.m_pValue, 0, pKey->m_iByteSizeM);
  memset(bnDecrypted.m_pValue, 0, pKey->m_iByteSizeM);
  u64* puIn = (u64*)bnIn.m_pValue;
  *puIn = 237ULL;

  if (fFast && !fEncrypt)
    printf("RSA Fast Decrypt, %d blocks\n", numBlocks);
  else if (!fEncrypt)
    printf("RSA Decrypt, %d blocks\n", numBlocks);
  else
    printf("RSA Encrypt, %d blocks\n", numBlocks);

#ifdef FAST
  if (fFast) {
    if (!mpRSACalculateFastRSAParameters(*(pKey->m_pbnE), *(pKey->m_pbnP),
                                         *(pKey->m_pbnQ), bnPM1, bnDP, bnQM1,
                                         bnDQ)) {
      printf("Can't calculate RSA fast decrypt parameters\n");
      return false;
    }
  }

#ifdef MONTGOMERYENABLED
  r = mpWordsinNum(pKey->m_pbnP->mpSize(), pKey->m_pbnP->m_pValue);
  if (!mpMontInit(r, *(pKey->m_pbnP), bnPPrime, bnRmodP, bnRsqmodP)) {
    printf(
        "RSA Montgomery Encrypt: can't initialize Montgomery components(P)\n");
    return false;
  }
  r = mpWordsinNum(pKey->m_pbnQ->mpSize(), pKey->m_pbnQ->m_pValue);
  if (!mpMontInit(r, *(pKey->m_pbnQ), bnQPrime, bnRmodQ, bnRsqmodQ)) {
    printf(
        "RSA Montgomery Encrypt: can't initialize Montgomery components(Q)\n");
    return false;
  }
#endif
#endif

  time(&start);
  if (fEncrypt) {
    for (i = 0; i < numBlocks; i++) {
      if (!mpRSAENC(bnIn, *(pKey->m_pbnE), *(pKey->m_pbnM), bnEncrypted)) {
        printf("Can't encrypt\n");
        return false;
      }
      (*puIn)++;
    }
  }
#ifdef FAST
#ifdef MONTGOMERYENABLED
      else if (fFast) {
    printf("fastDecrypt test\n");
    for (i = 0; i < numBlocks; i++) {
      if (!mpRSAMontDEC(bnIn, *(pKey->m_pbnP), bnPM1, bnDP, *(pKey->m_pbnQ),
                        bnQM1, bnDQ, *(pKey->m_pbnM), bnDecrypted, r, bnPPrime,
                        bnRmodP, bnRsqmodP, bnQPrime, bnRmodQ, bnRsqmodQ)) {
        printf("Can't decrypt\n");
        return false;
      }
      (*puIn)++;
    }
  }
#else
      else if (fFast) {
    for (i = 0; i < numBlocks; i++) {
      if (!mpRSADEC(bnIn, *(pKey->m_pbnP), bnPM1, bnDP, *(pKey->m_pbnQ), bnQM1,
                    bnDQ, *(pKey->m_pbnM), bnDecrypted)) {
        printf("Can't decrypt\n");
        return false;
      }
      (*puIn)++;
    }
  }
#endif
#endif
      else {
    for (i = 0; i < numBlocks; i++) {
      if (!mpRSAENC(bnIn, *(pKey->m_pbnD), *(pKey->m_pbnM), bnDecrypted)) {
        printf("Can't decrypt\n");
        return false;
      }
      (*puIn)++;
    }
  }
  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)numBlocks;
  opspersecond = ops / elapsedseconds;
  if (fEncrypt)
    printf("RSA Encypt: %10.2f seconds, %10d operations, %10.1f ops/second\n",
           elapsedseconds, numBlocks, opspersecond);
  else
    printf("RSA Decrypt: %10.2f seconds, %10d operations, %10.1f ops/second\n",
           elapsedseconds, numBlocks, opspersecond);
  return true;
}

bool RSASanityCheck(RSAKey* key, int file, bool fPrint, bool fFast) {
  bool fRet = true;
  int numBytes = 0;
  byte buf[4096];
  int blockSize = key->m_iByteSizeM;
  int numBlocks = 0;
  bool fFailed = false;

  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnMsg(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnEncrypted(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnDecrypted(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnPM1(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnQM1(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnDP(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnDQ(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnPPrime(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnRmodP(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnRsqmodP(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnQPrime(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnRmodQ(key->m_iByteSizeM / sizeof(u64) + 1);
  bnum bnRsqmodQ(key->m_iByteSizeM / sizeof(u64) + 1);

#ifdef MONTGOMERYENABLED
  int r = key->m_iByteSizeM / 2;
#endif
#ifdef FAST
  if (fFast) {
    printf("Fast RSA sanity check, block size is %d\n", blockSize);
    if (!mpRSACalculateFastRSAParameters(*(key->m_pbnE), *(key->m_pbnP),
                                         *(key->m_pbnQ), bnPM1, bnDP, bnQM1,
                                         bnDQ)) {
      printf("Can't calculate RSA fast decrypt parameters\n");
      return false;
    }
    printf("mpRSACalculateFastRSAParameters\n");
    printf("P  : ");
    printNum(*(key->m_pbnP));
    printf("\n");
    printf("PM1: ");
    printNum(bnPM1);
    printf("\n");
    printf("DP : ");
    printNum(bnDP);
    printf("\n");
    printf("Q  : ");
    printNum(*(key->m_pbnQ));
    printf("\n");
    printf("QM1: ");
    printNum(bnQM1);
    printf("\n");
    printf("DQ : ");
    printNum(bnDQ);
    printf("\n");
#ifdef MONTGOMERYENABLED
    if (!mpMontInit(r, *(key->m_pbnP), bnPPrime, bnRmodP, bnRsqmodP)) {
      printf("RSA Montgomery Encrypt: can't initialize Montgomery "
             "components(P)\n");
      return false;
    }
    if (!mpMontInit(r, *(key->m_pbnQ), bnQPrime, bnRmodQ, bnRsqmodQ)) {
      printf("RSA Montgomery Encrypt: can't initialize Montgomery "
             "components(Q)\n");
      return false;
    }
#endif
  } else
#endif
    printf("RSA sanity check, block size is %d\n", blockSize);
  printf("M  : ");
  printNum(*(key->m_pbnM));
  printf("\n");
  printf("E  : ");
  printNum(*(key->m_pbnE));
  printf("\n");
  printf("D  : ");
  printNum(*(key->m_pbnD));
  printf("\n");

  time(&start);
  for (;;) {
    numBytes = read(file, buf, blockSize);
    if (numBytes < blockSize) break;

    ZeroWords(bnMsg.mpSize(), bnMsg.m_pValue);
    ZeroWords(bnEncrypted.mpSize(), bnEncrypted.m_pValue);
    ZeroWords(bnDecrypted.mpSize(), bnDecrypted.m_pValue);

    fFailed = false;
    memcpy(bnMsg.m_pValue, buf, blockSize);
    bnMsg.m_pValue[blockSize / sizeof(u64) - 1] &= 0xffffffffULL;

    if (!mpRSAENC(bnMsg, *(key->m_pbnE), *(key->m_pbnM), bnEncrypted)) {
      printf("Can't encrypt\n");
      fFailed = true;
      fRet = false;
    }
#ifdef FAST
    if (fFast) {
#ifdef MONTGOMERYENABLED
      if (!mpRSAMontDEC(bnEncrypted, *(key->m_pbnP), bnPM1, bnDP,
                        *(key->m_pbnQ), bnQM1, bnDQ, *(key->m_pbnM),
                        bnDecrypted, r, bnPPrime, bnRmodP, bnRsqmodP, bnQPrime,
                        bnRmodQ, bnRsqmodQ)) {
        printf("Can't decrypt\n");
        fFailed = true;
        fRet = false;
      }
#else
      if (!mpRSADEC(bnEncrypted, *(key->m_pbnP), bnPM1, bnDP, *(key->m_pbnQ),
                    bnQM1, bnDQ, *(key->m_pbnM), bnDecrypted)) {
        printf("Can't decrypt\n");
        fFailed = true;
        fRet = false;
      }
#endif
    } else {
      if (!mpRSAENC(bnEncrypted, *(key->m_pbnD), *(key->m_pbnM), bnDecrypted)) {
        printf("Can't decrypt\n");
        fFailed = true;
        fRet = false;
      }
    }
#else
    if (!mpRSAENC(bnEncrypted, *(key->m_pbnD), *(key->m_pbnM), bnDecrypted)) {
      printf("Can't decrypt\n");
      fFailed = true;
      fRet = false;
    }
#endif
    numBlocks++;

    if (memcmp(bnMsg.m_pValue, bnDecrypted.m_pValue, blockSize) != 0) {
      fFailed = true;
      fRet = false;
    }

    if (fPrint || fFailed) {
      if (fFailed) {
        printf("\nFAILED\n");
      } else {
        printf("\nPASSED\n");
      }
      printf("Message\n");
      printNum(bnMsg);
      printf("\n");
      printf("Encrypted\n");
      printNum(bnEncrypted);
      printf("\n");
      printf("Decrypted\n");
      printNum(bnDecrypted);
      printf("\n");
    }
  }
  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)numBlocks;
  opspersecond = ops / elapsedseconds;
  printf(
      "RSA Enc/Decrypt: %10.2f seconds, %10d operations, %10.1f ops/second\n",
      elapsedseconds, numBlocks, opspersecond);
  return fRet;
}

// ---------------------------------------------------------------------

bool Puremult(int num) {
  int i;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;
  u64 a, b;
  u64 r = 0ULL;
  u64 c = 0ULL;
  u64* pr = &r;
  u64* pc = &c;
  UNUSEDVAR(i);
  UNUSEDVAR(pr);
  UNUSEDVAR(pc);

  a = 0x5555555577777007ULL;
  b = 0x9999999933333003ULL;

  time(&start);
  for (i = 0; i < num; i++) {
    asm volatile("\tmovq    %[A], %%rax\n"
                 "\tmulq    %[B]\n"
                 "\tmovq    %[pR], %%rcx\n"
                 "\tmovq    %%rax, (%%rcx)\n"
                 "\tmovq    %[pC], %%rcx\n"
                 "\tmovq    %%rdx, (%%rcx)\n"
                 :
                 : [pR] "m"(pr), [pC] "m"(pc), [A] "m"(a), [B] "m"(b)
                 : "%rax", "%rcx", "%rdx");
  }
  time(&finish);
  printf("%016lx*%016lx= (%016lx, %016lx)\n", a, b, c, r);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("Puremult    : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool Addtest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);
  bnum bnIn3(32);

  for (i = 0; i < 16; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 16; i++) bnIn2.m_pValue[i] = (i + 1) * 31;
  time(&start);

  for (i = 0; i < unum; i++) mpUAdd(bnIn1, bnIn2, bnIn3);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("Addtest     : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool Subtest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);
  bnum bnIn3(32);

  for (i = 0; i < 16; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 15; i++) bnIn2.m_pValue[i] = (i + 1) * 31;
  time(&start);

  for (i = 0; i < unum; i++) mpUSub(bnIn1, bnIn2, bnIn3);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("Subtest     : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool Multiplytest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);
  bnum bnIn3(32);

  for (i = 0; i < 16; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 16; i++) bnIn2.m_pValue[i] = (i + 1) * 31;

  time(&start);

  for (i = 0; i < unum; i++) mpUMult(bnIn1, bnIn2, bnIn3);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("Multiplytest: %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool SlowSquaretest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);

  for (i = 0; i < 16; i++) bnIn1.m_pValue[i] = (i + 1) * 23;

  time(&start);

  for (i = 0; i < unum; i++) mpUMult(bnIn1, bnIn1, bnIn2);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("SlowSquare  : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);
  return true;
}

bool FastSquaretest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);

  for (i = 0; i < 16; i++) bnIn1.m_pValue[i] = (i + 1) * 23;

  time(&start);

  for (i = 0; i < unum; i++) mpUSquare(bnIn1, bnIn2);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("FastSquare  : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);
  return true;
}

bool Divtest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);
  bnum bnIn3(32);
  bnum bnIn4(32);

  for (i = 0; i < 24; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 15; i++) bnIn2.m_pValue[i] = (i + 1) * 31;
  time(&start);

  for (i = 0; i < unum; i++) mpUDiv(bnIn1, bnIn2, bnIn3, bnIn4);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("Divtest     : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool Modtest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);
  bnum bnIn3(32);

  for (i = 0; i < 24; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 15; i++) bnIn2.m_pValue[i] = (i + 1) * 31;
  time(&start);

  for (i = 0; i < unum; i++) mpMod(bnIn1, bnIn2, bnIn3);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("Modtest     : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool Exptest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(128);
  bnum bnIn2(128);
  bnum bnIn3(128);
  bnum bnIn4(128);

  for (i = 0; i < 15; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 15; i++) bnIn2.m_pValue[i] = (i + 1) * 17;
  for (i = 0; i < 16; i++) bnIn3.m_pValue[i] = (i + 1) * 31;

  time(&start);

  for (i = 0; i < unum; i++) mpModExp(bnIn1, bnIn3, bnIn2, bnIn4);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("Exptest     : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool GCDtest(int num) {
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);
  bnum bnIn3(32);
  bnum bnIn4(32);
  bnum bnIn5(32);

  for (i = 0; i < 24; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 16; i++) bnIn2.m_pValue[i] = (i + 1) * 31;
  time(&start);

  for (i = 0; i < unum; i++) mpExtendedGCD(bnIn1, bnIn2, bnIn3, bnIn4, bnIn5);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("GCDtest     : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
}

bool BinaryGCDtest(int num) {
#if 1
  return true;
#else
  u64 i;
  u64 unum = (u64)num;
  time_t start, finish;
  double elapsedseconds = 0.0;
  double ops = 0.0;
  double opspersecond = 0.0;

  bnum bnIn1(32);
  bnum bnIn2(32);
  bnum bnIn3(32);
  bnum bnIn4(32);
  bnum bnIn5(32);

  for (i = 0; i < 24; i++) bnIn1.m_pValue[i] = (i + 1) * 23;
  for (i = 0; i < 16; i++) bnIn2.m_pValue[i] = (i + 1) * 31;
  time(&start);

  for (i = 0; i < unum; i++)
    mpBinaryExtendedGCD(bnIn1, bnIn2, bnIn3, bnIn4, bnIn5);

  time(&finish);

  elapsedseconds = difftime(finish, start);
  ops = (double)num;
  opspersecond = ops / elapsedseconds;
  printf("GCDtestBin  : %10.2f seconds, %10d operations, %10.1f ops/second\n",
         elapsedseconds, num, opspersecond);

  return true;
#endif
}

// ---------------------------------------------------------------------

#define ENCRYPT 1
#define DECRYPT 2

int main(int an, char** av) {
  int i;
  int mode = ENCRYPT;
  int numBlocks = 1024;
  RSAKey* pKey = NULL;
  char* szKeyFile = NULL;
  char* szBlockFile = NULL;
  bool fFast = false;
  bool fSanityOnly = false;
  bool fAdd = false;
  bool fSub = false;
  bool fMultiply = false;
  bool fPureMultiply = false;
  bool fDiv = false;
  bool fExp = false;
  bool fMod = false;
  bool fGCD = false;
  bool fBinaryGCD = false;
  bool fSlowSquare = false;
  bool fFastSquare = false;
  bool fEncrypt = false;
  bool fDecrypt = false;
  bool fMontEncrypt = false;
  bool fMontDecrypt = false;
  int file = -1;

  UNUSEDVAR(mode);
  for (i = 0; i < an; i++) {
    if (strcmp(av[i], "-help") == 0 || an < 3) {
      printf("\nUsage: rsaspeedtest keyfile -Encrypt blocks\n");
      printf("         rsaspeedtest keyfile -Decrypt blocks\n");
      printf("         rsaspeedtest keyfile -MontEncrypt blocks\n");
      printf("         rsaspeedtest keyfile -MontDecrypt blocks\n");
      printf("         rsaspeedtest keyfile -PureMultiply blocks\n");
      printf("         rsaspeedtest keyfile -Add blocks\n");
      printf("         rsaspeedtest keyfile -Sub blocks\n");
      printf("         rsaspeedtest keyfile -Multiply blocks\n");
      printf("         rsaspeedtest keyfile -SlowSquare blocks\n");
      printf("         rsaspeedtest keyfile -FastSquare blocks\n");
      printf("         rsaspeedtest keyfile -Div blocks\n");
      printf("         rsaspeedtest keyfile -Exp blocks\n");
      printf("         rsaspeedtest keyfile -GCD blocks\n");
      printf("         rsaspeedtest keyfile -BinaryGCD blocks\n");
      printf("         rsaspeedtest keyfile -sanity file\n");
      printf("         rsaspeedtest (other args) -fast\n");
      return 0;
    }

    if (strcmp(av[i], "-PureMultiply") == 0) {
      fPureMultiply = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-Add") == 0) {
      fAdd = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-Sub") == 0) {
      fSub = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-Multiply") == 0) {
      fMultiply = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-SlowSquare") == 0) {
      fSlowSquare = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-FastSquare") == 0) {
      fFastSquare = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-Div") == 0) {
      fDiv = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-Mod") == 0) {
      fMod = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-Exp") == 0) {
      fExp = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-GCD") == 0) {
      fGCD = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-BinaryGCD") == 0) {
      fBinaryGCD = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-Encrypt") == 0) {
      fEncrypt = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }
    if (strcmp(av[i], "-Decrypt") == 0) {
      fDecrypt = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-MontEncrypt") == 0) {
      fMontEncrypt = true;
      fEncrypt = true;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }
    if (strcmp(av[i], "-MontDecrypt") == 0) {
      fMontDecrypt = true;
      fEncrypt = false;
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }

    if (strcmp(av[i], "-fast") == 0) {
      fFast = true;
    }

    if (strcmp(av[i], "-sanity") == 0) {
      fSanityOnly = true;
      if (an > (i + 1)) {
        szBlockFile = av[++i];
      }
    }
  }

  if (!(fSanityOnly || fAdd || fSub || fMultiply || fPureMultiply || fDiv ||
        fExp || fMod || fGCD || fEncrypt || fDecrypt || fMontEncrypt ||
        fMontDecrypt || fSlowSquare || fFastSquare || fBinaryGCD)) {
    printf("No recognised function\n");
    return 1;
  }

  initCryptoRand();
  initBigNum();

  if (fPureMultiply) {
    if (Puremult(numBlocks)) return 0;
    return 1;
  } else if (fAdd) {
    if (Addtest(numBlocks)) return 0;
    return 1;
  } else if (fMultiply) {
    if (Multiplytest(numBlocks)) return 0;
    return 1;
  } else if (fSlowSquare) {
    if (SlowSquaretest(numBlocks)) return 0;
    return 1;
  } else if (fFastSquare) {
    if (FastSquaretest(numBlocks)) return 0;
    return 1;
  } else if (fSub) {
    if (Subtest(numBlocks)) return 0;
    return 1;
  } else if (fDiv) {
    if (Divtest(numBlocks)) return 0;
    return 1;
  } else if (fExp) {
    if (Exptest(numBlocks)) return 0;
    return 1;
  } else if (fMod) {
    if (Modtest(numBlocks)) return 0;
    return 1;
  } else if (fGCD) {
    if (GCDtest(numBlocks)) return 0;
    return 1;
  } else if (fBinaryGCD) {
    if (BinaryGCDtest(numBlocks)) return 0;
    return 1;
  }

  szKeyFile = av[1];
  pKey = (RSAKey*)ReadKeyfromFile(szKeyFile);
  if (pKey == NULL) {
    printf("Cant read key file\n");
    return 1;
  }

  if (fSanityOnly) {
    if (szBlockFile == NULL) {
      printf("No block file\n");
      return 1;
    }
    file = open(szBlockFile, O_RDONLY);
    if (file < 0) {
      printf("Cant open block file\n");
      return 1;
    }
    if (RSASanityCheck(pKey, file, false, fFast)) {
      printf("PASSED all sanity check operations\n");
    } else {
      printf("FAILED some sanity check operations\n");
    }
  }

  if (fEncrypt) {
    EncryptTest(pKey, numBlocks, fFast, true);
  }

  if (fDecrypt) {
    EncryptTest(pKey, numBlocks, fFast, false);
  }

  if (fMontEncrypt) {
    MontEncryptTest(pKey, numBlocks, true);
  }

  if (fMontDecrypt) {
    MontEncryptTest(pKey, numBlocks, false);
  }

  closeCryptoRand();

  return 0;
}

// -------------------------------------------------------------------------
