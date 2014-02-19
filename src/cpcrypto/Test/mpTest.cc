//
//  mpTest.cpp: Multiple Precision Arithmetic for jmbignum
//          Basic tests
//  (c) Copyright 2001-2013, John Manferdelli
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

//
//      mpTest.cpp: Multiple Precision Arithmetic for jmbignum
//              Basic tests
//      (c) Copyright 2001-2011, John Manferdelli
//

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "bignum.h"
#include "jlmcrypto.h"
#include "mpFunctions.h"
#include "logging.h"
#include "cryptoHelper.h"
#include "fastArith.h"
#include "ecc.h"
#include "nist.h"
#include "jlmUtility.h"

// ---------------------------------------------------------------------------------

//  Test structure

class numinit {
 public:
  int numWords;
  u64* rg;
};

class testinit {
 public:
  char* comment;
  int in1;
  int in2;
  u64 uparameter;
  int iparameter;
};

#ifdef OLD
int s_isEqualTo = s_iIsEqualTo;
int s_isLessThan = s_iIsLessThan;
int s_isGreaterThan = s_iIsGreaterThan;
#endif

// ---------------------------------------------------------------------------------

struct genRSATest {
  const char* m_szComment;
  const char* m_szE;
  const char* m_szP;
  const char* m_szQ;
};

genRSATest rgCases[] = {{"Bug 1",
                         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAE=",
                         "gRkcZgx2jDYWhnCIImmD07tCxPrYENos7wnQCY0z9g1hsItQY8eKC"
                         "ykJ9DcVOqEY0DGQfEPSHDpez3X+BWyjxQ==",
                         "+no9z0cOuoNSPAmLSPEhG8S0XtbeAwB5vVDpOBGQsxzbn1xtoiqyA"
                         "5vL6ztCiI8H4McUNVaeSgnGdk8IQI5cl3=="}, };

// ---------------------------------------------------------------------------------

#define NUMINITIALIZERS 20

u64 rguTest1[2] = {0xffffffffffffffffULL, 0xffffffffffffffffULL};
u64 rguTest2[2] = {0x0101010100000000ULL, 0xccccaaaaeeeebbbbULL};
u64 rguTest3[3] = {0xccccaaaa01010101ULL, 0xeeeebbbb33333333ULL};
u64 rguTest4[2] = {0ULL, 0x0000000400000000ULL};
u64 rguTest5[3] = {0ULL, 0x0000000500000000ULL, 0x0000000000000000ULL};
u64 rguTest6[2] = {0x0000008100000000ULL, 0x0000000000000000ULL};
u64 rguTest7[3] = {0xccccaaaa01010101ULL, 0xeeeebbbb33333333ULL,
                   0x00356ab299771254ULL};
u64 rguTest8[4] = {0ULL, 0xccccaaaa01010101ULL, 0xeeeebbbb33333333ULL,
                   0x00356ab299771254ULL};
u64 rguTest10[7] = {0x00000b255a6beefdULL, 0xf7ee4e1f44d6d60cULL,
                    0x565bfcecf309e0d0ULL, 0xe4c2b4b837e8591cULL,
                    0x1d3605a82eb76d22ULL, 0xa90a55e332313240ULL};
u64 rguTest11[2] = {0x0ULL, 0x1ULL};
u64 rguTest12[4] = {0xffffffffffffffffULL, 0xffffffffffffffffULL,
                    0xffffffffffffffffULL, 0xffffffffffffffffULL};
u64 rguCarryTest1[4] = {0x00000b255a6beefdULL, 0x00000b255a6beef0ULL, 0ULL};
u64 rguCarryTest1a[4] = {0x00000b255a6beefdULL, 0x000000000000000ULL};
u64 rguCarryTest2[4] = {0x00000b255a6beef0ULL, 0x00000b255a6beefdULL, 0ULL};
u64 rguCarryTest2a[4] = {0x00000b255a6beefdULL, 0x000000000000000ULL};
u64 rgudiv1[4] = {0xffff555205050505, 0x0000000000000002};
u64 rgudiv2[4] = {0xf7b5147a87dd32d4, 0x0000000000000002};

u64 rgudivbug1A[8] = {0x31422645a3b30df9, 0x36cd02a1a93a6d4e,
                      0x07142aaebc5c4d91, 0x822392071130c692,
                      0x336a2a6d27326c96, 0x906efef0c626aee3,
                      0x6b37ebffcb2452b8, 0x8a6fd278ae4ee55e};
u64 rgudivbug1B[4] = {0x2b1628268ab5acd6, 0xcb03e0028709eff5,
                      0x2fb92baeee16d107, 0x3c00ed20e0494db1};

// Initializes
numinit rgInitializers[] = {
  // int numWords, u64* rg
  {2, rguTest1},        // Entry 00
  {2, rguTest2},        // Entry 01
  {3, rguTest3},        // Entry 02
  {2, rguTest4},        // Entry 03
  {3, rguTest5},        // Entry 04
  {2, rguTest6},        // Entry 05
  {3, rguTest7},        // Entry 06
  {4, rguTest8},        // Entry 07
  {7, rguTest10},       // Entry 08
  {2, rguTest11},       // Entry 09
  {4, rguTest12},       // Entry 10
  {4, rguCarryTest1},   // Entry 10
  {2, rguCarryTest1a},  // Entry 12
  {4, rguCarryTest2},   // Entry 13
  {2, rguCarryTest2a},  // Entry 14
  {2, rgudiv1},         // Entry 15
  {2, rgudiv2}          // Entry 16
};

bnum* rgbn[NUMINITIALIZERS];

testinit copytestData[] = {
  // comment, in1; in2; uparameter; iparamater;
  {(char*)"Copy 1", 0, 0, 0, 0}, {(char*)"Copy 2", 7, 0, 0, 0}
};
testinit maxtestData[] = {{(char*)"MaxBit 1", 0, 0, 0, 0},
                          {(char*)"MaxBit 2", 1, 0, 0, 0},
                          {(char*)"MaxBit 3", 2, 0, 0, 0},
                          {(char*)"MaxBit 4", 3, 0, 0, 0}};
testinit shifttestData[] = {
  //  comment,  in1;  in2;  uparameter; iparamater;
  {(char*)"Shift 1", 0, 0, 0, 4}, {(char*)"Shift 2", 0, 0, 0, 72},
  {(char*)"Shift 3", 0, 0, 0, 20}, {(char*)"Shift 4", 0, 0, 0, 84},
  {(char*)"Shift 5", 0, 0, 0, -4}, {(char*)"Shift 6", 0, 0, 0, -72},
  {(char*)"Shift 7", 0, 0, 0, -20}, {(char*)"Shift 8", 0, 0, 0, -84}
};
testinit ucomparetestData[] = {{(char*)"Unsigned compare 1", 1, 1, 0, 0},
                               {(char*)"Unsigned compare 2", 5, 5, 0, 0},
                               {(char*)"Unsigned compare 3", 14, 13, 0, 0},
                               {(char*)"Unsigned compare 4", 13, 14, 0, 0},
                               {(char*)"Unsigned compare 4", 11, 10, 0, 0},
                               {(char*)"Unsigned compare 4", 10, 11, 0, 0},
                               {(char*)"Unsigned compare 5", 8, 7, 0, 0},
                               {(char*)"Unsigned compare 6", 7, 8, 0, 0}, };
testinit usingleaddtestData[] = {
  {(char*)"AddTo  1", 0, 0, 0x1, 0}, {(char*)"AddTo  2", 1, 0, 0x1, 0},
  {(char*)"AddTo  3", 2, 0, 0x1, 0}, {(char*)"AddTo  4", 3, 0, 0x1, 0},
  {(char*)"AddTo  5", 4, 0, 0x1, 0}, {(char*)"AddTo  6", 5, 0, 0x1, 0},
  {(char*)"AddTo  7", 6, 0, 0x1, 0}, {(char*)"AddTo  8", 7, 0, 0x1, 0},
  {(char*)"AddTo  9", 8, 0, 0x1, 0}, {(char*)"AddTo 10", 9, 0, 0x1, 0},
  {(char*)"AddTo 11", 10, 0, 0x1, 0}, {(char*)"AddTo 12", 11, 0, 0x1, 0},
  {(char*)"AddTo 13", 12, 0, 0x1, 0}, {(char*)"AddTo 14", 13, 0, 0x1, 0},
  {(char*)"AddTo 15", 13, 0, 0x1, 0}, {(char*)"AddTo 16", 0, 0, 0xf, 0},
  {(char*)"AddTo 17", 1, 0, 0xf, 0}, {(char*)"AddTo 18", 2, 0, 0xf, 0},
  {(char*)"AddTo 19", 3, 0, 0xf, 0}, {(char*)"AddTo 20", 4, 0, 0xf, 0},
  {(char*)"AddTo 21", 5, 0, 0xf, 0}, {(char*)"AddTo 22", 6, 0, 0xf, 0},
  {(char*)"AddTo 23", 7, 0, 0xf, 0}, {(char*)"AddTo 24", 8, 0, 0xf, 0},
  {(char*)"AddTo 25", 9, 0, 0xf, 0}, {(char*)"AddTo 26", 10, 0, 0xf, 0},
  {(char*)"AddTo 27", 11, 0, 0xf, 0}, {(char*)"AddTo 28", 12, 0, 0xf, 0},
  {(char*)"AddTo 29", 13, 0, 0xf, 0}, {(char*)"AddTo 30", 14, 0, 0xf, 0},
};
testinit uaddtestData[] = {
  {(char*)"Add  1", 0, 0, 0x0, 0}, {(char*)"Add  2", 1, 0, 0x0, 0},
  {(char*)"Add  3", 2, 0, 0x0, 0}, {(char*)"Add  4", 3, 0, 0x0, 0},
  {(char*)"Add  5", 4, 0, 0x0, 0}, {(char*)"Add  6", 5, 0, 0x0, 0},
  {(char*)"Add  7", 6, 0, 0x0, 0}, {(char*)"Add  8", 7, 0, 0x0, 0},
  {(char*)"Add  9", 8, 0, 0x0, 0}, {(char*)"Add 10", 9, 0, 0x0, 0},
  {(char*)"Add 11", 10, 0, 0x0, 0}, {(char*)"Add 12", 11, 0, 0x0, 0},
  {(char*)"Add 13", 12, 0, 0x0, 0}, {(char*)"Add 14", 13, 0, 0x0, 0},
  {(char*)"Add 15", 13, 0, 0x0, 0}, {(char*)"Add 16", 0, 1, 0x0, 0},
  {(char*)"Add 17", 1, 2, 0x0, 0}, {(char*)"Add 18", 2, 3, 0x0, 0},
  {(char*)"Add 19", 3, 4, 0x0, 0}, {(char*)"Add 20", 4, 5, 0x0, 0},
  {(char*)"Add 21", 5, 6, 0x0, 0}, {(char*)"Add 22", 6, 7, 0x0, 0},
  {(char*)"Add 23", 7, 8, 0x0, 0}, {(char*)"Add 24", 8, 9, 0x0, 0},
  {(char*)"Add 25", 9, 10, 0x0, 0}, {(char*)"Add 26", 10, 11, 0x0, 0},
  {(char*)"Add 27", 11, 12, 0x0, 0}, {(char*)"Add 28", 12, 13, 0x0, 0},
  {(char*)"Add 29", 13, 14, 0x0, 0}, {(char*)"Add 30", 14, 15, 0x0, 0},
};
testinit usinglemulttestData[] = {
  {(char*)"MultBy  1", 0, 0, 0x1, 0}, {(char*)"MultBy  2", 1, 0, 0x1, 0},
  {(char*)"MultBy  3", 2, 0, 0x2, 0}, {(char*)"MultBy  4", 3, 0, 0x2, 0},
  {(char*)"MultBy  5", 4, 0, 0x2, 0}, {(char*)"MultBy  6", 5, 0, 0x2, 0},
  {(char*)"MultBy  7", 6, 0, 0x2, 0}, {(char*)"MultBy  8", 7, 0, 0x2, 0},
  {(char*)"MultBy  9", 8, 0, 0x2, 0}, {(char*)"MultBy 10", 9, 0, 0x2, 0},
  {(char*)"MultBy 11", 10, 0, 0x2, 0}, {(char*)"MultBy 12", 11, 0, 0x2, 0},
  {(char*)"MultBy 13", 12, 0, 0x2, 0}, {(char*)"MultBy 14", 13, 0, 0x2, 0},
  {(char*)"MultBy 15", 13, 0, 0x2, 0}, {(char*)"MultBy 16", 0, 0, 0x10, 0},
  {(char*)"MultBy 17", 1, 0, 0x11, 0}, {(char*)"MultBy 18", 2, 0, 0x12, 0},
  {(char*)"MultBy 19", 3, 0, 0x14, 0}, {(char*)"MultBy 20", 4, 0, 0x18, 0},
  {(char*)"MultBy 21", 5, 0, 0x20, 0}, {(char*)"MultBy 22", 6, 0, 0x21, 0},
  {(char*)"MultBy 23", 7, 0, 0x22, 0}, {(char*)"MultBy 24", 8, 0, 0x24, 0},
  {(char*)"MultBy 25", 9, 0, 0x28, 0}, {(char*)"MultBy 26", 10, 0, 0x2f, 0},
  {(char*)"MultBy 27", 11, 0, 0xff, 0}, {(char*)"MultBy 28", 12, 0, 0x2f, 0},
  {(char*)"MultBy 29", 13, 0, 0xf0, 0}, {(char*)"MultBy 30", 14, 0, 0x2f, 0},
};
testinit usinglemultandshifttestData[] = {
  {(char*)"MultBy  1", 0, 0, 0x1, 1}, {(char*)"MultBy  2", 1, 0, 0x1, 1},
  {(char*)"MultBy  3", 2, 0, 0x2, 1}, {(char*)"MultBy  4", 2, 0, 0x2, 1},
  {(char*)"MultBy  5", 4, 0, 0x2, -1}, {(char*)"MultBy  6", 5, 0, 0x2, -1},
  {(char*)"MultBy  7", 6, 0, 0x2, 2}, {(char*)"MultBy  8", 7, 0, 0x2, -2},
  {(char*)"MultBy  9", 8, 0, 0x2, 0}, {(char*)"MultBy 10", 9, 0, 0x2, 0},
  {(char*)"MultBy 11", 10, 0, 0x2, 1}, {(char*)"MultBy 12", 11, 0, 0x2, 1},
  {(char*)"MultBy 13", 12, 0, 0x2, 2}, {(char*)"MultBy 14", 13, 0, 0x2, 2},
  {(char*)"MultBy 15", 13, 0, 0x2, 2}, {(char*)"MultBy 16", 0, 0, 0x10, 2},
  {(char*)"MultBy 17", 1, 0, 0x11, 1}, {(char*)"MultBy 18", 2, 0, 0x12, 1},
  {(char*)"MultBy 19", 3, 0, 0x14, 1}, {(char*)"MultBy 20", 4, 0, 0x18, -1},
  {(char*)"MultBy 21", 5, 0, 0x20, -1}, {(char*)"MultBy 22", 6, 0, 0x21, 1},
  {(char*)"MultBy 23", 7, 0, 0x22, 1}, {(char*)"MultBy 24", 8, 0, 0x24, -1},
  {(char*)"MultBy 25", 9, 0, 0x28, 1}, {(char*)"MultBy 26", 10, 0, 0x2f, 2},
  {(char*)"MultBy 27", 11, 0, 0xff, -2}, {(char*)"MultBy 28", 12, 0, 0x2f, 2},
  {(char*)"MultBy 29", 13, 0, 0xf0, 2}, {(char*)"MultBy 30", 14, 0, 0x2f, 2},
};

/*
testinit usubtracttestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit uaddtotestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit usubtractfromtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit umultiplytestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit udividetestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit usingledivtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit umultiplydividetestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};


testinit negatetestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit converttestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};

testinit comparetestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit singleaddtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit addtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit subtracttestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit addtotestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit subtractfromtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit singlemulttestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit singlemultandshifttestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit multiplytestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit dividetestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit singledivtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit multiplydividetestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit multiplydividetestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};


testinit gcdtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit crttestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};

testinit modaddtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit modmulttestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit modexptestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
testinit modinvtestData[] = {
    //  comment,  in1;  in2;  uparameter; iparamater;
};
*/

bool initNums() {
  int i, j;

  for (i = 0; i < (int)(sizeof(rgInitializers) / sizeof(numinit)); i++) {
    rgbn[i] = new bnum(rgInitializers[i].numWords);
    if (rgbn[i] == NULL) {
      printf("Cannot initialize bignum %d\n", i);
      return false;
    }
    for (j = 0; j < rgInitializers[i].numWords; j++) {
      rgbn[i]->m_pValue[j] = rgInitializers[i].rg[j];
    }
  }

  return true;
}

const char* g_szRandTestfile = "random.bin";

// ECC Signature example over P-256
// Q=dB
// E is hash
// K is random int
// D is private key

u64 tmpsig256D[4] = {0xC477F9F65C22CCE2ULL, 0x0657FAA5B2D1D812ULL,
                     0x2336F851A508A1EDULL, 0x04E479C34985BF96ULL};
u64 tmpsig256Qx[4] = {0xB7E08AFDFE94BAD3ULL, 0xF1DC8C734798BA1CULL,
                      0x62B3A0AD1E9EA2A3ULL, 0x8201CD0889BC7A19ULL};
u64 tmpsig256Qy[4] = {0x3603F747959DBF7AULL, 0x4BB226E419287290ULL,
                      0x63ADC7AE43529E61ULL, 0xB563BBC606CC5E09ULL};
u64 tmpsig256K[4] = {0x7A1A7E52797FC8CAULL, 0xAA435D2A4DACE391ULL,
                     0x58504BF204FBE19FULL, 0x14DBB427FAEE50AEULL};
u64 tmpsig256Rx[4] = {0x2B42F576D07F4165ULL, 0xFF65D1F3B1500F81ULL,
                      0xE44C316F1F0B3EF5ULL, 0x7325B69ACA46104FULL};
u64 tmpsig256E[4] = {0xA41A41A12A799548ULL, 0x211C410C65D8133AULL,
                     0xFDE34D28BDD542E4ULL, 0xB680CF2899C8A8C4ULL};
u64 tmpsig256Kinv[4] = {0x62159E5BA9E712FBULL, 0x098CCE8FE20F1BEDULL,
                        0x8346554E98EF3C7CULL, 0x1FC3332BA67D87EFULL};
u64 tmpsig256R[4] = {0x2B42F576D07F4165ULL, 0xFF65D1F3B1500F81ULL,
                     0xE44C316F1F0B3EF5ULL, 0x7325B69ACA46104FULL};
u64 tmpsig256S[4] = {0xDC42C2122D6392CDULL, 0x3E3A993A89502A81ULL,
                     0x98C1886FE69D262CULL, 0x4B329BDB6B63FAF1ULL};

// ---------------------------------------------------------------------------------

extern bnum g_bnZero;
extern bnum g_bnTwo;
extern bnum g_bnOne;

char uCompareSymbol(bnum& bnA, bnum& bnB) {
  int r = mpUCompare(bnA, bnB);

  switch (r) {
    default:
      return '?';
    case 1:
      return '>';
    case -1:
      return '<';
    case 0:
      return '=';
  }
}

// 3 (mod 4)
//#define TP 19
// 5 (mod 8)
//#define TP 13
// 1 (mod 8)
#define TP 17
#define MAXSQR 64

bool squareRootTest() {
  bnum bnA(1);
  bnum bnP(1);
  bnum bnS(1);
  bool fSquare;
  int i;

  bnP.m_pValue[0] = (u64)TP;
  for (i = 1; i < TP; i++) {
    bnA.m_pValue[0] = (u64)i;
    fSquare = mpModisSquare(bnA, bnP);
    if (!fSquare) {
      printf("%d is not a square root mod %d\n", i, TP);
      continue;
    }
    if (!mpModSquareRoot(bnA, bnP, bnS)) {
      printf("Cant find square root of %d mod %d\n", i, TP);
    }
    printf("sqrt(%d) (mod %d)= %d\n", i, TP, (int)bnS.m_pValue[0]);
  }

  // generate some squares and use NIST primes to check square roots

  // initialize NIST curves
  if (!initNist()) {
    printf("squareRoot: initnist failed\n");
    return false;
  }

  bnum bnX(6);
  bnum bnY(6);
  bnum bnZ(6);

  bnX.m_pValue[1] = 0x0f0e0d0c0b0a0900ULL;
  bnX.m_pValue[2] = 0x0102030405060708ULL;
  for (i = 1; i < MAXSQR; i++) {
    bnX.m_pValue[0] = (u64)i;
    fSquare = mpModisSquare(bnX, *nist256curve.m_bnM);
    if (!fSquare) {
      printNumberToConsole(bnX);
      printf("is not a square root mod nist256 prime\n");
      continue;
    }
    if (!mpModSquareRoot(bnX, *nist256curve.m_bnM, bnY)) {
      printf("Cant find square root of ");
      printNumberToConsole(bnX);
      printf("mod nist prime\n");
      return false;
    }
    printf("sqrt(%d) (mod %d)= %d\n", i, TP, (int)bnS.m_pValue[0]);
    printf("sqrt(");
    printNumberToConsole(bnX);
    printf(")= ");
    printNumberToConsole(bnY);
    printf("\n");
    mpModMult(bnY, bnY, *nist256curve.m_bnM, bnZ);
    if (mpCompare(bnX, bnZ) == 0) {
      printf("\t**MATCH\n");
    } else {
      printf("\t**NO MATCH\n");
      return false;
    }
  }

  return true;
}

bool eccTest() {
#ifdef SMALLTEST
  ECurve smallCurve;

  // E: y^2= x^3+4x+4 (mod 5) (1,2)+(4,3)=(4,2)
  smallCurve.m_bnM = new bnum(1);
  smallCurve.m_bnA = new bnum(1);
  smallCurve.m_bnB = new bnum(1);
  smallCurve.m_bnDisc = new bnum(1);
  smallCurve.m_bnM->m_pValue[0] = 5ULL;
  smallCurve.m_bnA->m_pValue[0] = 4ULL;
  smallCurve.m_bnB->m_pValue[0] = 4ULL;

  ECPoint P(&smallCurve, 1);
  ECPoint Q(&smallCurve, 1);
  ECPoint R(&smallCurve, 1);

  printf("\n\nE: y^2= x^3+4x+4 (mod 5) (1,2)+(4,3)=(4,2)\n");
  P.m_bnX = new bnum(1);
  P.m_bnY = new bnum(1);
  P.m_bnZ = new bnum(1);
  P.m_bnX->m_pValue[0] = 1ULL;
  P.m_bnY->m_pValue[0] = 2ULL;
  P.m_bnZ->m_pValue[0] = 1ULL;

  Q.m_bnX = new bnum(1);
  Q.m_bnY = new bnum(1);
  Q.m_bnZ = new bnum(1);
  Q.m_bnX->m_pValue[0] = 4ULL;
  Q.m_bnY->m_pValue[0] = 3ULL;
  Q.m_bnZ->m_pValue[0] = 1ULL;

  R.m_bnX = new bnum(1);
  R.m_bnY = new bnum(1);
  R.m_bnZ = new bnum(1);
  R.m_bnZ->m_pValue[0] = 1ULL;

  ecAdd(P, Q, R);
  P.printMe(true);
  printf("+");
  Q.printMe(true);
  printf("=");
  R.printMe(true);

  // E: y^2= x^3+4x+4 (mod 2773) 2(1,3)=(1771,705)
  printf("\n\nE: y^2= x^3+4x+4 (mod 2773) 2(1,3)=(1771,705)\n");
  P.m_bnX->m_pValue[0] = 1ULL;
  P.m_bnY->m_pValue[0] = 3ULL;
  P.m_bnZ->m_pValue[0] = 1ULL;

  Q.m_bnX->m_pValue[0] = 1ULL;
  Q.m_bnY->m_pValue[0] = 3ULL;
  Q.m_bnZ->m_pValue[0] = 1ULL;

  R.m_bnX->m_pValue[0] = 0ULL;
  R.m_bnY->m_pValue[0] = 0ULL;
  R.m_bnZ->m_pValue[0] = 1ULL;

  smallCurve.m_bnM->m_pValue[0] = 2773ULL;
  ecAdd(P, Q, R);
  P.printMe(true);
  printf("+");
  Q.printMe(true);
  printf("=");
  R.printMe(true);
  printf("?=(%d,%d)\n", R.m_bnX->m_pValue[0], R.m_bnY->m_pValue[0]);

  bnum bnMult(1);
  bnMult.m_pValue[0] = 1ULL;

  R.m_bnX->m_pValue[0] = 0ULL;
  R.m_bnY->m_pValue[0] = 0ULL;
  R.m_bnZ->m_pValue[0] = 1ULL;
  ecMult(P, bnMult, R);
  printf("\n");
  printNumberToConsole(bnMult);
  printf("*");
  P.printMe(true);
  printf("=");
  R.printMe(true);

  bnMult.m_pValue[0] = 2ULL;

  R.m_bnX->m_pValue[0] = 0ULL;
  R.m_bnY->m_pValue[0] = 0ULL;
  R.m_bnZ->m_pValue[0] = 1ULL;
  ecMult(P, bnMult, R);
  printf("\n");
  printNumberToConsole(bnMult);
  printf("*");
  P.printMe(true);
  printf("=");
  R.printMe(true);
#endif

  // initialize NIST curves
  if (!initNist()) {
    printf("eccTest: initnist failed\n");
    return false;
  }

#ifdef TEST
  nist256curve.printMe(true);
#endif
  ECKey myKey(&nist256curve);

  myKey.m_G = new ECPoint(&nist256curve, 4);
  myKey.m_Public = new ECPoint(&nist256curve, 4);
  ;
  myKey.m_secret = new bnum(4);
  if (!myKey.setGenerator(*nist256curve.m_bnGx, *nist256curve.m_bnGy)) {
    printf("eccTest: cant setGenerator()\n");
    return false;
  }
  if (!myKey.makePrivateKey()) {
    printf("eccTest: cant makePrivateKey()\n");
    return false;
  }
  if (!myKey.computePublic()) {
    printf("eccTest: cant computePublic()\n");
    return false;
  }
#ifdef TEST
  myKey.printMe(true);
#endif

  bnum Message(6);
  ECPoint R1(&nist256curve, 6);
  ECPoint R2(&nist256curve, 6);
  bnum decryptedMessage(6);

  Message.m_pValue[0] = 0x01234ULL;

  printf("ECC Test, nist 256 curve, message: ");
  printNumberToConsole(Message);
  printf("\n");

  if (!ecEncrypt(myKey, Message, R1, R2)) {
    printf("Cant ecEncrypt\n");
    return false;
  }
  printf("Encrypted message: ");
  R1.printMe(true);
  R2.printMe(true);
  if (!ecDecrypt(myKey, R1, R2, decryptedMessage)) {
    printf("Cant ecDecrypt\n");
    return false;
  }
  printf("Decrypted message: ");
  printNumberToConsole(decryptedMessage);
  printf("\n");

  bnum bnH(6);
  bnum bnR(6);
  bnum bnS(6);

  bnH.m_pValue[0] = 0x1234567890abcdefULL;
  printf("Message to sign, NIST-256: ");
  printNumberToConsole(bnH);
  printf("\n");

  if (!ecSign(myKey, bnH, bnR, bnS)) {
    printf("Cant ecSign\n");
    return false;
  }
  printf("Signature, R: ");
  printNumberToConsole(bnR);
  printf("\n");
  printf("Signature, S: ");
  printNumberToConsole(bnS);
  printf("\n");

  bool fRet = ecVerify(myKey, bnH, bnR, bnS);
  if (fRet) {
    printf("Signature verifies\n");
  } else {
    printf("Signature DOES NOT verify\n");
    return false;
  }

#ifdef TEST
  extern bool ecSignwithgivennonce(ECKey & K, bnum & bnH, bnum & bnK,
                                   bnum & bnR, bnum & bnS);
  mpZeroNum(bnR);
  mpZeroNum(bnS);
  int i;
  for (i = 0; i < 4; i++) myKey.m_secret->m_pValue[3 - i] = tmpsig256D[i];
  myKey.computePublic();
  bnum bnK(5);
  bnum bnRcheck(5);
  bnum bnScheck(5);
  for (i = 0; i < 4; i++) bnK.m_pValue[3 - i] = tmpsig256K[i];
  for (i = 0; i < 4; i++) bnRcheck.m_pValue[3 - i] = tmpsig256R[i];
  for (i = 0; i < 4; i++) bnScheck.m_pValue[3 - i] = tmpsig256S[i];
  for (i = 0; i < 4; i++) bnH.m_pValue[3 - i] = tmpsig256E[i];

  printf("\nTest Message to sign, NIST-256: ");
  printNumberToConsole(bnH);
  printf("\n");

  if (!ecSignwithgivennonce(myKey, bnH, bnK, bnR, bnS)) {
    printf("Cant ecSign\n");
    return false;
  }
  printf("Signature, R: ");
  printNumberToConsole(bnR);
  printf("\n");
  printf("Signature, S: ");
  printNumberToConsole(bnS);
  printf("\n");

  fRet = ecVerify(myKey, bnH, bnR, bnS);
  if (fRet) {
    printf("Signature verifies\n");
  } else {
    printf("Signature DOES NOT verify\n");
    return false;
  }
  if (mpCompare(bnR, bnRcheck) == 0 || mpCompare(bnS, bnScheck) == 0) {
    printf("Signature matched standard\n");
  } else {
    printf("Signature DID NOT match standard\n");
    fRet = false;
  }

#endif

  return true;
}

bool singlersaTest(RSAKey* pKey, int sizein, byte* in, bool fFast = false) {
  bool fRet = true;
  byte out[1024];
  byte recovered[1024];
  int m, n;
  u32 useprivate = USEPRIVATE;

  n = 1024;
  if (!RSASeal(*pKey, USEPUBLIC, sizein, in, &n, out)) {
    printf("singlersaTest: RSASeal failed\n");
    fRet = false;
    goto done;
  }
  m = 1024;
  if (fFast) useprivate = USEPRIVATEFAST;
  if (!RSAUnseal(*pKey, useprivate, n, out, &m, recovered)) {
    printf("singlersaTest: RSAUnseal failed\n");
    fRet = false;
    goto done;
  }
  printf("RSAUnseal returns %d bytes\n", m);
  if (memcmp(in, recovered, sizein) != 0) {
    printf("singlersaTest: input and recovered dont match\n");
    fRet = false;
  }

done:
  return fRet;
}

bool squaretests() {
  bool fRet = true;
  bnum bnOut1(32);
  bnum bnOut2(32);
  bnum bnOut3(32);
  int i;

  printf("squaretestData tests\n");
  bnOut1.m_pValue[0] = 0xffffffffffffffffULL;
  bnOut1.m_pValue[1] = 0xffffffffffffffffULL;
  bnOut1.m_pValue[2] = 0xffffffffffffffffULL;
  if (!mpUSquare(bnOut1, bnOut2)) {
    printf("mpUSquare reports error test 1\n");
    fRet = false;
  }
  if (!mpUMult(bnOut1, bnOut1, bnOut3)) {
    printf("mpUMult reports error test 1\n");
    fRet = false;
  }
  if (mpUCompare(bnOut2, bnOut3) != s_isEqualTo) {
    printf("MISMATCH test 1\n");
    fRet = false;
  }
  printNumberToConsole(bnOut1);
  printf("**2= \n");
  printNumberToConsole(bnOut2);
  printf("\n");
  printNumberToConsole(bnOut1);
  printf("**2= \n");
  printNumberToConsole(bnOut3);
  printf("\n");
  mpZeroNum(bnOut1);
  mpZeroNum(bnOut2);

  for (i = 0; i < (int)(sizeof(rgInitializers) / sizeof(numinit)); i++) {
    if (!mpUSquare(*rgbn[i], bnOut1)) {
      printf("mpUSquare reports error\n");
      fRet = false;
    }
    if (!mpUMult(*rgbn[i], *rgbn[i], bnOut2)) {
      printf("mpUMult reports error\n");
      fRet = false;
    }
    if (mpUCompare(bnOut2, bnOut1) != s_isEqualTo) {
      printf("MISMATCH\n");
      fRet = false;
    } else {
      printf("MATCH\n");
    }

    printNumberToConsole(*rgbn[i]);
    printf("**2= \n");
    printNumberToConsole(bnOut1);
    printf("\n");
    printf("Normal alg says: ");
    printNumberToConsole(bnOut2);
    printf("\n");
    mpZeroNum(bnOut1);
    mpZeroNum(bnOut2);
    printf("\n");
  }

  return fRet;
}

bool copytests() {
  bool fRet = true;
  bnum bnOut(10);
  int i;
  int i1;

  printf("copytestData, %d tests\n",
         (int)(sizeof(copytestData) / sizeof(testinit)));
  for (i = 0; i < (int)(sizeof(copytestData) / sizeof(testinit)); i++) {
    mpZeroNum(bnOut);
    i1 = copytestData[i].in1;
    rgbn[i1]->mpCopyNum(bnOut);
    printf("%d Copied ", i + 1);
    printNumberToConsole(*rgbn[i1]);
    printf("\n  to\n  ");
    printNumberToConsole(bnOut);
    printf("\n");
  }

  return fRet;
}

bool keygenrestoretest() {
  bool fRet = true;
  RSAKey* pKey = RSAGenerateKeyPair(1024);
  if (pKey == NULL) {
    printf("keygenrestoretest: cant generate key\n");
    return false;
  }

  printf("keygenrestoretest:\n");
  pKey->printMe(true);
  printf("\n");

  char* szKey = pKey->SerializetoString();
  if (szKey == NULL) {
    printf("keygenrestoretest: can't serialize key\n");
    return false;
  }
  if (!saveBlobtoFile("keytest.xml", (byte*)szKey, strlen(szKey) + 1)) {
    printf("keygenrestoretest: can't save key\n");
    return false;
  }

  printf("reading key\n");
  fflush(stdout);
  RSAKey* pKeyAgain = (RSAKey*)ReadKeyfromFile("keytest.xml");
  if (pKeyAgain == NULL) {
    printf("keygenrestoretest: can't reread key\n");
    return false;
  }

  printf("keygenrestoretest reprinting key:\n");
  fflush(stdout);
  pKey->printMe(true);
  printf("\n");

  return fRet;
}

bool maxbittests() {
  bool fRet = true;
  int i;
  int i1;
  int i2;

  printf("MaxBit, %d tests\n", (int)(sizeof(copytestData) / sizeof(testinit)));
  for (i = 0; i < (int)(sizeof(maxtestData) / sizeof(testinit)); i++) {
    i1 = maxtestData[i].in1;
    i2 = MaxBit(rgbn[i1]->m_pValue[0]);
    printf("%d MaxBit, maxbit in %016lx is %d\n", i + 1, rgbn[i1]->m_pValue[0],
           i2);
  }
  return fRet;
}

bool shifttests() {
  bool fRet = true;
  bnum bnOut(10);
  int i;
  int i1;
  int param1;

  printf("shifttestData, %d tests\n",
         (int)(sizeof(shifttestData) / sizeof(testinit)));
  for (i = 0; i < (int)(sizeof(shifttestData) / sizeof(testinit)); i++) {
    mpZeroNum(bnOut);
    i1 = shifttestData[i].in1;
    param1 = shifttestData[i].iparameter;
    mpShift(*rgbn[i1], param1, bnOut);
    printf("%d ", i + 1);
    printNumberToConsole(*rgbn[i1]);
    if (param1 >= 0)
      printf(" << %02d = ", param1);
    else
      printf(" >> %02d = ", -param1);
    printNumberToConsole(bnOut);
    printf("\n");
  }

  return fRet;
}

bool usingleaddtests() {
  bool fRet = true;
  bnum bnOut(10);
  int i;
  int i1;
  u64 param2;

  printf("usingleaddtestData, %d tests\n",
         (int)(sizeof(usingleaddtestData) / sizeof(testinit)));
  for (i = 0; i < (int)(sizeof(usingleaddtestData) / sizeof(testinit)); i++) {
    mpZeroNum(bnOut);
    i1 = usingleaddtestData[i].in1;
    rgbn[i1]->mpCopyNum(bnOut);
    param2 = usingleaddtestData[i].uparameter;
    mpSingleUAddTo(bnOut, param2);
    printf("%d ", i + 1);
    printNumberToConsole(*rgbn[i1]);
    printf("\n  +  %016lx =\n  ", param2);
    printNumberToConsole(bnOut);
    printf("\n");
  }

  return fRet;
}

bool monttests() {
  bool fRet = true;
  int i = 0;

  RSAKey* pKey = RSAGenerateKeyPair(1024);
  byte testmessage[32] = {0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01,
                          0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
                          0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03,
                          0x04, 0x01, 0x02, 0x03, 0x04};
  if (pKey == NULL) {
    printf("montTests: cant generate key\n");
    return false;
  }
#ifdef TEST
  pKey->printMe(true);
  printf("\n");
#endif

  bnum bnIn(pKey->m_iByteSizeM);
  bnum bnEncrypted(pKey->m_iByteSizeM);
  bnum bnDecrypted(pKey->m_iByteSizeM);
  bnum bnRmodM(pKey->m_iByteSizeM);
  bnum bnRsqmodM(pKey->m_iByteSizeM);
  bnum bnMPrime(pKey->m_iByteSizeM);

  int r = pKey->m_iByteSizeM / sizeof(u64);

  if (!mpMontInit(r, *(pKey->m_pbnM), bnMPrime, bnRmodM, bnRsqmodM)) {
    printf("RSA Montgomery: can't initialize Montgomery components\n");
    return false;
  }

  memcpy(bnIn.m_pValue, testmessage, 32);

  for (i = 0; i < 15; i++) {
    if (!mpModExp(bnIn, *(pKey->m_pbnE), *(pKey->m_pbnM), bnEncrypted)) {
      printf("Can't encrypt\n");
      return false;
    }
    if (!mpMontModExp(bnEncrypted, *(pKey->m_pbnD), *(pKey->m_pbnM),
                      bnDecrypted, r, bnMPrime, bnRmodM, bnRsqmodM)) {
      printf("Can't decrypt\n");
      return false;
    }
    printf("In       : ");
    printNumberToConsole(bnIn);
    printf("\n");
    printf("Encrypted: ");
    printNumberToConsole(bnEncrypted);
    printf("\n");
    printf("Decrypted: ");
    printNumberToConsole(bnDecrypted);
    printf("\n");

    if (mpUCompare(bnIn, bnDecrypted) == s_isEqualTo) {
      printf("match\n");
    } else {
      printf("mismatch\n");
      fRet = false;
    }
    mpZeroNum(bnEncrypted);
    mpZeroNum(bnDecrypted);
    bnIn.m_pValue[0]++;
  }
  return fRet;
}

// ---------------------------------------------------------------------------------

bool uaddtests() {
  bool fRet = true;
  bnum bnOut(10);
  int i;
  int i1;
  int i2;

  printf("uaddtestData, %d tests\n",
         (int)(sizeof(uaddtestData) / sizeof(testinit)));
  for (i = 0; i < (int)(sizeof(uaddtestData) / sizeof(testinit)); i++) {
    mpZeroNum(bnOut);
    i1 = uaddtestData[i].in1;
    i2 = uaddtestData[i].in2;
    mpUAdd(*rgbn[i1], *rgbn[i2], bnOut);
    printf("%d   ", i + 1);
    printNumberToConsole(*rgbn[i1]);
    printf("\n  + ");
    printNumberToConsole(*rgbn[i2]);
    printf("\n  = ");
    printNumberToConsole(bnOut);
    printf("\n");
  }

  return fRet;
}

bool usubtracttests() {
  bool fRet = true;
#if 0
    bnum    bnOut(10);
    int     i2;
    int     param1;
    u64     param2;

    printf("copytestData, %d tests\n", (int)(sizeof(copytestData)/sizeof(testinit)));
    for(i=0;i<(int)(sizeof(copytestData)/sizeof(testinit)); i++) {
        mpZeroNum(bnOut);
        i1= copytestData[i].in1;
        rgbn[i1]->mpCopyNum(bnOut);
        printf("%d Copied ", i+1); 
        printNumberToConsole(*rgbn[i1]); 
        printf("\n  to\n  "); 
        printNumberToConsole(bnOut); 
        printf("\n");
    }
#endif

  return fRet;
}

bool uaddtotests() {
  bool fRet = true;
#if 0
    bnum    bnOut(10);
    int     i2;
    int     param1;
    u64     param2;

    printf("copytestData, %d tests\n", (int)(sizeof(copytestData)/sizeof(testinit)));
    for(i=0;i<(int)(sizeof(copytestData)/sizeof(testinit)); i++) {
        mpZeroNum(bnOut);
        i1= copytestData[i].in1;
        rgbn[i1]->mpCopyNum(bnOut);
        printf("%d Copied ", i+1); 
        printNumberToConsole(*rgbn[i1]); 
        printf("\n  to\n  "); 
        printNumberToConsole(bnOut); 
        printf("\n");
    }
#endif

  return fRet;
}

bool usubfromtests() {
  bool fRet = true;
#if 0
    bnum    bnOut(10);
    int     i2;
    int     param1;
    u64     param2;

    printf("copytestData, %d tests\n", (int)(sizeof(copytestData)/sizeof(testinit)));
    for(i=0;i<(int)(sizeof(copytestData)/sizeof(testinit)); i++) {
        mpZeroNum(bnOut);
        i1= copytestData[i].in1;
        rgbn[i1]->mpCopyNum(bnOut);
        printf("%d Copied ", i+1); 
        printNumberToConsole(*rgbn[i1]); 
        printf("\n  to\n  "); 
        printNumberToConsole(bnOut); 
        printf("\n");
    }
#endif

  return fRet;
}

bool usinglemulttests() {
  bool fRet = true;
  bnum bnOut(10);
  int i;
  int i1;
  u64 param2;

  printf("usinglemulttestData, %d tests\n",
         (int)(sizeof(usinglemulttestData) / sizeof(testinit)));
  for (i = 0; i < (int)(sizeof(usinglemulttestData) / sizeof(testinit)); i++) {
    mpZeroNum(bnOut);
    i1 = usinglemulttestData[i].in1;
    rgbn[i1]->mpCopyNum(bnOut);
    param2 = usingleaddtestData[i].uparameter;
    mpUSingleMultBy(bnOut, param2);
    printf("%d ", i + 1);
    printNumberToConsole(*rgbn[i1]);
    printf("\n  *  %016lx =\n  ", param2);
    printNumberToConsole(bnOut);
    printf("\n");
  }

  return fRet;
}

bool usinglemultandshifttests() {
  bool fRet = true;
  bnum bnOut(128);
  int i;
  int i1;
  int param1;
  u64 param2;

  printf("usinglemultandshifttestData, %d tests\n",
         (int)(sizeof(usinglemultandshifttestData) / sizeof(testinit)));
  for (i = 0;
       i < (int)(sizeof(usinglemultandshifttestData) / sizeof(testinit)) - 1;
       i++) {
    mpZeroNum(bnOut);
    i1 = usinglemultandshifttestData[i].in1;
    param1 = usinglemultandshifttestData[i].iparameter;
    param2 = usinglemultandshifttestData[i].uparameter;
    // mpUSingleMultAndShift(*rgbn[i1], param2, param1, bnOut);
    printf("%d ", i + 1);
    printNumberToConsole(*rgbn[i1]);
    printf("\n  *  %016lx << %d =\n  ", param2, param1);
    printNumberToConsole(bnOut);
    printf("\n");
  }

  return fRet;
}

bool umultiplytests() {
  bool fRet = true;
#if 0
    bnum    bnOut(10);
    int     i2;
    int     param1;
    u64     param2;

    printf("copytestData, %d tests\n", (int)(sizeof(copytestData)/sizeof(testinit)));
    for(i=0;i<(int)(sizeof(copytestData)/sizeof(testinit)); i++) {
        mpZeroNum(bnOut);
        i1= copytestData[i].in1;
        rgbn[i1]->mpCopyNum(bnOut);
        printf("%d Copied ", i+1); 
        printNumberToConsole(*rgbn[i1]); 
        printf("\n  to\n  "); 
        printNumberToConsole(bnOut); 
        printf("\n");
    }
#endif

  return fRet;
}

bool ucomparetests() {
  bool fRet = true;
  int i;
  int i1;
  int i2;
  char c;

  printf("ucomparetestData, %d tests\n",
         (int)(sizeof(ucomparetestData) / sizeof(testinit)));
  for (i = 0; i < (int)(sizeof(ucomparetestData) / sizeof(testinit)); i++) {
    i1 = ucomparetestData[i].in1;
    i2 = ucomparetestData[i].in2;
    c = uCompareSymbol(*rgbn[i1], *rgbn[i2]);
    printf("%d ", i + 1);
    printNumberToConsole(*rgbn[i1]);
    printf(" %c  ", c);
    printNumberToConsole(*rgbn[i2]);
    printf("\n");
  }

  return fRet;
}

bool udividetests() {
  bnum bnA(128);
  bnum bnB(128);
  bnum bnQ(128);
  bnum bnR(128);
  bnum bnX(128);
  bnum bnY(128);
  bnum bnD(128);

  printf("special udividetests\n");
  mpZeroNum(bnA);
  mpZeroNum(bnB);
  mpZeroNum(bnQ);
  mpZeroNum(bnR);
  mpZeroNum(bnD);

  memcpy((byte*)bnA.m_pValue, (byte*)rgudivbug1A, 64);
  memcpy((byte*)bnB.m_pValue, (byte*)rgudivbug1B, 32);

  printf("A: ");
  printNumberToConsole(bnA);
  printf("\n");
  printf("B: ");
  printNumberToConsole(bnB);
  printf("\n");

  if (!mpUDiv(bnA, bnB, bnQ, bnR)) {
    printf("udividetests: mpUDiv fails\n");
    return false;
  }

  printf("quotient\n");
  printNumberToConsole(bnQ);
  printf("\n");
  printf("remainder\n");
  printNumberToConsole(bnR);
  printf("\n");

  if (!mpUMult(bnQ, bnB, bnX)) {
    printf("umultdiv: mpUMult failed\n");
    return false;
  }
  if (mpUAdd(bnX, bnR, bnY) != 0) {
    printf("umultdiv: mpUAdd failed\n");
    return false;
  }

  int lR = mpWordsinNum(bnR.mpSize(), bnR.m_pValue);
  int lB = mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
  if (lR > lB) {
    printf("umultdiv error: remainder larger than divisor\n");
    return false;
  }

  if (mpUCompare(bnA, bnY) == s_isEqualTo) return true;

  printf("X: ");
  printNumberToConsole(bnX);
  printf("\n");
  printf("Y: ");
  printNumberToConsole(bnY);
  printf("\n");
  mpSub(bnA, bnY, bnD);
  printf("Difference\n");
  printNumberToConsole(bnD);
  printf("\n\n");
  return false;
}

bool usingledivtests() {
  bool fRet = true;
#if 0
    bnum    bnOut(10);
    int     i2;
    int     param1;
    u64     param2;

    printf("copytestData, %d tests\n", (int)(sizeof(copytestData)/sizeof(testinit)));
    for(i=0;i<(int)(sizeof(copytestData)/sizeof(testinit)); i++) {
        mpZeroNum(bnOut);
        i1= copytestData[i].in1;
        rgbn[i1]->mpCopyNum(bnOut);
        printf("%d Copied ", i+1); 
        printNumberToConsole(*rgbn[i1]); 
        printf("\n  to\n  "); 
        printNumberToConsole(bnOut); 
        printf("\n");
    }
#endif

  return fRet;
}

int getNext(int iRead, int* pnumLeft, int* pnumUsed, byte* inbuf, int numtoget,
            byte* outbuf) {
  int numbytesgotten = 0;
  int numbytestoget = numtoget * sizeof(u64);
  int n;

  while (numbytestoget > 0) {
    if (*pnumLeft > 0) {
      if (*pnumLeft > numbytestoget)
        n = numbytestoget;
      else
        n = *pnumLeft;
      *pnumLeft -= n;
      memcpy(outbuf, &inbuf[*pnumUsed], n);
      outbuf += n;
      *pnumUsed += n;
      numbytesgotten += n;
      numbytestoget -= n;
    }

    if (numbytestoget <= 0) break;

    if (*pnumLeft <= 0) {
      n = read(iRead, inbuf, 8192);
      if (n <= 0) {
        return 0;
      }
      *pnumUsed = 0;
      *pnumLeft = n;
    }
  }

  return numbytesgotten;
}

bool umultdiv(bnum& bnA, bnum& bnB, bnum& bnQ, bnum& bnR, bnum& bnX,
              bnum& bnY) {
  bnum bnD(128);

//      a=bq+r
#ifdef PRINTNUMS
  printf("umultdiv\n");
  printNumberToConsole(bnA);
  printf("\n");
  printf("divided by\n");
  printNumberToConsole(bnB);
  printf("\n");
#endif

  if (!mpUDiv(bnA, bnB, bnQ, bnR)) {
    printf("umultdiv: mpUDiv fails\n");
    return false;
  }

#ifdef PRINTNUMS
  printf("quotient\n");
  printNumberToConsole(bnQ);
  printf("\n");
  printf("remainder\n");
  printNumberToConsole(bnR);
  printf("\n");
#endif

  if (!mpUMult(bnQ, bnB, bnX)) {
    printf("umultdiv: mpUMult failed\n");
    return false;
  }
  if (mpUAdd(bnX, bnR, bnY) != 0) {
    printf("umultdiv: mpUAdd failed\n");
    return false;
  }

  if (mpUCompare(bnA, bnY) != s_isEqualTo) {
    printf("umultdiv: a!=bq+r\n");
    printf("A\n");
    printNumberToConsole(bnA);
    printf("\n");
    printf("B\n");
    printNumberToConsole(bnB);
    printf("\n");
    printf("X\n");
    printNumberToConsole(bnX);
    printf("\n");
    printf("Y\n");
    printNumberToConsole(bnY);
    printf("\n\n");
    mpZeroNum(bnD);
    mpSub(bnA, bnY, bnD);
    printf("Difference\n");
    printNumberToConsole(bnD);
    printf("\n\n");
    return false;
  }

#if 1
  printf("umultdiv succeeded\n");
#endif
  return true;
}

bool umultiplydividetests() {
  bool fRet = true;
  bool fDone = false;
  int iRead = -1;
  byte buf[8192];
  int numUsed = 0;
  int numLeft = 0;

  //      a=bq+r
  bnum bnA(128);
  bnum bnB(128);
  bnum bnQ(128);
  bnum bnR(128);
  bnum bnX(128);
  bnum bnY(128);

  int sizeA;
  int sizeB;
  int i, j;

  iRead = open(g_szRandTestfile, O_RDONLY);
  if (iRead < 0) {
    printf("umultiplydividetests: cant open random number file\n");
    return false;
  }

  for (;;) {
    if (fDone) break;
    mpZeroNum(bnA);
    mpZeroNum(bnB);
    mpZeroNum(bnQ);
    mpZeroNum(bnR);
    mpZeroNum(bnX);
    mpZeroNum(bnY);
    for (i = 4; i < 128; i += 4) {
      if (fDone) break;
      sizeA = getNext(iRead, &numLeft, &numUsed, buf, i, (byte*)bnA.m_pValue);
      if (sizeA <= 0) {
        fDone = true;
        break;
      }
      for (j = 4; j <= i; j += 4) {
        sizeB = getNext(iRead, &numLeft, &numUsed, buf, j, (byte*)bnB.m_pValue);
        if (sizeB <= 0) {
          fDone = true;
          break;
        }
        if (!umultdiv(bnA, bnB, bnQ, bnR, bnX, bnY)) fRet = false;
      }
    }
  }

  if (iRead > 0) close(iRead);

  if (fRet)
    printf("umultiplydividetests completed, all tests PASSED\n");
  else
    printf("umultiplydividetests completed, some tests FAILED\n");

  return fRet;
}

bool negatetests() {
  bool fRet = true;
#if 0
    bnum    bnOut(10);
    int     i2;
    int     param1;
    u64     param2;

    printf("copytestData, %d tests\n", (int)(sizeof(copytestData)/sizeof(testinit)));
    for(i=0;i<(int)(sizeof(copytestData)/sizeof(testinit)); i++) {
        mpZeroNum(bnOut);
        i1= copytestData[i].in1;
        rgbn[i1]->mpCopyNum(bnOut);
        printf("%d Copied ", i+1); 
        printNumberToConsole(*rgbn[i1]); 
        printf("\n  to\n  "); 
        printNumberToConsole(bnOut); 
        printf("\n");
    }
#endif

  return fRet;
}

bool converttests() {
  bool fRet = true;
#if 0
    bnum    bnOut(10);
    int     i2;
    int     param1;
    u64     param2;

    printf("copytestData, %d tests\n", (int)(sizeof(copytestData)/sizeof(testinit)));
    for(i=0;i<(int)(sizeof(copytestData)/sizeof(testinit)); i++) {
        mpZeroNum(bnOut);
        i1= copytestData[i].in1;
        rgbn[i1]->mpCopyNum(bnOut);
        printf("%d Copied ", i+1); 
        printNumberToConsole(*rgbn[i1]); 
        printf("\n  to\n  "); 
        printNumberToConsole(bnOut); 
        printf("\n");
    }
#endif

  return fRet;
}

bool addtests() {
  bool fRet = true;

  return fRet;
}

bool subtracttests() {
  bool fRet = true;

  return fRet;
}

bool addtotests() {
  bool fRet = true;

  return fRet;
}

bool subfromtests() {
  bool fRet = true;

  return fRet;
}

bool multiplytests() {
  bool fRet = true;

  return fRet;
}

bool comparetests() {
  bool fRet = true;

  return fRet;
}

bool dividetests() {
  bool fRet = true;

  return fRet;
}

bool multiplydividetests() {
  bool fRet = true;

  return fRet;
}

bool gcdtests() {
  bool fRet = true;
  int i;
  int lP, lQ, lE;
  byte rgP[2048];
  byte rgQ[2048];
  byte rgE[2048];
  bnum bnP(128);
  bnum bnPM1(128);
  bnum bnQ(128);
  bnum bnQM1(128);
  bnum bnOrder(128);
  bnum bnE(128);
  bnum bnG(128);
  bnum bnX(128);
  bnum bnY(128);
  bnum bnGBinary(128);
  bnum bnXBinary(128);
  bnum bnYBinary(128);
  bnum bnTest1(128);
  bnum bnTest2(128);
  bnum bnTest3(128);

  printf("gcdtests, %d tests\n", (int)(sizeof(rgCases) / sizeof(genRSATest)));

  for (i = 0; i < (int)(int)(sizeof(rgCases) / sizeof(genRSATest)); i++) {

    // base64 convert m_szE, m_szP, m_szQ
    lP = 2048;
    lQ = 2048;
    lE = 2048;

    if (!bytesfrombase64((char*)rgCases[i].m_szE, &lE, rgE)) {
      printf("gcdtests: E conversion failed\n");
      return false;
    }
    if (!bytesfrombase64((char*)rgCases[i].m_szP, &lP, rgP)) {
      printf("gcdtests: P conversion failed\n");
      return false;
    }
    if (!bytesfrombase64((char*)rgCases[i].m_szQ, &lQ, rgQ)) {
      printf("gcdtests: Q conversion failed\n");
      return false;
    }

    memcpy((byte*)bnE.m_pValue, rgE, lE);
    memcpy((byte*)bnP.m_pValue, rgP, lP);
    memcpy((byte*)bnQ.m_pValue, rgQ, lQ);

    // Order= (P-1)(Q-1)
    mpUSub(bnP, g_bnOne, bnPM1);
    mpUSub(bnQ, g_bnOne, bnQM1);
    mpUMult(bnPM1, bnQM1, bnOrder);

    // X E+Y Order= G
    if (!mpExtendedGCD(bnE, bnOrder, bnX, bnY, bnG)) {
      printf("gcdtests: gcd failed\n");
      return false;
    }
#ifdef BINARYEXTENDEDGCD
    if (!mpBinaryExtendedGCD(bnE, bnOrder, bnXBinary, bnYBinary, bnGBinary)) {
      printf("gcdtests: gcd failed\n");
      return false;
    }
#endif
    // mpZeroNum(bnX);
    // mpZeroNum(bnY);
    // mpZeroNum(bnG);
    // mpZeroNum(bnXBinary);
    // mpZeroNum(bnYBinary);
    // mpZeroNum(bnGBinary);
  }

  printf("E     : ");
  printNumberToConsole(bnE);
  printf("\n");
  printf("Order : ");
  printNumberToConsole(bnOrder);
  printf("\n");
  printf("X     : ");
  printNumberToConsole(bnX);
  printf("\n");
  printf("Y     : ");
  printNumberToConsole(bnY);
  printf("\n");
  printf("GCD   : ");
  printNumberToConsole(bnG);
  printf("\n");

  printf("XBin  : ");
  printNumberToConsole(bnXBinary);
  printf("\n");
  printf("YBin  : ");
  printNumberToConsole(bnYBinary);
  printf("\n");
  printf("GCDBin: ");
  printNumberToConsole(bnGBinary);
  printf("\n");
  printf("\n");

  if (mpCompare(bnX, bnXBinary) != s_isEqualTo ||
      mpCompare(bnY, bnYBinary) != s_isEqualTo ||
      mpCompare(bnG, bnGBinary) != s_isEqualTo) {
    printf("Extended Euclid and Binary extended Euclid DO NOT agree\n");
    mpMult(bnE, bnXBinary, bnTest1);
    mpMult(bnOrder, bnYBinary, bnTest2);
    mpAdd(bnTest1, bnTest2, bnTest3);
    printf("A*X+B*Y: ");
    printNumberToConsole(bnTest3);
    printf("\n");
  } else {
    printf("Extended Euclid and Binary extended Euclid agree\n");
  }
  return fRet;
}

bool modaddtests() {
  bool fRet = true;

  return fRet;
}

bool modmulttests() {
  bool fRet = true;

  return fRet;
}

bool modexptests() {
  bool fRet = true;

  return fRet;
}

bool moddinvtests() {
  bool fRet = true;

  return fRet;
}

bool crttests() {
  bool fRet = true;

  return fRet;
}

bool primeGentests() {
  bool fRet = true;

  return fRet;
}

bool rsaTests() {
  bool fRet = true;
  int i;
  RSAKey* pKey = RSAGenerateKeyPair(1024);
  byte testmessage[32] = {0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01,
                          0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
                          0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03,
                          0x04, 0x01, 0x02, 0x03, 0x04};
  u64* pU = (u64*)testmessage;

  if (pKey == NULL) {
    printf("rsaTests: cant generate key\n");
    return false;
  }
#ifdef TEST
  pKey->printMe(true);
  printf("\n");
#endif

  for (i = 0; i < 100; i++) {
    if (singlersaTest(pKey, 32, testmessage, i > 75))
      printf("singlersaTest %d passed\n", i);
    else {
      fRet = false;
      printf("singlersaTest %d failed\n", i);
    }
    (*pU)++;
  }

  if (!fRet) {
    char* szKey = pKey->SerializetoString();
    if (szKey != NULL)
      saveBlobtoFile("FailedRSAKey", (byte*)szKey, strlen(szKey) + 1);
    printf("wrote FailedRSAKey\n");
  }

  return fRet;
}

// ---------------------------------------------------------------------------------

int main(int an, char** av) {
  bool fAllTests = true;
  const char* szFile = NULL;
  int iWrite = -1;
  int num = 0;
  byte buf[8192];
  int i;

  initBigNum();
  initCryptoRand();
  initLog("mpTest.log");

  printf("mpTests, use genRand option to generate new random tests (often to "
         "random.bin)\n");
  for (i = 1; i < an; i++) {
    if (strcmp(av[i], "-genRand") == 0) {
      szFile = av[++i];
      i++;
      num = atoi(av[i]);
      printf("Generate %d random numbers and put in %s\n", num, szFile);
      iWrite = open(szFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (iWrite < 0) {
        printf("cant open random number file %s\n", szFile);
        return 1;
      }
      while (num > 0) {
        if (!getCryptoRandom(NBITSINBYTE * 8192, buf)) {
          printf("getCryptoRandom cant generate enough bits\n");
          break;
        }
        if (write(iWrite, buf, 8192) < 0) {
          printf("write failed\n");
        }
        num -= 8192;
      }
      close(iWrite);
      printf("File generation complete\n");
      return 0;
    }
  }

#if 0
    bnum  bnA(8);
    bnum  bnB(8);
    bnum  bnX(8);
    bnum  bnY(8);
    bnum  bnG(8);
    bnA.m_pValue[0]= 1520ULL;
    bnB.m_pValue[0]= 2480ULL;
    if(mpBinaryExtendedGCD(bnA, bnB, bnX, bnY, bnG)) {
        printf("mpBinaryExtendedGCD, succeeded\n");
    }
    else {
        printf("mpBinaryExtendedGCD, failed\n");
    }

    printf("A: "); printNumberToConsole(bnA); printf("\n");
    printf("B: "); printNumberToConsole(bnB); printf("\n");
    printf("X: "); printNumberToConsole(bnX); printf("\n");
    printf("Y: "); printNumberToConsole(bnY); printf("\n");
    printf("G: "); printNumberToConsole(bnG); printf("\n");
    return 0;
#endif

  try {
    printf("mpTest\n\n");

    if (!initNums()) {
      throw((char*)"Cant init numbers");
    }

    if (eccTest()) {
      printf("eccTest succeeded\n");
    } else {
      fAllTests = false;
      printf("eccTest failed\n");
    }
    printf("\n");

    if (squareRootTest()) {
      printf("squareRootTest succeeded\n");
    } else {
      fAllTests = false;
      printf("squareRootTest failed\n");
    }
    printf("\n");

    if (monttests()) {
      printf("monttests succeeded\n");
    } else {
      fAllTests = false;
      printf("monttests failed\n");
    }
    printf("\n");

    if (squaretests()) {
      printf("squaretests succeeded\n");
    } else {
      fAllTests = false;
      printf("squaretests failed\n");
    }
    printf("\n");

    if (copytests()) {
      printf("copytests succeeded\n");
    } else {
      fAllTests = false;
      printf("copytests failed\n");
    }
    printf("\n");

    if (maxbittests()) {
      printf("maxbitstests succeeded\n");
    } else {
      fAllTests = false;
      printf("maxbitstests failed\n");
    }
    printf("\n");

    if (shifttests()) {
      printf("shifttests succeeded\n");
    } else {
      fAllTests = false;
      printf("shifttests failed\n");
    }
    printf("\n");

    if (usingleaddtests()) {
      printf("usingleaddtests succeeded\n");
    } else {
      fAllTests = false;
      printf("usingleaddtests failed\n");
    }
    printf("\n");

    if (uaddtests()) {
      printf("uaddtests succeeded\n");
    } else {
      fAllTests = false;
      printf("uaddtests failed\n");
    }
    printf("\n");

    if (usubtracttests()) {
      printf("usubtracttests succeeded\n");
    } else {
      fAllTests = false;
      printf("usubtracttests failed\n");
    }
    printf("\n");

    if (uaddtotests()) {
      printf("uaddtotests succeeded\n");
    } else {
      fAllTests = false;
      printf("uaddtotests failed\n");
    }
    printf("\n");

    if (usubfromtests()) {
      printf("subfromtests succeeded\n");
    } else {
      fAllTests = false;
      printf("subfromtests failed\n");
    }
    printf("\n");

    if (usinglemulttests()) {
      printf("usinglemulttests succeeded\n");
    } else {
      fAllTests = false;
      printf("usinglemulttests failed\n");
    }
    printf("\n");

    if (usinglemultandshifttests()) {
      printf("usinglemultandshifttests succeeded\n");
    } else {
      fAllTests = false;
      printf("usinglemultandshifttests failed\n");
    }
    printf("\n");

    if (ucomparetests()) {
      printf("ucomparetests succeeded\n");
    } else {
      fAllTests = false;
      printf("ucomparetests failed\n");
    }
    printf("\n");

    if (udividetests()) {
      printf("udividetests succeeded\n");
    } else {
      fAllTests = false;
      printf("udividetests failed\n");
    }
    printf("\n");

    if (usingledivtests()) {
      printf("usingledivtests succeeded\n");
    } else {
      fAllTests = false;
      printf("usingledivtests failed\n");
    }
    printf("\n");

    if (umultiplydividetests()) {
      printf("umultiplydividetests succeeded\n");
    } else {
      fAllTests = false;
      printf("umultiplydividetests failed\n");
    }
    printf("\n");

    if (negatetests()) {
      printf("negatetests succeeded\n");
    } else {
      fAllTests = false;
      printf("negatetests failed\n");
    }
    printf("\n");

    if (converttests()) {
      printf("converttests succeeded\n");
    } else {
      fAllTests = false;
      printf("converttests failed\n");
    }
    printf("\n");

    if (addtests()) {
      printf("addtests succeeded\n");
    } else {
      fAllTests = false;
      printf("addtests failed\n");
    }
    printf("\n");

    if (subtracttests()) {
      printf("subtracttests succeeded\n");
    } else {
      fAllTests = false;
      printf("subtracttests failed\n");
    }
    printf("\n");

    if (addtotests()) {
      printf("addtests succeeded\n");
    } else {
      fAllTests = false;
      printf("addtests failed\n");
    }
    printf("\n");

    if (subfromtests()) {
      printf("subfromtests succeeded\n");
    } else {
      fAllTests = false;
      printf("subfromtests failed\n");
    }
    printf("\n");

    if (multiplytests()) {
      printf("multiplytests succeeded\n");
    } else {
      fAllTests = false;
      printf("multiplytests failed\n");
    }
    printf("\n");

    if (comparetests()) {
      printf("comparetests succeeded\n");
    } else {
      fAllTests = false;
      printf("comparetests failed\n");
    }
    printf("\n");

    if (dividetests()) {
      printf("dividetests succeeded\n");
    } else {
      fAllTests = false;
      printf("dividetests failed\n");
    }
    printf("\n");

    if (multiplydividetests()) {
      printf("multiplydividetests succeeded\n");
    } else {
      fAllTests = false;
      printf("multiplydividetests failed\n");
    }
    printf("\n");

    if (gcdtests()) {
      printf("gcdtests succeeded\n");
    } else {
      fAllTests = false;
      printf("gcdtests failed\n");
    }
    printf("\n");

    if (modaddtests()) {
      printf("modaddtests succeeded\n");
    } else {
      fAllTests = false;
      printf("modaddtests failed\n");
    }
    printf("\n");

    if (modmulttests()) {
      printf("modmulttests succeeded\n");
    } else {
      fAllTests = false;
      printf("modmulttests failed\n");
    }
    printf("\n");

    if (modexptests()) {
      printf("modexptests succeeded\n");
    } else {
      fAllTests = false;
      printf("modexptests failed\n");
    }
    printf("\n");

    if (moddinvtests()) {
      printf("moddinvtests succeeded\n");
    } else {
      fAllTests = false;
      printf("moddinvtests failed\n");
    }
    printf("\n");

    if (crttests()) {
      printf("crttests succeeded\n");
    } else {
      fAllTests = false;
      printf("crttests failed\n");
    }
    printf("\n");

    if (primeGentests()) {
      printf("primeGentests succeeded\n");
    } else {
      fAllTests = false;
      printf("primeGentests failed\n");
    }
    printf("\n");

    if (rsaTests()) {
      printf("rsaTests succeeded\n");
    } else {
      fAllTests = false;
      printf("rsaTests failed\n");
    }
    printf("\n");

    if (!keygenrestoretest()) throw("Keytest failed");

    if (!udividetests()) throw((char*)"special test fails");

    if (fAllTests)
      printf("\nTests completed, all tests PASSED\n");
    else
      printf("\nTests completed, some tests FAILED\n");
    return 0;
  }
  catch (char * szError) {
    printf("\nMain Error! %s.\n", szError);
    return 1;
  }
}

// ----------------------------------------------------------------------------
