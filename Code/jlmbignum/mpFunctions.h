//
//  File: mpFunctions.h
//  Description: Function definitions for jmbignum
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
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


// ---------------------------------------------------------------------------------

#ifndef _MPFUNCTIONS_H__
#define _MPFUNCTIONS_H__
#include "bignum.h"


bool            mpCopyWords(int iSizeA, u64* puA, int iSizeB, u64* puB);
void            mpZeroNum(bnum& bnN);
int             mpWordsinNum(i32 iLen, u64* puN);
void            ZeroWords(i32 iLen, u64* puN);
void            mpNormalizeZero(bnum& bnA);
void            mpTrimNum(bnum& bnA);
i32             mpUCompare(bnum& bnA, bnum& bnB);
i32             mpCompare(bnum& bnA, bnum& bnB);
i32             max2PowerDividing(bnum& bnA);
i32             MaxBit(u64 uW);
i32             mpBitsinNum(i32 iSize, u64* rguN);
bool            IsBitPositionNonZero(bnum& bnN, i32 iPos);
void     	printNum(bnum& bnA, bool fFull=false);
void            initBigNum();

u64             mpUAdd(bnum& bnA, bnum& bnB, bnum& bnR);
u64             mpUAddTo(bnum& bnA, bnum& bnB);
u64             mpUSub(bnum& bnA, bnum& bnB, bnum& bnR, u64 uBorrow=0);
u64             mpUSubFrom(bnum& bnA, bnum& bnB);
u64             mpAddTo(bnum& bnA, bnum& bnB);
u64             mpSubFrom(bnum& bnA, bnum& bnB);
u64             mpDec(bnum& bnN);
u64             mpInc(bnum& bnN);
u64             mpSingleUAddTo(bnum& bnA, u64 uA);
u64             mpUSingleMultBy(bnum& bnA, u64 uB);
bool            mpUMult(bnum& bnA, bnum& bnB, bnum& bnR);
bool            mpUSingleMultAndShift(bnum& bnA, u64 uB, i32 iShift, bnum& bnR);
bool            mpShift(bnum& bnA, i32 iShiftNumBits, bnum& bnR);
bool            mpSingleUDiv(bnum& bnA, u64 uB, bnum& bnQ, u64* puRem, bool fZero=true);
bool            mpUDiv(bnum& bnA, bnum& bnB, bnum& bnQ, bnum& bnR);
bool            mpAdd(bnum& bnA, bnum& bnB, bnum& bnR);
bool            mpSub(bnum& bnA, bnum& bnB, bnum& bnR);
bool            mpMult(bnum& bnA, bnum& bnB, bnum& bnR);
bool            mpDiv(bnum& bnA, bnum& bnB, bnum& bnQ, bnum& bnR);

bool            mpMod(bnum& bnA, bnum& bnM, bnum& bnR);
bool            mpModNormalize(bnum& bnA, bnum& bnM);
bool            mpModAdd(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR);
bool            mpModSub(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR);
bool            mpModMult(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR);
bool            mpModInv(bnum& bnA, bnum& bnM, bnum& bnR);
bool            mpModDiv(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR);
bool            mpModExp(bnum& bnBase, bnum& bnExp, bnum& bnM, bnum& bnR);
bool            mpSlidingModExp(bnum& bnBase, bnum& bnExp, bnum& bnM, bnum& bnR,
                            int r, bnum& bnMPrime, bnum& bnRmodM, bnum& bnRsqmodM);
bool            mpModisSquare(bnum& bnX, bnum& bnM);
bool            mpTonelliShanks(bnum& bnX, bnum& bnP, bnum& bnR);
bool            mpModSquareRoot(bnum& bnX, bnum& bnM, bnum& R);

bool            mpShiftInPlace(bnum& bnA, int iShiftNumBits);
bool            mpExtendedGCD(bnum& bnA, bnum& bnB, bnum& bnX, 
                                    bnum& bnY, bnum& bnG);
bool            mpCRT(bnum& bnA1, bnum& bnM1, bnum& bnA2, bnum& bnM2, bnum& bnR);

bool            mpUSquare(bnum& bnA,bnum& bnR);

bool            mpGenPrime(i32 iBitSize, bnum& bnA, int iConfid=20);
bool            mpRSAGen(int iNumBits, bnum& bnE, bnum& bnP, bnum& bnQ, 
                         bnum& bnM, bnum& bnD, bnum& bnOrder);
bool            mpRSACalculateFastRSAParameters(bnum& bnE, bnum& bnP, bnum& bnQ, 
                    bnum& bnPM1, bnum& bnDP, bnum& bnQM1, bnum& bnDQ);
bool            mpRSAENC(bnum& bnMsg, bnum& bnE, bnum& bnM, bnum& bnR);
bool            mpRSADEC(bnum& bnMsg, bnum& bnP, bnum& bnPM1, bnum& bnDP, 
                    bnum& bnQ, bnum& bnQM1, bnum& bnDQ, bnum& bnM, bnum& bnR);
bool            mpRSAMontDEC(bnum& bnMsg, bnum& bnP, bnum& bnPM1, bnum& bnDP,
                             bnum& bnQ, bnum& bnQM1, bnum& bnDQ, bnum& bnM, 
                             bnum& bnR, int r, bnum& bnDPrime, bnum& bnDRmodP, 
                             bnum& bnDRsqmodP, bnum& bnQPrime, bnum& bnQRmodP, 
                             bnum& bnQRsqmodP);
bool            mpMontInit(int r, bnum& bnM, bnum& bnMPrime, bnum& bnRmodM, 
                                  bnum& bnRsqmodM);
bool            mpMontModExp(bnum& bnBase, bnum& bnExp, bnum& bnM, bnum& bnOut,
                             int r, bnum& bnMPrime, bnum& bnRmodM, bnum& bnRsqmodM);

bool            ConvertToDecimalString(bnum& bnA, i32 iStringSize, char* szNumber);
bool            ConvertFromDecimalString(bnum& bnA, const char* szNumber);
#endif



// ---------------------------------------------------------------------------------


