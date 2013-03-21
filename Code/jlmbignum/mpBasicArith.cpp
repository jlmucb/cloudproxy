//
//  File: mpBasicArith.cpp
//      Basic Multiple Precision Arithmetic for jmbignum
//      including Add, Subtract, Multiply, Divide
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
//  Some contributions may be (c) Intel Corporation
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
//  Number Format (bnum): 
//      Structure consisting of uLen32 digit0 digit1 ... digitn
//      Top bit of sLen is sign (1 means negative) remaining 31 bits are
//      the number of 64 bit words constituting the number low order words first.
//      Remaining 64 bit words are 64 bit unsigned quantities representing the
//      absolute value of the number, least significant word is first, most
//      significant is last.
//
//  References:
//      Knuth, SemiNumerical Algorithms
//      Menzes, Handbook of Applied Cryptography

#include <stdio.h> 
#include <stdlib.h> 
#include <fcntl.h> 
#include <string.h>
#include <unistd.h>

#include "bignum.h"
#include "logging.h"
#include "jlmUtility.h"


// ---------------------------------------------------------------------------------


bnum::bnum(int iSize)
{
    m_pValue= new u64[iSize];
    m_signandSize= (u32) iSize;
    for(int i=0; i<iSize; i++)
        m_pValue[i]= 0; 
}


bnum::~bnum()
{
    int iSize= mpSize();
    for(int i=0; i<iSize;i++)
        m_pValue[i]= 0; 
    delete m_pValue;
}


void mpNormalizeZero(bnum& bnA)
{
    int     i;
    u64*    puA;

    if(!bnA.mpSign())
        return;
    puA= bnA.m_pValue;
    for(i=0; i<bnA.mpSize(); i++) {
        if(*(puA++)!=0)
            return;
    }
    bnA.mpDumpSign();
    return;
}


//  Function: inline int mpWordsinNum
//  Arguments:
//      IN      i32 iLen
//      IN      u64* puN
//  Description:
//      Returns minumum number of words 
//      to represent number
int mpWordsinNum(i32 iLen, u64* puN)
{
    puN+= iLen-1;
    while(iLen>1) {
        if((*(puN--))!=0ULL)
            return(iLen);
        iLen--;
    }
    return(iLen);
}


bool bnum::mpCopyNum(bnum& bnC)  
// copy this into bnC
{
    extern bool mpCopyWords(int, u64*, int, u64*);
    int size=  mpSize();
    int sizeC= bnC.mpSize();
    int len= mpWordsinNum(size, m_pValue);
 
    if(len>sizeC)
        return false;   

    // copy Sign
    bnC.mpDumpSign();
    if(mpSign())
        bnC.mpNegate();
    return mpCopyWords(size, m_pValue, sizeC, bnC.m_pValue);
}


//  Function: void printNum
//  Arguments:
//      (bNum bnA)
void printNum(bnum& bnA, bool fFull=false)
{
    i32     sizeA= bnA.mpSize();
    bool    fSignA= bnA.mpSign();
    u64*    puN= NULL;
    i32     lA;

    if(sizeA<=0) {
        fprintf(g_logFile, "Bad number, no extent\n");
        return;
    }

    if(fSignA)
        fprintf(g_logFile, "[-");
    else
        fprintf(g_logFile, "[+");

    if(fFull) {
        puN= bnA.m_pValue+sizeA-1;
        while(sizeA-->0)  {
            fprintf(g_logFile, " 0x%016lx", *((unsigned long*)puN));
            puN--;
        }
    }
    else {
        lA= mpWordsinNum(sizeA, bnA.m_pValue);
        if(lA<=0)
            lA= 1;
        puN= bnA.m_pValue+lA-1;
        while(lA-->0)  {
            fprintf(g_logFile, " 0x%016lx", *((unsigned long*)puN));
            puN--;
        }
    }

    fprintf(g_logFile, "]");
    return;
}


// ----------------------------------------------------------------------------


//  Data:
//      Bignum representations of 0, 1 and 2
bnum    g_bnZero(1);
bnum    g_bnOne(1);
bnum    g_bnTwo(1);


void initBigNum()
{
    g_bnZero.m_pValue[0]= 0ULL;
    g_bnOne.m_pValue[0]= 1ULL;
    g_bnTwo.m_pValue[0]= 2ULL;
}


// ----------------------------------------------------------------------------


//
//      Basic Operations
//


//  Function: bool mpCopyWords
//  Arguments:
//      IN  int sizeA 
//      IN  int sizeB 
//      IN  u64* puA 
//      OUT u64* puB
//      Description:
//          Copies up to sizeB 64 bit words from puA to puB
//          if sizeA<sizeB the most significant slots are 0 filled
bool mpCopyWords(int sizeA, u64* puA, int sizeB, u64* puB)
{
    for(int i=0; i<sizeB; i++) {
        if(i<sizeA)
            *(puB++)= *(puA++);
        else
            *(puB++)= 0;
    }
    return true;
}


//  Function: bnum mpDuplicateNum
//  Arguments:
//      IN bnum bnA
//  Description:
//      Duplicate bnA and allocate an additional iPad (zero filled) words 
bnum* mpDuplicateNum(bnum& bnA)
{
    i32     sizeA=  bnA.mpSize();
    bnum*   bn= new bnum(sizeA);

    bn->m_signandSize= bnA.m_signandSize;
    for(int i=0; i<sizeA; i++)
        bn->m_pValue[i]=bnA.m_pValue[i];
    return(bn);
}


//  Function: void ZeroWords
//  Arguments:
//      IN      i32 len
//      INOUT   u32* puN
//  Description:
//      Zero len words in puN
void ZeroWords(i32 len, u64* puN)
{
    while(len-->0) 
        *(puN++)= 0;
}


//  Function: void mpZeroNum
//  Arguments:
//      IN      bnum bnN
//  Description:
//      Turn bN into a 0 but keep slot size the same
void mpZeroNum(bnum& bnN)
{
    ZeroWords(bnN.mpSize(), bnN.m_pValue);
}


//  Function: void mpTrimNum
//  Arguments:
//      INOUT   bnum bnA
//  Description:
//      Trim bnA to minimum number of words required
void mpTrimNum(bnum& bnA)
{
    u32     sign= bnA.m_signandSize&s_signBit;
    u32     k= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);

    if(k==0)
        bnA.m_signandSize= 0;
    else
        bnA.m_signandSize= sign|k;
}


// ----------------------------------------------------------------------------


//  Function: i32 mpUCompare
//  Arguments:
//      IN      bnum bnA
//      IN      bnum bnB
//  Description:
//      for positive bnA and bnB, return
//        s_isGreaterThan if bnA>bnB
//        s_isEqualTo if bnA==bnB
//        s_isLessThan if bnA<bnB
i32 mpUCompare(bnum& bnA, bnum& bnB)
{
    i32 sizeA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    i32 sizeB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);

    if(sizeA>sizeB)
        return(s_isGreaterThan);
    if(sizeA<sizeB)
        return(s_isLessThan);

    u64* puA= bnA.m_pValue+sizeA-1;
    u64* puB= bnB.m_pValue+sizeB-1;
    while(sizeA-->0) {
        if(*puA>*puB)
            return(s_isGreaterThan);
        if(*puA<*puB)
            return(s_isLessThan);
        puA--;
        puB--;
    }
    return(s_isEqualTo);
}


//  Function: i32 mpCompare
//  Arguments:
//      IN      bnum bnA
//      IN      bnum bnB
//  Description:
//      Compare bnA and bnB
//  Note if sign is negative, this assumes number is <0
i32 mpCompare(bnum& bnA, bnum& bnB)
{
    bool    fSignA= bnA.mpSign();
    bool    fSignB= bnB.mpSign();

    if(fSignA!=fSignB) {
        if(fSignA!=0)
            return s_isLessThan;
        return s_isGreaterThan;
    }
    if(fSignA)
        return -mpUCompare(bnA, bnB);
    else
        return mpUCompare(bnA, bnB);
}


// ----------------------------------------------------------------------------


//  Function: i32 max2PowerDividing
//  Arguments:
//      bnum bnA
//  Description:
//      Largest power of 2 dividing bnA
i32 max2PowerDividing(bnum& bnA)
{
    int     iMax= bnA.mpSize();
    u64*    rgA= bnA.m_pValue;
    int     i, j;
    u64     uX;
    u64     uOne= 1ULL;

    for(i=0; i<iMax; i++) {
        if(rgA[i]!=0ULL)
            break;
    }
    if(i>=iMax)
        return(-1);
    uX= rgA[i];
    for(j=0; j<NUMBITSINU64; j++) {
        if((uOne&uX)!=0)
            break;
        uOne<<= 1;
    }
    if(j>NUMBITSINU64MINUS1)
        j= 0;
    return i*NUMBITSINU64+j;
}


//  Function: int MaxBit
//  Arguments:
//      int uW
//  Description:
//      Return position of most significant non zero bit.
//      Least Significant bit is at position 1.  0 means no bit is on
int MaxBit(u64 uW)
{
    u64     uM=(1ULL<<NUMBITSINU64MINUS1);
    int     i= NUMBITSINU64;

    while(i>0) {
        if((uM&uW)!=0ULL)
            return(i);
        i--;
        uM>>= 1;
    }
    return 0;
}


//  Function: i32 mpBitsinNum
//  Arguments:
//      i32 iSize - Size of array
//      u32* rguN - Array of unsigned, least significant first
//  Description:
//      return most significant non-zero bit position.
i32 mpBitsinNum(i32 size, u64* rguN)
{
    int     numWords= mpWordsinNum(size, rguN);

    if(numWords==0)
        return 0;
    numWords--;
    int numBits= MaxBit(rguN[numWords]);
    return NUMBITSINU64*numWords+numBits;
}


//
//  Function: bool IsBitPositionNonZero
//  Arguments:
//      bnum bnN  (Note: Word size is important)
//      i32 pos
//  Description:
//      Is bit at position pos on?  
//      Bit 1 is LSB.
bool IsBitPositionNonZero(bnum& bnN, i32 pos)
{
    pos--;
    u64     uM= bnN.m_pValue[(pos/NUMBITSINU64)];

    pos&= 0x3f;
    if((uM&(1ULL<<pos))!=0)
        return true;
    return false;
}


// ----------------------------------------------------------------------------


//
//      Shift
//

inline u64 bottomMask64(int numBits)
{
    u64     uMask= -1ULL;

    uMask>>= (NUMBITSINU64-numBits);
    return uMask;
}


void shiftup(bnum& bnA, bnum& bnR, i32 numShiftBits)
{
    int         i;
    int         wordShift= (numShiftBits>>6);
    int         bitShift= numShiftBits&0x3f;
    int         bottomShift= 0;
    u64         bottomMask= 0ULL;
    u64         topMask= 0ULL;
    u64*        rgA= bnA.m_pValue;
    u64*        rgR= bnR.m_pValue;
    i32         lA= mpWordsinNum(bnA.mpSize(), rgA);
    u64         r, s, t;

    if(bitShift==0)
        bottomShift= 0;
    else
        bottomShift= NUMBITSINU64-bitShift;
    bottomMask= bottomMask64(bottomShift);
    topMask= (-1ULL)^bottomMask;

    t= rgA[lA-1];
    if(bitShift>0) {
        r= (t&topMask)>>bottomShift;
        rgR[lA+wordShift]= r;
    }
    s= (t&bottomMask)<<bitShift;

    for(i=(lA-1); i>0;i--) {
        t= rgA[i-1];
        r= (t&topMask)>>bottomShift;
        rgR[i+wordShift]|= s|r;
        s= (t&bottomMask)<<bitShift;
    }
    rgR[wordShift]= s;
}


void shiftdown(bnum& bnA, bnum& bnR, i32 numShiftBits)
{
    int         i;
    int         wordShift= (numShiftBits>>6);
    int         bitShift= numShiftBits&0x3f;
    u64         bottomMask= 0ULL;
    int         bottomShift;
    u64*        rgA= bnA.m_pValue;
    u64*        rgR= bnR.m_pValue;
    i32         lA= mpWordsinNum(bnA.mpSize(), rgA);
    u64         r, s, t;

    if(bitShift==0)
        bottomShift= 0;
    else
        bottomShift= NUMBITSINU64-bitShift;
    bottomMask= bottomMask64(bitShift);
    // topMask= bottomMask^(-1ULL);

    t= rgA[wordShift];
    s= t>>bitShift;
    for(i=0; i<(lA-wordShift); i++) {
        if((i+wordShift+1)<lA)
            t= rgA[i+wordShift+1];
        else
            t= 0ULL;
        r= (t&bottomMask)<<bottomShift;
        rgR[i]= s|r;
        s= t>>bitShift;
    }
}


//  Function: bool mpShift
//  Arguments:
//      IN bnum bnA
//      IN i32 numShiftBits
//      OUT bnum bnR
//  Description:
//      numShiftBits>0 means shift increases value
bool mpShift(bnum& bnA, i32 numShiftBits, bnum& bnR)
{
    i32     sizeA= bnA.mpSize();
    i32     sizeR= bnR.mpSize();

    // Enough room?
    if(sizeA+((numShiftBits+NUMBITSINU64MINUS1)/NUMBITSINU64)>sizeR)
        return false;

    mpZeroNum(bnR);
    if(numShiftBits==0) {
        bnA.mpCopyNum(bnR);
        return true;
    }

    if(numShiftBits>0) {
        shiftup(bnA, bnR, numShiftBits);
    }
    else {
        shiftdown(bnA, bnR, -numShiftBits);
    }

    return true;
}


// ----------------------------------------------------------------------------


//     Unsigned operations 
//          Assembly routines are are machine dependent

#include "fastArith.h"


//  Function: void mpUAdd (no inline)
//  Arguments:
//      IN bnum bnA 
//      IN bnum bnB
//      OUT bnum bnR
//  Description:
//      Addition of two non-negative numbers.  bnR = bnA + bnB
//  Return carry if there's no room
u64 mpUAdd(bnum& bnA, bnum& bnB, bnum& bnR)
{
    i32     lR= bnR.mpSize();
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    i32     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    u64     uCarry= 0ULL;

    if(lA<=0) {
        fprintf(g_logFile, "mpUAdd: first arg not a number\n");
        return 0ULL;
    }
    if(lB<=0) {
        fprintf(g_logFile, "mpUAdd: second arg not a number\n");
        return 0ULL;
    }

    if(lA>=lB) {
        if(lR<lA) {
            fprintf(g_logFile, "mpUAdd: Overflow\n");
            return 0ULL;
        }
        uCarry= mpUAddLoop(lA, bnA.m_pValue, lB, bnB.m_pValue, bnR.m_pValue);
        if(uCarry>0 && lR>lA) {
            bnR.m_pValue[lA]= uCarry;
            uCarry= 0ULL;
        }
    }
    else {
        if(lR<lB) {
            fprintf(g_logFile, "mpUAdd: Overflow\n");
            return 0ULL;
        }
        uCarry= mpUAddLoop(lB, bnB.m_pValue, lA, bnA.m_pValue, bnR.m_pValue);
        if(uCarry>0 && lR>lB) {
            bnR.m_pValue[lB]= uCarry;
            uCarry= 0ULL;
        }
    }
    return uCarry;
}


//  Function: u64 mpUAddTo (no inline)
//  Arguments:
//      INOUT bnum bnA
//      IN bnum bnB
//  Description:
//      bnA+= bnB, don't trim
//      Return carry if there's no room
u64 mpUAddTo(bnum& bnA, bnum& bnB)
{
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    i32     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    u64     uCarry= 0ULL;

    if(lA<=0) {
        fprintf(g_logFile, "mpUAddTo: first arg not a number\n");
        return 0ULL;
    }
    if(lB<=0) {
        fprintf(g_logFile, "mpUAddTo: second arg not a number\n");
        return 0ULL;
    }

    if(lA>=lB) {
        uCarry= mpUAddLoop(lA, bnA.m_pValue, lB, bnB.m_pValue, bnA.m_pValue);
        if(uCarry>0 && bnA.mpSize()>lA) {
            bnA.m_pValue[lA]= uCarry;
            uCarry= 0ULL;
        }
    }
    else {
        if(bnA.mpSize()<lB) {
            fprintf(g_logFile, "mpUAddTo: Overflow\n");
            return 0ULL;
        }
        uCarry= mpUAddLoop(lB, bnB.m_pValue, lA, bnA.m_pValue, bnA.m_pValue);
        if(uCarry>0 && bnA.mpSize()>lB) {
            bnA.m_pValue[lB]= uCarry;
            uCarry= 0ULL;
        }
    }
    return uCarry;
}


//  Function: u64 mpSingleUAddTo (no inline)
//  Arguments:
//      INOUT   bnum bnA
//      IN      u64 uA
//  Description:
//      bnA+= uA, don't trim
//  Return carry if there's no room
u64 mpSingleUAddTo(bnum& bnA, u64 uA)
{
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    u64     uCarry= 0ULL;

    if(lA<=0) {
        fprintf(g_logFile, "mpSingleUAddTo: first arg not a number\n");
        return 0ULL;
    }

    uCarry= mpUAddLoop(lA, bnA.m_pValue, 1, &uA, bnA.m_pValue);
    if(uCarry>0 && bnA.mpSize()>lA) {
        bnA.m_pValue[lA]= uCarry;
        uCarry= 0ULL;
    }
    return uCarry;
}


//  Function: u64 mpUSub (no inline)
//  Arguments:
//      IN bnum bnA
//      IN bnum bnB
//      OUT bnum bnR
//  Description:
//      Assumes there is enough room, size A >= size B
u64 mpUSub(bnum& bnA, bnum& bnB, bnum& bnR, u64 uBorrow=0)
{
    i32     lR= bnR.mpSize();
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    i32     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);

    if(lA<=0) {
        fprintf(g_logFile, "mpUSub: first arg not a number\n");
        return 0ULL;
    }
    if(lB<=0) {
        fprintf(g_logFile, ": second arg not a number\n");
        return 0ULL;
    }
    if(lA<lB) {
        fprintf(g_logFile, "mpUSub: second argument is bigger than first\n");
        return 0ULL;
    }

    if(lR<lA) {
        fprintf(g_logFile, "mpUSub: Overflow");
        return 0ULL;
    }
    uBorrow= mpUSubLoop(lA, bnA.m_pValue, lB, bnB.m_pValue, bnR.m_pValue, uBorrow);
    return uBorrow;
}


//  Function: u64 mpUSubFrom (no inline)
//  Arguments:
//      INOUT   bnum bnA
//      IN      bnum bnB
//  Description:
//      bnA-= bnB, don't trim
//      Return borrow
u64 mpUSubFrom(bnum& bnA, bnum& bnB)
{
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    i32     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    u64     uBorrow= 0ULL;

    if(lA<=0) {
        fprintf(g_logFile, "mpUSubFrom: first arg not a number\n");
        return 0ULL;
    }
    if(lB<=0) {
        fprintf(g_logFile, "mpUSubFrom: second arg not a number\n");
        return 0ULL;
    }
    if(lA<lB) {
        fprintf(g_logFile, "mpUSubFrom: second argument is bigger than first\n");
        return 0ULL;
    }

    uBorrow= mpUSubLoop(lA, bnA.m_pValue, lB, bnB.m_pValue, bnA.m_pValue, uBorrow);
    return uBorrow;
}


//  Function: u64 mpUSingleMultBy (no inline)
//  Arguments:
//      INOUT   bnum bnA
//      IN      u64  uB
//  return carry
u64 mpUSingleMultBy(bnum& bnA, u64 uB)
{
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    u64     uCarry= 0ULL;

    if(lA<=0) {
        fprintf(g_logFile, "mpUSingleMultBy: first arg not a number\n");
        return 0ULL;
    }
    if(uB==0) {
        ZeroWords(bnA.mpSize(), bnA.m_pValue);
        return 0ULL;
    }

    uCarry= mpUMultByLoop(lA, bnA.m_pValue, uB);
    if(uCarry>0 && bnA.mpSize()>lA) {
        bnA.m_pValue[lA]= uCarry;
        uCarry= 0;
    }
    return uCarry;
}


//  Function: bool mpUMult (no inline)
//  Arguments:
//      bnum bnA
//      bnum bnB
//      bnum bnR
//  Note: bnR is set to zero to compute bnA*bnB so calling
//      mpUMult(bnA, bnB, bnA);
//  will result in an error
bool mpUMult(bnum& bnA, bnum& bnB, bnum& bnR)
{
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    i32     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    u64     uCarry= 0ULL;
   
    if(lA<=0) {
        fprintf(g_logFile, "mpUMult: first arg not a number\n");
        return 0ULL;
    }
    if(lB<=0) {
        fprintf(g_logFile, "mpUMult: second arg not a number\n");
        return 0ULL;
    }
    if(bnR.mpSize()<(lA+lB)) {
        fprintf(g_logFile, "mpUMult: potential overflow %d, %d, %d\n",
                bnR.mpSize(), lA, lB);
        return false;
    }
    ZeroWords(bnR.mpSize(), bnR.m_pValue);

    if(lA>=lB) {
        uCarry= mpUMultLoop(lA, bnA.m_pValue, lB, bnB.m_pValue, bnR.m_pValue);
    }
    else {
        uCarry= mpUMultLoop(lB, bnB.m_pValue, lA, bnA.m_pValue, bnR.m_pValue);
    }
    if(uCarry==0)
        return true;

    if(bnR.mpSize()>(lA+lB-1)) {
        bnR.m_pValue[lA+lB-1]= uCarry;
        return true;
    }
    fprintf(g_logFile, "mpUMult: overflow\n");
    return false;
}


//  Function: bool mpUSingleMultAndShift (no inline)
//  Arguments:
//      bnum bnA
//      u32 uB
//      int shift (by full words)
//      bnum bnR
bool mpUSingleMultAndShift(bnum& bnA, u64 uB, int shift, bnum& bnR)
{
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    u64     uCarry= 0;

    ZeroWords(bnR.mpSize(), bnR.m_pValue);
    if(uB==0ULL || bnA.mpIsZero()) {
        return true;
    }

    if((lA+shift)>bnR.mpSize()) {
        fprintf(g_logFile, "mpUSingleMultAndShift: overflow\n");
        return false;
    }
    int lR= bnR.mpSize();
    mpCopyWords(lA, bnA.m_pValue, lR-shift, bnR.m_pValue+shift);
    uCarry= mpUMultByLoop(lR, bnR.m_pValue, uB);
    if(uCarry==0)
        return true;
    fprintf(g_logFile, "mpUSingleMultAndShift: overflow\n");
    return false;
}


//  Function: bool mpSingleUDiv (no inline)
//  Arguments:
//      bnum bnA, 
//      u32 uB, 
//      bNum bnR, 
//      u32* puRem, 
//      bool fZero=true
//  Note: uB>b/2
bool mpSingleUDiv(bnum& bnA, u64 uB, bnum& bnQ, u64* puRem, bool fZero=true)
{
    i32     i;
    u64*    rgA= bnA.m_pValue;
    int     lA= mpWordsinNum(bnA.mpSize(), rgA);
    u64     uRem= 0;
    int     sizeQ= bnQ.mpSize();
    u64*    rgQ= bnQ.m_pValue;

    if(uB==0L) {
        fprintf(g_logFile, "mpSingleUDiv: Division by 0\n");
        return false;
    }
    if(sizeQ<lA) {
        fprintf(g_logFile, "mpSingleUDiv: potential overflow\n");
        return false;
    }
    if(fZero)
        ZeroWords(sizeQ, bnQ.m_pValue);

    for(i=(lA-1); i>=0; i--)
        uRem= longdivstep(&rgQ[i], uRem, rgA[i], uB);

    *puRem= uRem;
    return true;
}


//  Function: void TwoDigitEstimateQuotient (no inline)
void TwoDigitEstimateQuotient(u64* pqE, u64 uHi, u64 uLo, u64 uLower, u64 vHi, u64 vLo)
{
    u64     uQ, uR;
    int     maxBit= MaxBit(vHi);
    int     shift= NUMBITSINU64-maxBit;
    u64     newv;
    u64     newuHi;
    u64     newuLo;
 
    if(maxBit==NUMBITSINU64) {
        newv= vHi;
        newuHi= uHi;
        newuLo= uLo;
    }
    else { 
        newv= (vHi<<shift)|(vLo>>maxBit);
        newuHi= (uHi<<shift)|(uLo>>maxBit);
        newuLo= (uLo<<shift)|(uLower>>maxBit);
    }

#ifdef ARITHTEST
    printf("Estimate quotient new u/v: %016lx %016lx %016lx, shift: %d, maxBit: %d\n", 
        newuHi, newuLo, newv, shift, maxBit);
#endif
    if(newuHi>=newv) {
        *pqE= (u64)-1;
        return;
    }

    uR= longdivstep(&uQ, newuHi, newuLo, newv);
    UNUSEDVAR(uR);
    *pqE= uQ;
    return;
}


//  Function: void EstimateQuotient (no inline)
//  Description:
//      Estimate Quotient.  
//          vM1!=0
//      qE= min(floor((uHi*r+uLo)/uDenom)), radix-1), rE= remainder. r is radix.
//      qE>= q >= qE-2, if uDenom>= floor(r/2);
//      if( qE==r || qE*uLower> r*rE+uNext) {
//          qE--; rE+= uDenom;
//      }
//      repeat if rE< r
void EstimateQuotient(u64* pqE, u64 uHi, u64 uLo, u64 uLower, u64 vHi, u64 vLo)
{
    u64     uQ, uR;
    int     maxBit= MaxBit(vHi);
    int     shift= NUMBITSINU64-maxBit;
    u64     newv;
    u64     newuHi;
    u64     newuLo;
 
    if(maxBit==NUMBITSINU64) {
        newv= vHi;
        newuHi= uHi;
        newuLo= uLo;
    }
    else { 
        newv= (vHi<<shift)|(vLo>>maxBit);
        newuHi= (uHi<<shift)|(uLo>>maxBit);
        newuLo= (uLo<<shift)|(uLower>>maxBit);
    }

#ifdef ARITHTEST
    printf("Estimate quotient new u/v: %016lx %016lx %016lx, shift: %d, maxBit: %d\n", 
        newuHi, newuLo, newv, shift, maxBit);
#endif
    uR= longdivstep(&uQ, newuHi, newuLo, newv);
    UNUSEDVAR(uR);
    *pqE= uQ;
    return;
}


// ----------------------------------------------------------------------------


bool notsmallerthan(u64* pA, u64* pB, int size)
{
    int i;

    for(i=0;i<size;i++) {
        if(*pA>*pB)
            return true;
        if(*pA<*pB)
            return false;
        pA--; pB--;
    }
    return true;
}


//  Function: bool mpUDiv
//  Arguments:
//      bNum bnA
//      bNum bnB
//      bNum bnQ
//      bNum bnR
//  Description:
//      Unsigned division a la Knuth
//      Uses the following theorem in the estimate quotient inline:
//          If U=u[n]b^n+..u[0], V=v[n-1]b^(n-1)+...+v[0] with u/b<v
//          qE= min([(u[n]b+u[n-1])/v[n-1]],b-1) then qE>=q.  
//          If v[n-1]>b/2, qE-2<=q<=qE.
//      At conclusion, rem:= rem/d
//          Note that this is the only one of the classical algorithms
//          that destroys the value of the arguments, so we copy them.
bool mpUDiv(bnum& bnA, bnum& bnB, bnum& bnQ, bnum& bnR)
{
    int     sizeA= bnA.mpSize();
    int     sizeB= bnB.mpSize();
    int     sizeQ= bnQ.mpSize();
    int     sizeR= bnR.mpSize();
    int     lA= mpWordsinNum(sizeA, bnA.m_pValue);
    int     lB= mpWordsinNum(sizeB, bnB.m_pValue);

    int     scaledA, scaledB;
    u64     uQ= 0;
    u64*    rgQ= bnQ.m_pValue;
    u64*    rgtA= NULL;
    u64*    rgtC= NULL;
    u64     uBHi, uBLo;
    int     i;
    int     compare;
    bool    fTwoDigitArgs;

#ifdef ARITHTEST      
    printf("mpUDiv: \n"); 
    printf("A: ");printNum(bnA);printf("\n");
    printf("B: ");printNum(bnB);printf("\n");
#endif
    if(bnB.mpIsZero()) {
        fprintf(g_logFile, "mpUDiv: Division by 0\n");
        return false;
    }
    int lQ= lA-lB+1;
    if(lQ>sizeQ) {
        fprintf(g_logFile, "mpUDiv: Quotient overflow\n");
        return false;
    }
    mpZeroNum(bnQ);
    mpZeroNum(bnR);

    if(mpCompare(bnA, bnB)==s_isLessThan) {
        if(sizeR<lA) {
            fprintf(g_logFile, "mpUDiv: Remainder overflow\n");
            return false;
        }
        bnA.mpCopyNum(bnR);
        return true;
    }
    if(sizeR<lB) {
        fprintf(g_logFile, "mpUDiv: Remainder overflow\n");
        return false;
    }

    // does bnB have length 1?
    if(lB==1) {
        mpSingleUDiv(bnA, bnB.m_pValue[0], bnQ, bnR.m_pValue, true);
        return true;
    }

    // Allocate Temporaries: one more digit than bnA in 
    //       case normalization causes digit spill over.
    bnum bnTempA(sizeA+3);
    bnum bnTempC(sizeA+3);
    rgtA= bnTempA.m_pValue;
    rgtC= bnTempC.m_pValue;
    bnA.mpCopyNum(bnTempA);
    UNUSEDVAR(rgtC);

    scaledA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    scaledB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    uBHi= bnB.m_pValue[scaledB-1];
    uBLo= bnB.m_pValue[scaledB-2];

    // Loop through the digits
    for(i=(scaledA-1); i>=(scaledB-1); i--) {
        fTwoDigitArgs= false;
        if(rgtA[i]>=uBHi) {
            if(notsmallerthan(&rgtA[i], &bnB.m_pValue[scaledB-1], scaledB)) {
                EstimateQuotient(&uQ, 0ULL, rgtA[i], rgtA[i-1], uBHi, uBLo);
#ifdef ARITHTEST
                printf("Quotient: %016lx, i: %d, i-scaledB+1: %d\n", uQ, i, i-scaledB+1);
#endif
                while(uQ>0) {
                    mpZeroNum(bnTempC);
                    mpUSingleMultAndShift(bnB, uQ, i-scaledB+1, bnTempC);
                    compare= mpCompare(bnTempA, bnTempC);
                    if(compare!=s_isLessThan)
                        break;
                    uQ--;
                    mpZeroNum(bnTempC);
                    mpUSingleMultAndShift(bnB, uQ, i-scaledB+1, bnTempC);
                }
                if(uQ>0) {
                    mpUSubFrom(bnTempA, bnTempC);
                    rgQ[i-scaledB+1]= uQ;
                    continue;
                }
                fTwoDigitArgs= true;
            }
        else
            fTwoDigitArgs= true;
        }
        if(i==(scaledB-1))
            break;
        if(fTwoDigitArgs) {
            if(i>scaledB) {
                if(scaledA<3)
                    TwoDigitEstimateQuotient(&uQ, rgtA[i], rgtA[i-1], 0ULL, uBHi, uBLo);
                else
                    TwoDigitEstimateQuotient(&uQ, rgtA[i], rgtA[i-1],rgtA[i-2], uBHi, uBLo);
                i--;
                uQ= (u64)-1;
            }
        }
        else {
            if(scaledA<3)
                EstimateQuotient(&uQ, rgtA[i], rgtA[i-1], 0ULL, uBHi, uBLo);
            else
                EstimateQuotient(&uQ, rgtA[i], rgtA[i-1],rgtA[i-2], uBHi, uBLo);
        }
        mpZeroNum(bnTempC);
        mpUSingleMultAndShift(bnB, uQ, i-scaledB, bnTempC);
        while(mpCompare(bnTempA, bnTempC)==s_isLessThan) {
            uQ--;
            mpZeroNum(bnTempC);
            mpUSingleMultAndShift(bnB, uQ, i-scaledB, bnTempC);
        }
        mpUSubFrom(bnTempA, bnTempC);
        rgQ[i-scaledB]= uQ;
    }

#ifdef ARITHTEST
    printf("mpUDiv returning %016lx\n", uQ);printNum(bnQ);printf("\n");
#endif
    bnTempA.mpCopyNum(bnR);
    return true;
}



// ----------------------------------------------------------------------------


//  Function: bool ConvertToDecimalString
//  Arguments:
//      IN bnum bnA,
//      IN i32 stringSize
//      OUT char* szNumber
//  Description:
//      Print as decimal number
bool ConvertToDecimalString(bnum& bnA, i32 stringSize, char* szNumber)
{
    int     i, j;
    u64     uRem= 0;
    char*   rgszNum= NULL;
    char    chA;

    bnum bnN(bnA.mpSize());
    bnum bnQ(bnA.mpSize());
    bnA.mpCopyNum(bnN);

    // Sign
    if(bnA.mpSign())
        *szNumber= '-';
    else
        *szNumber= '+';
    rgszNum= szNumber+1;
    for(i=0; i<(stringSize-1); i++) {
        if(bnN.mpIsZero())
            break;
        mpSingleUDiv(bnN, 10L, bnQ, &uRem, false);
        bnQ.mpCopyNum(bnN);
        rgszNum[i]= '0'+uRem;
    }
    if(i==0)
        rgszNum[i]= '0'+uRem;
    if(i>=(stringSize-1)) {
        fprintf(g_logFile, "String too small\n");
        return false;
    }
    rgszNum[i]= 0;

    // reverse the string
    int k= i/2;
    for(j=0; j<k; j++) {
        chA= rgszNum[j];
        rgszNum[j]= rgszNum[i-1-j];
        rgszNum[i-1-j]= chA;
    }

    return true;
}


//  Function: bool ConvertFromDecimalString
//  Arguments:
//      OUT bNum bnA
//      IN const char* szNumber
bool ConvertFromDecimalString(bnum& bnA, const char* szNumber)
{
    int     i;
    int     maxSize= bnA.mpSize();
    u64     uN= 0;
    const char*   pszNum= szNumber;
    u64*    rguNum= NULL;
    bool    fSign= false;

    pszNum= szNumber+1;
    i= 0;
    while(*pszNum!=0) {
        if(*pszNum>='0' && *pszNum<='9')
            i++;
        pszNum++;
    }
    if((maxSize*9)<i) {
        fprintf(g_logFile, "ConvertFromDecimalString(:Character length too small\n");
        return false;
    }
    ZeroWords(bnA.mpSize(), bnA.m_pValue);

    // Sign processing
    pszNum= szNumber+1;
    while(*pszNum!=0) {
        if(*pszNum>='0' && *pszNum<='9')
            break;
        if(*pszNum=='+') {
            pszNum++;
            fSign= true;
            break;
        }
        if(*pszNum=='-') {
            pszNum++;
            fSign= true;
            break;
        }
        pszNum++;
    }
    rguNum= bnA.m_pValue;
    UNUSEDVAR(rguNum);

    // pszNum is correctly positioned
    while(*pszNum!=0) {
        if(*pszNum<'0' || *pszNum>'9')
            break;
        uN= (*pszNum)-'0';
        mpUSingleMultBy(bnA, 10);
        mpSingleUAddTo(bnA, uN);
        pszNum++;
    }

    UNUSEDVAR(fSign);

    return true;
}


// ----------------------------------------------------------------------------


//
//              Classical Algorithms on signed numbers
//


//  Function: bool mpAdd
//  Arguments:
//      bnum bnA
//      bnum bnB 
//      bnum bnR
//  Description:
//      bnR= bnA+bnB (Signed)
bool mpAdd(bnum& bnA, bnum& bnB, bnum& bnR)
{
    bool    fSignA= bnA.mpSign();
    bool    fSignB= bnB.mpSign();
    i32     iComp;

    if(fSignA==fSignB) {
        bnR.mpDumpSign();
        if(mpUAdd(bnA, bnB, bnR)!=0) {
            fprintf(g_logFile, "mpAdd: Overflow\n");
            return false;
        }
        if(fSignA)
            bnR.mpNegate();
        return true;
    }
    bnR.mpDumpSign();
    iComp= mpUCompare(bnA, bnB);
    if(iComp==s_isEqualTo) {
        ZeroWords(bnR.mpSize(), bnR.m_pValue);
        return true;
    }
    if(iComp==s_isGreaterThan) {
        mpUSub(bnA, bnB, bnR);
        // bnR gets sign of A
        if(fSignA)
            bnR.mpNegate();
    }
    else {
        mpUSub(bnB, bnA, bnR);
        // bnR gets sign of B
        if(fSignB)
            bnR.mpNegate();
    }

    mpNormalizeZero(bnR);
    return true;
}


//  Function: bool mpSub
//  Arguments:
//      IN bnum bnA,
//      IN bnum bnB 
//      OUT bnum bnR
//  Description:
//      bnR= bnA-bnB, Assumes here is enough rooms
bool mpSub(bnum& bnA, bnum& bnB, bnum& bnR)
{
    bool fRet= false;

    bnB.mpNegate();
    fRet= mpAdd(bnA, bnB, bnR);
    bnB.mpNegate();
    mpNormalizeZero(bnR);
    return fRet;
}


//  Function: void mpMult
//  Arguments:
//      IN bnum bnA
//      IN bnum bnB 
//      OUT bnum bnR
//  Note: bnR is set to zero to compute bnA*bnB so calling
//      mpUMult(bnA, bnB, bnA);
//  will result in an error
void mpMult(bnum& bnA, bnum& bnB, bnum& bnR)
{
    bool    fSignA= bnA.mpSign();
    bool    fSignB= bnB.mpSign();

    mpUMult(bnA, bnB, bnR);
    bnR.mpDumpSign();
    if(fSignA!=fSignB)
        bnR.mpNegate();
    mpNormalizeZero(bnR);
    return;
}


//  Function: void mpDiv
//  Arguments:
//      bnum bnA
//      bnum bnB 
//      bnum bnQ 
//      bnum bnR
void mpDiv(bnum& bnA, bnum& bnB, bnum& bnQ, bnum& bnR)
{
    bool    fSignA= bnA.mpSign();
    bool    fSignB= bnB.mpSign();
    
    mpUDiv(bnA, bnB, bnQ, bnR);
    if(fSignA==fSignB) {
        bnQ.mpDumpSign();
        if(fSignA)
            bnR.mpNegate();
    }
    else {
        bnQ.mpNegate();
        if(fSignB)
            bnR.mpNegate();
    }
    mpNormalizeZero(bnR);
    return;
}


//  Function: u64 mpAddTo
//  Arguments:
//      INOUT bnum bnA
//      IN bnum bnB
//  Description:
//      bnA+= bnB, don't trim
//      Return carry
u64 mpAddTo(bnum& bnA, bnum& bnB)
{
    bool    fSignA= bnA.mpSign();
    bool    fSignB= bnB.mpSign();
    u64     uCarry= 0;
    i32     iCompare= 0;

    // remove signs
    bnA.mpDumpSign();
    bnB.mpDumpSign();

    if(fSignA==fSignB) {
        uCarry= mpUAddTo(bnA, bnB);
        // restore corrected signs
        if(fSignA) {
            bnA.mpNegate();
            bnB.mpNegate();
        }
    mpNormalizeZero(bnA);
    return uCarry;
    }

    // Signs are different
    iCompare= mpUCompare(bnA, bnB);

    // bnA == bnB
    if(iCompare==s_isEqualTo) {
        ZeroWords(bnA.mpSize(), bnA.m_pValue);
        bnA.mpDumpSign();
        bnB.mpNegate();
        return 0ULL;
    }

    // bnA > bnB
    if(iCompare==s_isGreaterThan) {
        uCarry= mpUSubFrom(bnA, bnB);
        // restore corrected signs
        if(fSignA)
            bnA.mpNegate();
        if(fSignB)
            bnB.mpNegate();
        mpNormalizeZero(bnA);
        return uCarry;
    }

    // bnA < bnB
    bnum bnC(bnB.mpSize());
    bnB.mpCopyNum(bnC);
    mpUSubFrom(bnC, bnA);
    bnC.mpCopyNum(bnA);
    if(fSignB)
        bnB.mpNegate();
    if(!fSignA)
        bnA.mpNegate();
    mpNormalizeZero(bnA);
    return 1ULL;
}


//  Function: u64 mpSubFrom
//  Arguments:
//      INOUT   bnum bnA
//      IN      bnum bnB
//  Description:
//      bnA-= bnB, don't trim
//      Return carry
u64 mpSubFrom(bnum& bnA, bnum& bnB)
{
    bool    fSignA= bnA.mpSign();
    bool    fSignB= bnB.mpSign();
    u64     uCarry= 0;
    i32     iCompare= 0;

    // remove signs
    bnA.mpDumpSign();
    bnB.mpDumpSign();

    if(fSignA!=fSignB) {
        uCarry= mpUAddTo(bnA, bnB);
        // restore signs
        if(fSignA)
            bnA.mpNegate();
        if(fSignB)
            bnB.mpNegate();
        mpNormalizeZero(bnA);
        return uCarry;
    }

    iCompare= mpUCompare(bnA, bnB);

    // bnA < bnB
    if(iCompare==s_isLessThan) {
        bnum bnC(bnB.mpSize());
        bnB.mpCopyNum(bnC);
        uCarry= mpUSubFrom(bnC, bnA);
        bnC.mpCopyNum(bnA); 
        if(!fSignA)
            bnA.mpNegate();
        if(fSignB)
            bnB.mpNegate();
        mpNormalizeZero(bnA);
        return uCarry;
    }

    // bnA >= bnB
    uCarry= mpUSubFrom(bnA, bnB);
    // restore corrected signs
    if(fSignA)
        bnA.mpNegate();
    if(fSignB)
        bnB.mpNegate();

    mpNormalizeZero(bnA);
    return uCarry;
}


//  Function: u64 mpDec
//  Arguments:
//      INOUT bNum bnN
u64 mpDec(bnum& bnN)
{
    return mpUSubFrom(bnN, g_bnOne);
}


//  Function: u64 mpInc
//  Arguments:
//      INOUT bNum bnN
u64 mpInc(bnum& bnN)
{
    return mpUAddTo(bnN, g_bnOne);
}


// ----------------------------------------------------------------------------


