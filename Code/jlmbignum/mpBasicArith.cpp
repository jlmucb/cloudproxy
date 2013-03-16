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
    m_uSignandSize= (u32) iSize;
    for(int i=0; i<iSize; i++)
        m_pValue[i]= 0; 
}


bnum::~bnum()
{
    int iSize= (int) mpSize();
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
    for(i=0; i<(int)bnA.mpSize(); i++) {
        if(*(puA++)!=0)
            return;
    }
    bnA.mpDumpSign();
    return;
}


//  Function: inline i32 mpWordsinNum
//  Arguments:
//      IN      i32 iLen
//      IN      u64* puN
//  Description:
//      Returns minumum number of words 
//      to represent number
i32 mpWordsinNum(i32 iLen, u64* puN)
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
        fprintf(g_logFile, "0x0000000000000000");
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
//      Bignum representations of 1 and 2
bnum    g_bnOne(1);
bnum    g_bnTwo(1);


void initBigNum()
{
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
    i32     sizeA= (int) bnA.mpSize();
    bnum*   bn= new bnum(sizeA);

    bn->m_uSignandSize= bnA.m_uSignandSize;
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
    ZeroWords((int)bnN.mpSize(), bnN.m_pValue);
}


//  Function: void mpTrimNum
//  Arguments:
//      INOUT   bnum bnA
//  Description:
//      Trim bnA to minimum number of words required
void mpTrimNum(bnum& bnA)
{
    u32     uSign= bnA.m_uSignandSize&s_SignBit;
    u32     k= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);

    if(k==0)
        bnA.m_uSignandSize= 0;
    else
        bnA.m_uSignandSize= uSign|k;
}


// ----------------------------------------------------------------------------


//  Function: i32 mpUCompare
//  Arguments:
//      IN      bnum bnA
//      IN      bnum bnB
//  Description:
//      for positive bnA and bnB, return
//        s_iIsGreaterThan if bnA>bnB
//        s_iIsEqualTo if bnA==bnB
//        s_iIsLessThan if bnA<bnB
i32 mpUCompare(bnum& bnA, bnum& bnB)
{
    i32 sizeA= (int)mpWordsinNum((int)bnA.mpSize(), bnA.m_pValue);
    i32 sizeB= (int)mpWordsinNum((int)bnB.mpSize(), bnB.m_pValue);

    if(sizeA>sizeB)
        return(s_iIsGreaterThan);
    if(sizeA<sizeB)
        return(s_iIsLessThan);

    u64* puA= bnA.m_pValue+sizeA-1;
    u64* puB= bnB.m_pValue+sizeB-1;
    while(sizeA-->0) {
        if(*puA>*puB)
            return(s_iIsGreaterThan);
        if(*puA<*puB)
            return(s_iIsLessThan);
        puA--;
        puB--;
    }
    return(s_iIsEqualTo);
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
            return s_iIsLessThan;
        return s_iIsGreaterThan;
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
    for(j=0; j<64; j++) {
        if((uOne&uX)!=0)
            break;
        uOne<<= 1;
    }
    if(j>63)
        j= 0;
    return i*64+j;
}


//  Function: i32 MaxBit
//  Arguments:
//      u32 uW
//  Description:
//      Return position of most significant non zero bit.
//      Least Significant bit is at position 1.  0 means no bit is on
i32 MaxBit(u64 uW)
{
    u64 uM=(1ULL<<63);
    int i= 64;

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
    int numWords= mpWordsinNum(size, rguN);

    if(numWords==0)
        return 0;
    numWords--;
    int numBits= MaxBit(rguN[numWords]);
    return 64*numWords+numBits;
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
    u64 uM= bnN.m_pValue[(pos/64)];

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
    u64 uMask= (u64) (-1);

    uMask<<= (64-numBits);
    uMask>>= (64-numBits);
    return uMask;
}


void shiftup(bnum& bnA, bnum& bnR, i32 numShiftBits)
{
    int         i;
    int         wordShift= (numShiftBits>>6);
    int         bitShift= numShiftBits&0x3f;
    int         bottomShift= 64-bitShift;
    u64         ubottomMask= bottomMask64(bottomShift);
    u64         utopMask= ((u64)(-1))^ubottomMask;
    u64*        rgA= bnA.m_pValue;
    u64*        rgR= bnR.m_pValue;
    i32         lA= mpWordsinNum(bnA.mpSize(), rgA);
    u64         r, s, t;

    t= rgA[lA-1];
    if(bitShift>0) {
        r= (t&utopMask)>>bottomShift;
        rgR[lA+wordShift]= r;
    }
    s= (t&ubottomMask)<<bitShift;

    for(i=(lA-1); i>0;i--) {
        t= rgA[i-1];
        r= (t&utopMask)>>bottomShift;
        rgR[i+wordShift]|= s|r;
        s= (t&ubottomMask)<<bitShift;
    }
    rgR[wordShift]= s;
}


void shiftdown(bnum& bnA, bnum& bnR, i32 numShiftBits)
{
    int         i;
    int         wordShift= (numShiftBits>>6);
    int         bitShift= numShiftBits&0x3f;
    u64         ubottomMask= bottomMask64(bitShift);
    int         bottomShift= 64-bitShift;
    u64*        rgA= bnA.m_pValue;
    u64*        rgR= bnR.m_pValue;
    i32         lA= mpWordsinNum(bnA.mpSize(), rgA);
    u64         r, s, t;

    t= rgA[wordShift];
    s= t>>bitShift;
    for(i=0; i<(lA-wordShift); i++) {
        t= rgA[i+1+wordShift];
        r= (t&ubottomMask)<<bottomShift;
        rgR[i]|= s|r;
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
    if(sizeA+((numShiftBits+63)/64)>sizeR)
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
        if(uCarry>0 && (int)bnA.mpSize()>lA) {
            bnA.m_pValue[lA]= uCarry;
            uCarry= 0ULL;
        }
    }
    else {
        if((int)bnA.mpSize()<lB) {
            fprintf(g_logFile, "mpUAddTo: Overflow\n");
            return 0ULL;
        }
        uCarry= mpUAddLoop(lB, bnB.m_pValue, lA, bnA.m_pValue, bnA.m_pValue);
        if(uCarry>0 && (int)bnA.mpSize()>lB) {
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
    if(uCarry>0 && (int)bnA.mpSize()>lA) {
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
    if(uCarry>0 && (int)bnA.mpSize()>lA) {
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
    if((int)bnR.mpSize()<(lA+lB)) {
        fprintf(g_logFile, "mpUMult: potential overflow\n");
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

    if((int)bnR.mpSize()>(lA+lB-1)) {
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
//      i32 iShift (by full words)
//      bnum bnR
bool mpUSingleMultAndShift(bnum& bnA, u64 uB, i32 iShift, bnum& bnR)
{
    i32     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    u64     uCarry= 0;

    ZeroWords(bnR.mpSize(), bnR.m_pValue);
    if(uB==0ULL || bnA.mpIsZero()) {
        return true;
    }

    if((lA+iShift)>(int)bnR.mpSize()) {
        fprintf(g_logFile, "mpUSingleMultAndShift: overflow\n");
        return false;
    }
    int lR= (int)bnR.mpSize();
    mpCopyWords(lA, bnA.m_pValue, lR-iShift, bnR.m_pValue+iShift);
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
bool mpSingleUDiv(bnum& bnA, u64 uB, bnum& bnQ, u64* puRem, bool fZero=true)
{
    i32     i;
    u64*    rguA= bnA.m_pValue;
    i32     iRealSizeA= mpWordsinNum(bnA.mpSize(), rguA);
    u64     uRem= 0;
    i32     iOutSize= bnQ.mpSize();
    u64*    rguOut= bnQ.m_pValue;

    if(uB==0L) {
        fprintf(g_logFile, "mpSingleUDiv: Division by 0\n");
        return false;
    }
    if(iOutSize<iRealSizeA) {
        fprintf(g_logFile, "mpSingleUDiv: potential overflow\n");
        return false;
    }
    if(fZero)
        ZeroWords(iOutSize, bnQ.m_pValue);

    for(i=(iRealSizeA-1); i>=0; i--)
        uRem= longdivstep(&rguOut[i], uRem, rguA[i], uB);

    *puRem= uRem;
    return true;
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
void EstimateQuotient(u64* pqE, u64 uN, u64 uNM1, u64 uNM2, u64 vM1, u64 vM2)
{
    u64 uQ, uR, uRTop, uA;
    
#ifdef ARITHTEST
    fprintf(g_logFile, "longdivstep(%016lx, %016lx, %016lx\n", uN-vM1, uNM1, vM1);
    fflush(g_logFile);
#endif
    // if(vM1==0)
    //    return false;
    if(uN>=vM1) {
        uQ= (u64) -1ULL;
        uR= longdivstep(&uA, uN-vM1, uNM1, vM1);
        uRTop= longaddwithcarry(&uR, uR, vM1, 0ULL);

        // mark unused variables to keep the compiler happy
        UNUSEDVAR(uRTop);
        UNUSEDVAR(uA);
    } 
    else {
        uR= longdivstep(&uQ, uN, uNM1, vM1);
    }

    *pqE= uQ;
#ifdef ARITHTEST
    fprintf(g_logFile, "EstimateQuotient(%016lx, %016lx, %016lx, %016lx, %016lx) --- ",
           (up64) uN, (up64) uNM1, (up64) uNM2, (up64) vM1, (up64) vM2);
    fprintf(g_logFile, "uQ: %016lx\n", (up64) uQ);
    fflush(g_logFile);
#endif
    return;
}


// ----------------------------------------------------------------------------


//  Function: bool mpUDiv
//  Arguments:
//      bNum bnA
//      bNum bnB
//      bNum bnQ
//      bNum bnR
//  Description:
//      Unsigned division a la Knuth
//      First normallize:  d<-- floor((r-1)/v[m-1])
//      A<-- A*d
//      B<-- B*d
//      At conclusion, rem<-- rem/d
//      Uses the following theorem in the estimate quotient inline:
//          If U=u[n]b^n+..u[0], V=v[n-1]b^(n-1)+...+v[0] and
//              qE= min([(u[n]b+u[n-1])/v[n-1]},b-1) then eq>=q.  
//          If v[n-1]>b/2, eq-2<=q<=eq.
//          Note that this is the only one of the classical algorithms
//          that destroys the value of the arguments, so we copy them.
bool mpUDiv(bnum& bnA, bnum& bnB, bnum& bnQ, bnum& bnR)
{
    i32     i;
    i32     sizeA= bnA.mpSize();
    i32     sizeB= bnB.mpSize();
    i32     sizeQ= bnQ.mpSize();
    i32     sizeR= bnR.mpSize();
    i32     lA, lB, iQSize, iShift;
    i32     scaledA, scaledB;
    u64     uQ= 0;
    u64     uScale, uRem;
    u64*    rgQOut= bnQ.m_pValue;
    u64*    rgtA= NULL;
    u64*    rgtB= NULL;
    u64*    rgtC= NULL;
    u64     uA, uB;
        
    if(bnB.mpIsZero()) {
        fprintf(g_logFile, "mpUDiv: Division by 0\n");
        return false;
    }
    lA= mpWordsinNum(sizeA, bnA.m_pValue);
    lB= mpWordsinNum(sizeB, bnB.m_pValue);
    iQSize= lA-lB+1;
    if(iQSize>sizeQ) {
        fprintf(g_logFile, "mpUDiv: Quotient overflow\n");
        return false;
    }
    mpZeroNum(bnQ);
    mpZeroNum(bnR);

    if(mpUCompare(bnA, bnB)==s_iIsLessThan) {
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

    // does bnB have length 1 or less?
    if(lB==1) {
        mpSingleUDiv(bnA, bnB.m_pValue[0], bnQ, bnR.m_pValue, true);
        return true;
    }

    // Allocate Temporaries: one more digit than bnA in 
    //       case normalization causes digit spill over.
    bnum bnTempA(sizeA+3);
    bnum bnTempB(sizeB+3);
    bnum bnTempC(sizeA+3);
    rgtA= bnTempA.m_pValue;
    rgtB= bnTempB.m_pValue;
    rgtC= bnTempC.m_pValue;

    UNUSEDVAR(rgtC);

    i= mpWordsinNum(bnB.mpSize(), bnB.m_pValue)-1;
    if(i<0) {
        fprintf(g_logFile, "mpUDiv: divide by 0\n");
        return false;
    }

    // Normalize
    //  make sure v1>= floor(b/2)
    if((bnB.m_pValue[i]&(1ULL<<63))!=0) {
        mpCopyWords(sizeA, bnA.m_pValue, sizeA, rgtA);
        mpCopyWords(sizeB, bnB.m_pValue, sizeB, rgtB);
        uScale= 1ULL;     // for renormalization
    }
    else {
        uRem= longdivstep(&uScale, 1, 0ULL, bnB.m_pValue[i]+1ULL);
        mpUSingleMultAndShift(bnA, uScale, 0, bnTempA);
        mpUSingleMultAndShift(bnB, uScale, 0, bnTempB);
    }
    scaledA= mpWordsinNum(bnTempA.mpSize(), rgtA);
    scaledB= mpWordsinNum(bnTempB.mpSize(), rgtB);
#ifdef ARITHTEST
    fprintf(g_logFile, "Scale: %016lx, LeadA: %016lx, leadB: %016lx\n", (up64) uScale,
           (up64) rgtA[scaledA-1], (up64) rgtB[scaledB-1]);
#endif

    // Loop through the digits
    uA= rgtB[scaledB-1];
    if(scaledB>=2)
        uB= rgtB[scaledB-2];
    else
        uB= 0ULL;

    for(i=scaledA-1; i>=scaledB; i--) {
#ifdef ARITHTEST
        fprintf(g_logFile, "\nLoop head %d\n", i); 
        fprintf(g_logFile, "Estimate Quotient(%016lx, %016lx, %016lx, %016lx, %016lx\n",
            (up64) rgtA[i], (up64) rgtA[i-1], (up64) rgtA[i-2], 
            (up64) uA, (up64) uB); fflush(stdout);
#endif
        if(i==1)
            EstimateQuotient(&uQ, rgtA[i], rgtA[i-1], 0, uA, uB);
        else
            EstimateQuotient(&uQ, rgtA[i], rgtA[i-1], rgtA[i-2], uA, uB);

        // Compute product
        mpZeroNum(bnTempC);
        iShift= i-scaledB;
        mpUSingleMultAndShift(bnTempB, uQ, iShift, bnTempC);
#ifdef ARITHTEST
        fprintf(g_logFile, "\n");
        fprintf(g_logFile, "uA: %016lx, uB: %016lx", (up64) uA, (up64) uB);
        fprintf(g_logFile, ", singlemult, uQ: %016lx\n", (up64) uQ);
        fprintf(g_logFile, "Shift: %d\n", iShift);
        fprintf(g_logFile, "A: "); printNum(bnTempA); printf("\n");
        fprintf(g_logFile, "B: "); printNum(bnTempB); printf("\n");
        fprintf(g_logFile, "C: "); printNum(bnTempC); printf("\n");
        fflush(stdout);
#endif

        // Too big? (if so it's only by 1)
        while(mpUCompare(bnTempA, bnTempC)==s_iIsLessThan) {
            uQ--;
            mpZeroNum(bnTempC);
            mpUSingleMultAndShift(bnTempB, uQ, iShift, bnTempC);
#ifdef ARITHTEST
            fprintf(g_logFile, "\nIn Loop compare, ");
            fprintf(g_logFile, "uQ: %016lx\n", (up64) uQ);
            fprintf(g_logFile, "A: "); printNum(bnTempA); printf("\n");
            fprintf(g_logFile, "C: "); printNum(bnTempC); printf("\n");
            fflush(stdout);
#endif
        }
#ifdef ARITHTEST
        fprintf(g_logFile, "Out of loop, i: %d\n", i); fflush(stdout);
#endif
        mpUSubFrom(bnTempA, bnTempC);
#ifdef ARITHTEST
        fprintf(g_logFile, "After USub: ");
        printNum(bnTempA);
        fprintf(g_logFile, "\n");
        fflush(stdout);
#endif
        // Set Quotient
        rgQOut[i-scaledB]= uQ;
    }

    // UnNormalize
    if(uScale>0) {
        mpSingleUDiv(bnTempA, uScale, bnR, &uRem);
    }
    else {
        bnTempA.mpCopyNum(bnR);
    }
        
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
    if(iComp==s_iIsEqualTo) {
        ZeroWords(bnR.mpSize(), bnR.m_pValue);
        return true;
    }
    if(iComp==s_iIsGreaterThan) {
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
    if(iCompare==s_iIsEqualTo) {
        ZeroWords(bnA.mpSize(), bnA.m_pValue);
        bnA.mpDumpSign();
        bnB.mpNegate();
        return 0ULL;
    }

    // bnA > bnB
    if(iCompare==s_iIsGreaterThan) {
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
    if(iCompare==s_iIsLessThan) {
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


