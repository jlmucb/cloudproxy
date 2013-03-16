//
//  File: mpModArith.cpp
//  Multiple Precision Arithmetic for bignum
//      Modular arithmetic
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
//  Some modifications may be (c) Intel Corporation
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


#include <stdio.h> 
#include <stdlib.h> 
#include <fcntl.h> 
#include <string.h>
#include <unistd.h>

#include "bignum.h"
#include "logging.h"
#include "jlmUtility.h"
#include "mpFunctions.h"


// ----------------------------------------------------------------------------

//
//              Modular Arithmetic
//


//  Function: bool mpMod
//  Arguments:
//      bnum bnA>=0
//      bnum bnM
//      bnum bnR
//  Description:
//      Compute bnR= bnA (mod bnM), 0=<bnR<bnM
bool mpMod(bnum& bnA, bnum& bnM, bnum& bnR)
{
    int     iMaxSize= bnA.mpSize();
    int     i= bnM.mpSize();
    bool    fRet= false;

    if(i>iMaxSize)
        iMaxSize= i;

    try {
        bnum    bnQ(iMaxSize);
        mpUDiv(bnA, bnM, bnQ, bnR);
        fRet= true;
        }
    catch(const char* szError) {
        szError= NULL;
        fRet= false;
    }
    return fRet;
}


//  Function: bool mpModNormalize
//  Arguments:
//      INOUT bnum bnA
//      IN    bnum bnM
//  Description:
//      Compute bnR= bnA (mod bnM), 0=<bnR<bnM
bool mpModNormalize(bnum& bnA, bnum& bnM)
{
    int     iMaxSize= bnA.mpSize();
    int     i= bnM.mpSize();
    extern bnum g_bnOne;

    if(i>iMaxSize)
        iMaxSize= i;

    try {
        bnum    bnB(iMaxSize);
        bnum    bnQ(iMaxSize);
        bnum    bnR(iMaxSize);
        if(bnA.mpSign()) {
            // make it positive by adding ceil(|A|/|M|)
            bnA.mpCopyNum(bnB);
            bnB.mpDumpSign();
            mpDiv(bnB, bnM, bnQ, bnR);
            if(!bnR.mpIsZero())
                mpUAddTo(bnQ, g_bnOne);
#ifdef ARITHTEST1
            extern void printNum(bnum& bnA, bool fFull=false);
            fprintf(g_logFile, "normalize Q: "); printNum(bnQ); printf("\n");
#endif
            mpZeroNum(bnB);
            mpUMult(bnQ,bnM,bnB);
#ifdef ARITHTEST1
            fprintf(g_logFile, "normalize B: "); printNum(bnB); printf("\n");
#endif
            mpAddTo(bnA,bnB);
        }
        if(mpCompare(bnM, bnA)==s_iIsGreaterThan)
            return true;
        mpDiv(bnA, bnM, bnQ, bnR);
        bnR.mpCopyNum(bnA);
        return true;
    }
    catch(const char* szError) {
        szError= NULL;
        return false;
    }
}


//  Function: bool mpModAdd
//  Arguments:
//      IN bnum bnA
//      IN bnum bnB
//      IN bnum bnM
//      OUT bnum bnR
//  Description:
//      Compute bnA+bnB (mod bnM) with classical algorithm
bool mpModAdd(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR)
{
    mpUAdd(bnA, bnB, bnR);
    return mpModNormalize(bnR, bnM);
}


//  Function: bool mpModSub
//  Arguments:
//      IN bnum bnA>=0
//      IN bnum bnB>=0
//      IN bnum bnM
//      OUT bnum bnR
//  Description:
//      Compute bnA-bnB (mod bnM) with classical algorithm, result>=0
bool mpModSub(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR)
{
    int     iMaxSize= bnA.mpSize();
    int     i= bnB.mpSize();
    int     j= bnM.mpSize();

    if(i>iMaxSize)
        iMaxSize= i;
    if(j>iMaxSize)
        iMaxSize= j;

    if(!(mpCompare(bnA, bnB)==s_iIsLessThan)) {
        mpUSub(bnA, bnB, bnR);
    }
    else {
        bnum  bnC(iMaxSize+2);
        mpUAdd(bnA, bnM, bnC);
        mpUSub(bnC, bnB, bnR);
    }
    mpModNormalize(bnR, bnM);
    return true;
}


//  Function: bool mpModMult
//  Arguments:
//      IN bnum bnA>=0
//      IN bnum bnB>=0
//      IN bnum bnM
//      OUT bnum bnR
//  Description:
//      Compute bnA*bnB (mod bnM) with classical algorithm, result>=0

bool mpModMult(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR)
{
    int     iMaxSize= bnA.mpSize();
    int     i= bnB.mpSize();
    int     j= bnM.mpSize();
    bool    fRet= false;

    if(i>iMaxSize)
        iMaxSize= i;
    if(j>iMaxSize)
        iMaxSize= j;
    iMaxSize*= 2;

    try {
        bnum  bnC(iMaxSize+1);
        bnum  bnQ(iMaxSize+1);
        mpUMult(bnA, bnB, bnC);
        mpUDiv(bnC, bnM, bnQ, bnR);
        mpModNormalize(bnR, bnM);
        fRet= true;
    }
    catch(const char* szError) {
        szError= NULL;
        fRet= false;
    }

    return fRet;
}


//  Function: bool mpModInv
//  Arguments:
//      IN bnum bnA
//      IN bnum bnM
//      IN bnum bnN
//      OUT bnum bnR
//  Description:
//      Compute bnA^(-1) (mod bnM) with classical algorithm, result>=0
bool mpModInv(bnum& bnA, bnum& bnM, bnum& bnR)
{
    int     iSizeA= bnA.mpSize();
    int     iSizeM= bnM.mpSize();
    int     iMaxSize;
    bool    fRet= false;

    if(iSizeA>iSizeM)
        iMaxSize= iSizeA;
    else
        iMaxSize= iSizeM;

    try {
        bnum bnT(iMaxSize);
        bnum bnG(iMaxSize);
        mpBinaryExtendedGCD(bnA, bnM, bnR, bnT, bnG);
        // Now, bnA (bnR) + bnM (bnT)= 1, so bnR is bnA inverse
        mpModNormalize(bnR, bnM);
        fRet= true;
     }
    catch(const char* szError) {
        szError= NULL;
        fRet= false;
    }
    return fRet;
}


//  Function: bool mpModDiv
//  Arguments:
//      IN bnum bnA
//      IN bnum bnB
//      IN bnum bnM
//      OUT bnum bnR
//  Description:
//      Compute bnA/bnB (mod bnM) with classical algorithm, result>=0
bool mpModDiv(bnum& bnA, bnum& bnB, bnum& bnM, bnum& bnR)
{
    int     iMaxSize= bnA.mpSize();
    int     i= bnM.mpSize();
    bool    fRet= false;

    if(i>iMaxSize)
        iMaxSize= i;
    iMaxSize*= 2;

    try {
        bnum    bna(iMaxSize);
        bnum    bnc(iMaxSize);
        bnum    bnb(iMaxSize);
        bnum    bnG(iMaxSize);

        mpBinaryExtendedGCD(bnB, bnM, bnb, bnc, bnG);
        // Now, bnB (bnb) + bnM (bnc)= 1, so bnb is bnB inverse
        mpModNormalize(bnb, bnM);
        mpMult(bnb, bnA, bnR);
        mpModNormalize(bnR, bnM);
        fRet= true;
    }
    catch(const char* szError) {
        szError= NULL;
        fRet= false;
    }

    return fRet;
}


//  Function: bool mpModExp
//  Arguments:
//      IN bnum bnBase
//      IN bnum bnExp
//      IN bnum bnM
//      OUT bnum bnR
//  Description:
//      Compute bnBase^bnExp (mod bnM) with classical algorithm, result>=0

bool mpModExp(bnum& bnBase, bnum& bnExp, bnum& bnM, bnum& bnR)
{
    int     iMaxSizeB= bnBase.mpSize();
    int     iMaxSizeM= bnM.mpSize();
    int     iMaxSize;
    int     j;

    if(iMaxSizeB>iMaxSizeM) {
        iMaxSize= 2*iMaxSizeB+1;
    }
    else {
        iMaxSize= 2*iMaxSizeM+1;
    }

    bnum    bnBasePow(iMaxSize);    // Base to powers of 2
    bnum    bnAccum(iMaxSize);      // Exponent so far
    bnum    bnTemp(iMaxSize);       // Temporary storage
    bnum    bnQ(iMaxSize);          // Quotient

    UNUSEDVAR(iMaxSize);
    bnBase.mpCopyNum(bnBasePow);
    bnAccum.m_pValue[0]= 1ULL;

    int iLeadBit= LeadingNonZeroBit(bnExp.mpSize(), bnExp.m_pValue);
    if(IsBitPositionNonZero(bnExp, 1)) {
        mpZeroNum(bnTemp);
        mpUMult(bnBasePow, bnAccum, bnTemp);
        mpZeroNum(bnAccum);
        mpDiv(bnTemp, bnM, bnQ, bnAccum);
    }
    for(j=2;j<=iLeadBit; j++) {
        mpZeroNum(bnTemp);
        mpUMult(bnBasePow, bnBasePow, bnTemp);
        mpZeroNum(bnBasePow);
        mpUDiv(bnTemp, bnM, bnQ, bnBasePow); 
        if(IsBitPositionNonZero(bnExp, j)) {
#ifdef ARITHTEST81
            fprintf(g_logFile, "%d mult\n", j);
#endif
            mpZeroNum(bnTemp);
            mpUMult(bnBasePow, bnAccum, bnTemp);
            mpZeroNum(bnAccum);
            mpUDiv(bnTemp, bnM, bnQ, bnAccum);
        }
    }
    bnAccum.mpCopyNum(bnR);

    return true;
}


// ---------------------------------------------------------------------------------


bool mpTestFermatCondition(bnum& bnBase, bnum& bnM)
{
    extern bnum g_bnOne;
    int         iSizeM= bnM.mpSize();
    bnum        bnE(iSizeM);
    bnum        bnR(iSizeM);
    bool        fRet= mpModSub(bnM, g_bnOne, bnM, bnE);

    if(!fRet)
        return false;
    fRet= mpModExp(bnBase, bnE, bnM, bnR);
    if(!fRet)
        return false;
    if(s_iIsEqualTo== mpUCompare(bnR, g_bnOne))
        return true;
    return false;
}


bool mpFermatTest(bnum& bnBase, bnum& bnM, bnum& bnR)
{
    extern bnum g_bnOne;
    int         iSizeM= bnM.mpSize();
    bnum        bnE(iSizeM);
    bool        fRet= mpModSub(bnM, g_bnOne, bnM, bnE);

    if(!fRet)
        return false;
    fRet= mpModExp(bnBase, bnE, bnM, bnR);
    return fRet;
}


bool mpRSAENC(bnum& bnMsg, bnum& bnE, bnum& bnM, bnum& bnR)
{
    bool fRet= mpModExp(bnMsg, bnE, bnM, bnR);

    return fRet;
}


bool mpRSAGen(int iNumBits, bnum& bnE, bnum& bnP, bnum& bnQ, bnum& bnM, 
              bnum& bnD, bnum& bnOrder)
{
    extern bnum g_bnOne;
    int         iSizeP= bnP.mpSize();
    int         iSizeQ= bnQ.mpSize();
    int         iSizeM= bnM.mpSize();

#ifdef TEST
    fprintf(g_logFile, "mpRSAGen: GenPrime start\n");
#endif
    // Get two primes
    if(!mpGenPrime(iNumBits/2, bnP)) {
        fprintf(g_logFile, "Cant find P\n");
        return false;
    }
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: GenPrime got first prime\n");
#endif
    if(!mpGenPrime(iNumBits/2, bnQ)) {
        fprintf(g_logFile, "Cant find Q\n");
        return false;
    }
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: GenPrime got second prime\n");
#endif

    // Multiply to get bnM
    int iRealSizeP= LeadingNonZeroWord(iSizeP, bnP.m_pValue);
    if((iRealSizeP)*NUMBITSINU64>iNumBits/2) {
        fprintf(g_logFile, "P too big\n");
        return false;
    }
    int iRealSizeQ= LeadingNonZeroWord(iSizeQ, bnQ.m_pValue);
    if((iRealSizeQ)*NUMBITSINU64>iNumBits/2) {
        fprintf(g_logFile, "Q too big\n");
        return false;
    }

    mpUMult(bnP, bnQ, bnM);

    int (iRealSizeM)= LeadingNonZeroWord(iSizeM, bnM.m_pValue);
    if(iRealSizeM*NUMBITSINU64>iNumBits) {
        fprintf(g_logFile, "Modulus too big\n");
        return false;
    }

    // Dec to get bnP-1 and bnQ-1
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: exponent modulus\n");
#endif
    bnum bnPM1(iSizeP);
    bnum bnQM1(iSizeQ);
    mpUSub(bnP, g_bnOne, bnPM1);
    mpUSub(bnQ, g_bnOne, bnQM1);

    // Compute Order
    mpUMult(bnPM1, bnQM1, bnOrder);

#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: computing order\n");
#endif
    // get bnD
    bnum bnT(iSizeM);
    bnum bnG(iSizeM);
    if(!mpBinaryExtendedGCD(bnE, bnOrder, bnD, bnT, bnG)) {
        fprintf(g_logFile, "Cant find D\n");
        return false;
    }
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: computed order\n");
#endif
    if(mpCompare(bnG, g_bnOne)!=s_iIsEqualTo) {
        fprintf(g_logFile, "Exponent and Order are not coprime\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "mpRSAGen: returns true\n");
#endif
    return true;
}


// ---------------------------------------------------------------------------------


