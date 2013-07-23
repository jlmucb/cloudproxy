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


// #define MONTGOMERYENABLED
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
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>maxSize)
        maxSize= lM;

    try {
        bnum    bnQ(maxSize);

        if(!mpUDiv(bnA, bnM, bnQ, bnR))
            throw("mpUDiv failed");
        }
    catch(const char* szError) {
        fprintf(g_logFile, "mpMod error\n");
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
    extern bnum g_bnOne;
    int     maxSize= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    maxSize+= lM;

    try {
        bnum    bnB(maxSize);
        bnum    bnQ(maxSize);
        bnum    bnR(maxSize);

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
        if(mpCompare(bnM, bnA)==s_isGreaterThan)
            return true;
        mpDiv(bnA, bnM, bnQ, bnR);
        bnR.mpCopyNum(bnA);
        return true;
    }
    catch(const char* szError) {
        fprintf(g_logFile, "mpModNormalize error\n");
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
    if(bnA.mpSign()) {
        mpModNormalize(bnA, bnM);
    }
    if(bnB.mpSign()) {
        mpModNormalize(bnB, bnM);
    }

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
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>maxSize)
        maxSize= lM;
    if(lB>maxSize)
        maxSize= lB;

    try {
        if(!(mpCompare(bnA, bnB)==s_isLessThan)) {
            mpUSub(bnA, bnB, bnR);
        }
        else {
            bnum  bnC(maxSize+2);
    
            mpUAdd(bnA, bnM, bnC);
            mpUSub(bnC, bnB, bnR);
        }
        mpModNormalize(bnR, bnM);
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpModSub error\n");
        fRet= false;
    }

    return fRet;
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
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>maxSize)
        maxSize= lM;
    if(lB>maxSize)
        maxSize= lB;

    maxSize*= 2;

    try {
        bnum  bnC(maxSize+1);
        bnum  bnQ(maxSize+1);

        mpUMult(bnA, bnB, bnC);
        mpUDiv(bnC, bnM, bnQ, bnR);
        mpModNormalize(bnR, bnM);
    }
    catch(const char* szError) {
        fprintf(g_logFile, "mpModMult error\n");
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
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>maxSize)
        maxSize= lM;

    try {
        bnum bnT(maxSize);
        bnum bnG(maxSize);

        mpExtendedGCD(bnA, bnM, bnR, bnT, bnG);
        // Now, bnA (bnR) + bnM (bnT)= 1, so bnR is bnA inverse
        mpModNormalize(bnR, bnM);
     }
    catch(const char* szError) {
        fprintf(g_logFile, "mpModInv error\n");
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
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>maxSize)
        maxSize= lM;
    if(lB>maxSize)
        maxSize= lB;
    maxSize*= 2;

    try {
        bnum    bna(maxSize);
        bnum    bnc(maxSize);
        bnum    bnb(maxSize);
        bnum    bnG(maxSize);

        mpExtendedGCD(bnB, bnM, bnb, bnc, bnG);
        // Now, bnB (bnb) + bnM (bnc)= 1, so bnb is bnB inverse
        mpModNormalize(bnb, bnM);
        mpMult(bnb, bnA, bnR);
        mpModNormalize(bnR, bnM);
    }
    catch(const char* szError) {
        fprintf(g_logFile, "mpModDiv error\n");
        fRet= false;
    }

    return fRet;
}


#ifdef MPMODOVERFLOWTEST
void sizeUDiv(int pos, bnum& bnA, bnum& bnB, bnum& bnC, bnum& bnD)
{
    int     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    int     lC= mpWordsinNum(bnC.mpSize(), bnC.m_pValue);
    int     lD= mpWordsinNum(bnD.mpSize(), bnD.m_pValue);

    fprintf(g_logFile, "Udiv reduction, position %d: %d %d %d %d\n", 
              pos, lA, lB, lC, lD);
    if(lD>lB) {
        fprintf(g_logFile, "A: "); printNum(bnA); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "B: "); printNum(bnB); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "D: "); printNum(bnD); fprintf(g_logFile, "\n");
    }
}


void sizeMultArgs(int pos, bnum& bnA, bnum& bnB, bnum& bnC)
{
    int     lA= mpWordsinNum(bnA.mpSize(), bnA.m_pValue);
    int     lB= mpWordsinNum(bnB.mpSize(), bnB.m_pValue);
    int     sizeC= bnC.mpSize();

    if((lA+lB)>sizeC) {
        fprintf(g_logFile, "\nUMult monitor, position %d, lA: %d, lB: %d, sizeC: %d\n",
                  pos, lA, lB, sizeC);
        fprintf(g_logFile, "A: "); printNum(bnA); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "B: "); printNum(bnB); fprintf(g_logFile, "\n\n");
    }
}
#endif


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
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnBase.mpSize(), bnBase.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);
    int     leadBit= 0;
    int     j;

    if(lM>maxSize)
        maxSize= lM;
    maxSize*= 4;

#ifdef MPMODOVERFLOWTEST
    fprintf(g_logFile, "\nmpModExp %d\n", maxSize);
    fprintf(g_logFile, "M: "); printNum(bnM); fprintf(g_logFile, "\n\n");
#endif
    try {
        bnum    bnBasePower(maxSize);   // Base to Power of 2
        bnum    bnA(maxSize);           // Accumulated product

        bnum    bnT(maxSize);           // Temporary result
        bnum    bnQ(maxSize);           // Temporary quotient

        mpZeroNum(bnBasePower);
        mpZeroNum(bnA);

        mpZeroNum(bnT);
        mpZeroNum(bnQ);
    
        UNUSEDVAR(maxSize);
        bnBase.mpCopyNum(bnBasePower);
        bnA.m_pValue[0]= 1ULL;

        leadBit= mpBitsinNum(bnExp.mpSize(), bnExp.m_pValue);
        // maybe we should always multiply to avoid timing attack
        if(IsBitPositionNonZero(bnExp, 1)) {
            mpUMult(bnBasePower, bnA, bnT);
            mpZeroNum(bnA);
            if(!mpUDiv(bnT, bnM, bnQ, bnA)) {
                throw("UDiv error");
            }
            mpZeroNum(bnT);
        }
        for(j=2; j<=leadBit; j++) {
#define DONTSQUARE
#ifdef DONTSQUARE
            mpUMult(bnBasePower, bnBasePower, bnT);
#else
            mpUSquare(bnBasePower, bnT);
#endif
            mpZeroNum(bnBasePower);
            if(!mpUDiv(bnT, bnM, bnQ, bnBasePower)) {
                throw("UDiv error");
            }
            mpZeroNum(bnT);
            if(IsBitPositionNonZero(bnExp, j)) {
                mpUMult(bnBasePower, bnA, bnT);
                mpZeroNum(bnA);
                if(!mpUDiv(bnT, bnM, bnQ, bnA)) {
                    throw("UDiv error");
                }
                mpZeroNum(bnT);
            }
        }
        bnA.mpCopyNum(bnR);
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpModExp error\n");
        fRet= false;
    }

#ifdef ARITHTEST
    fprintf(g_logFile, "mpModExp returning\n");
#endif
    return fRet;
}


// ---------------------------------------------------------------------------------
// #define MPMONTTEST


inline bool mpShiftUpWords(bnum& bnN, int r, bnum& bnOut)
{
    int     lN= mpWordsinNum(bnN.mpSize(), bnN.m_pValue);
    int     j;

    if(bnOut.mpSize()<(lN+r))
        return false;

    for(j=0;j<lN; j++)
        bnOut.m_pValue[j+r]= bnN.m_pValue[j];
    for(j=0; j<r; j++)
        bnOut.m_pValue[j]= 0ULL;
    return true;
}


inline bool mpShiftDownWords(bnum& bnN, int r, bnum& bnOut)
{
    int     lN= mpWordsinNum(bnN.mpSize(), bnN.m_pValue);
    int     j;

    if(bnOut.mpSize()<(lN-r)) {
        fprintf(g_logFile, "ShiftDownWords no room: Out: %d, transfer: %d\n",
                bnOut.mpSize(), lN-r);
        return false;
    }
    for(j=r;j<lN; j++)
        bnOut.m_pValue[j-r]= bnN.m_pValue[j];
    for(j=lN;j<bnOut.mpSize(); j++)
        bnOut.m_pValue[j]= 0ULL;
    return true;
}



inline bool mpModPowerofTwo(bnum& bnN, int r)
// reset bnN to bnN (mod 2^r)
{
    int     j;

    for(j=r;j<bnN.mpSize(); j++)
        bnN.m_pValue[j]= 0ULL;
    return true;
}


bool mpMontRed(bnum& bnN, bnum& bnM, int r, bnum& bnMPrime, bnum& bnmontN)
//
//   0<= bnN < bnM*2^r, bnMPrime= -bnM^(-1) (mod 2^r)
//   return x= bnN 2^(-r) (mod bnM)
{
    bool    fRet= true;
    int     lN= mpWordsinNum(bnN.mpSize(), bnN.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>r || lN>2*r) {
        fprintf(g_logFile, "mpMontRed inputs too large lM: %d, lN: %d, r: %d\n",
                lM, lN, r);
        return false;
    }

#ifdef MPMONTTEST
    fprintf(g_logFile, "\nmpMontRed, r: %d\n", r);
    fprintf(g_logFile, "N: "); printNum(bnN); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "M: "); printNum(bnM); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "MPrime: "); printNum(bnMPrime); fprintf(g_logFile, "\n");
#endif
    try {
        bnum    bnU(4*r);
        bnum    bnV(4*r);

        if(!mpUMult(bnN, bnMPrime, bnU)) {
            throw("UMult failed");
        }
        mpModPowerofTwo(bnU, r);
        if(!mpUMult(bnU, bnM, bnV)) {
            throw("UMult failed");
        }
        mpAddTo(bnV, bnN);
        // bnmontN= bnV/2^r
        if(!mpShiftDownWords(bnV, r, bnmontN)) {
            fprintf(g_logFile, "mpShiftDownWords failed\n");
        }
        if(s_isGreaterThan== mpUCompare(bnmontN, bnM)) {
            mpUSubFrom(bnmontN, bnM);
        }
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpMontRed error\n");
        fRet= false;
    }
#ifdef MPMONTTEST
    fprintf(g_logFile, "montN (%d): ", mpWordsinNum(bnmontN.mpSize(), bnmontN.m_pValue)); 
    printNum(bnmontN); fprintf(g_logFile, "\n\n");
#endif
    return fRet;
}


bool mpMakeMont(bnum& bnN, bnum& bnM, int r, bnum& bnmontN)
// montN= N*2**r (mod M)
{
    bool    fRet= true;
    int     lN= mpWordsinNum(bnN.mpSize(), bnN.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>r || lN>2*r) {
        fprintf(g_logFile, "mpMakeMont inputs too large lM: %d, lN: %d, r: %d\n",
                lM, lN, r);
        return false;
    }

#ifdef MPMONTTEST
    fprintf(g_logFile, "\nmpMakeMont, r: %d\n", r);
    fprintf(g_logFile, "N: "); printNum(bnN); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "M: "); printNum(bnM); fprintf(g_logFile, "\n");
#endif
    try {
        bnum    bnU(4*r);

        if(!mpShiftUpWords(bnN, r, bnU))
            throw("mpShiftUpWords error");
        mpMod(bnU, bnM, bnmontN);
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpMakeMont error\n");
        fRet= false;
    }
#ifdef MPMONTTEST
    fprintf(g_logFile, "montN: "); printNum(bnmontN); fprintf(g_logFile, "\n\n");
#endif
    return fRet;
}


bool mpMontStep(bnum& bnmontA, bnum& bnmontB, bnum& bnM, bnum& bnMPrime, 
                      int r, bnum& bnmontC)
// return bnmontC= bnmontA*bnmontB*2^(-r)
//      bnMPrime= -(bnM^(-1)) (mod 2^r)
{
    bool    fRet= true;
    int     lMontA= mpWordsinNum(bnmontA.mpSize(), bnmontA.m_pValue);
    int     lMontB= mpWordsinNum(bnmontB.mpSize(), bnmontB.m_pValue);
    int     maxSize= lMontA;
    
    if(lMontA<lMontB)
        maxSize= lMontB;
    if(r>maxSize)
        maxSize= r;
    maxSize*= 4;
    UNUSEDVAR(maxSize);

    try {
        bnum    bnT(maxSize);

        mpZeroNum(bnT);
        if(!mpUMult(bnmontA, bnmontB, bnT)) {
            throw("UMult failed");
        }
        if(!mpMontRed(bnT, bnM, r, bnMPrime, bnmontC)) {
            throw("MontRed failed");
        }
    }
    catch(const char* sz) {
        fprintf(g_logFile, "montStep error\n");
        fRet= false;
    }
#ifdef MPMONTTEST
    fprintf(g_logFile, "\nMontStep, r: %d, in sizes: %d, %d, outsize: %d\n", 
            r, lMontA, lMontB, mpWordsinNum(bnmontC.mpSize(), bnmontC.m_pValue));
    fprintf(g_logFile, "A: "); printNum(bnmontA); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "B: "); printNum(bnmontB); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "M: "); printNum(bnM); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "montC: "); printNum(bnmontC); fprintf(g_logFile, "\n\n");
#endif
    return fRet;
}


//  Function: bool mpMontModExp
//  Arguments:
//      IN bnum bnBase
//      IN bnum bnExp
//      IN bnum bnM
//      OUT bnum bnR
//  Description:
//      Compute bnBase^bnExp (mod bnM) with classical algorithm, result>=0

bool mpMontModExp(bnum& bnBase, bnum& bnExp, bnum& bnM, bnum& bnOut)
{
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnBase.mpSize(), bnBase.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);
    int     leadBit= 0;
    int     j;

    if(lM>maxSize)
        maxSize= lM;
    maxSize*= 4;

#ifdef MPMONTTEST
    fprintf(g_logFile, "\nmpMontModExp, r: %d, maxSize: %d\n", lM, maxSize);
    fprintf(g_logFile, "Base: "); printNum(bnBase); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "Exp: "); printNum(bnExp); fprintf(g_logFile, "\n");
    fprintf(g_logFile, "M: "); printNum(bnM); fprintf(g_logFile, "\n");
#endif
    try {
        int     r= lM;
        bnum    bnmontBasePower(maxSize);   // Base to Power of 2
        bnum    bnmontA(maxSize);           // Accumulated product

        bnum    bnT(maxSize);
        bnum    bnR(maxSize);
        bnum    bncoR(maxSize);           
        bnum    bnMPrime(maxSize); 

        mpZeroNum(bnmontBasePower);
        mpZeroNum(bnmontA);
        mpZeroNum(bnT);
        mpZeroNum(bncoR);
        mpZeroNum(bnR);
        mpZeroNum(bnMPrime);
        bnR.m_pValue[r]= 1;

        UNUSEDVAR(maxSize);

        // bncoR*bnR + bnM*bnX = 1
        if(!mpExtendedGCD(bnR, bnM, bncoR, bnMPrime, bnT)) {
            throw("cant compute mont gcd");
        }
        // bnT should be 1
#ifdef MPMONTTEST
        fprintf(g_logFile, "T: "); printNum(bnT); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "R: "); printNum(bnR); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "MPrime: "); printNum(bnMPrime); fprintf(g_logFile, "\n");
#endif

        // bnMPrime= -bnMPrime (mod 2^r)
        bnMPrime.mpNegate();
        while(bnMPrime.mpSign()) {
            mpAddTo(bnMPrime, bnR);
        }
#ifdef MPMONTTEST
        fprintf(g_logFile, "finalMPrime: "); printNum(bnMPrime); fprintf(g_logFile, "\n");
#endif

        if(!mpMakeMont(bnBase, bnM, r, bnmontBasePower)) {
            throw("MontMake error 1");
        }
        if(!mpMakeMont(g_bnOne, bnM, r, bnmontA)) {
            throw("MontMake error 2");
        }
#ifdef MPMONTTEST
        fprintf(g_logFile, "montBasePower: "); printNum(bnmontBasePower); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "montA: "); printNum(bnmontA); fprintf(g_logFile, "\n\n");
#endif

        leadBit= mpBitsinNum(bnExp.mpSize(), bnExp.m_pValue);
        
        if(IsBitPositionNonZero(bnExp, 1)) {
            if(!mpMontStep(bnmontBasePower, bnmontA, bnM, 
                           bnMPrime, r, bnT)) {
                throw("MontStep error 1");
            }
            mpZeroNum(bnmontA);
            bnT.mpCopyNum(bnmontA);
            mpZeroNum(bnT);
        }
        for(j=2; j<=leadBit; j++) {
            if(!mpMontStep(bnmontBasePower, bnmontBasePower, bnM, 
                           bnMPrime, r, bnT)) {
                throw("MontStep error 2");
            }
            mpZeroNum(bnmontBasePower);
            bnT.mpCopyNum(bnmontBasePower);
            mpZeroNum(bnT);
            if(IsBitPositionNonZero(bnExp, j)) {
                if(!mpMontStep(bnmontBasePower, bnmontA, bnM, bnMPrime, r, bnT)) {
                    throw("MontStep error 3");
                }
                mpZeroNum(bnmontA);
                bnT.mpCopyNum(bnmontA);
                mpZeroNum(bnT);
            }
        }
        if(!mpMontRed(bnmontA, bnM, r, bnMPrime, bnOut)) {
            throw("MontStep error 4");
        }
#ifdef MPMONTTEST
        fprintf(g_logFile, "j: %d\n", j);
        fprintf(g_logFile, "montBasePower: "); printNum(bnmontBasePower); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "montA: "); printNum(bnmontA); fprintf(g_logFile, "\n\n");
        fprintf(g_logFile, "reduced: "); printNum(bnOut); fprintf(g_logFile, "\n\n");
#endif
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpMontModExp error\n");
        fRet= false;
    }
#ifdef MPMONTTEST
    fprintf(g_logFile, "Out: "); printNum(bnOut); fprintf(g_logFile, "\n\n");
#endif
    return fRet;
}


// ---------------------------------------------------------------------------------


bool mpTestFermatCondition(bnum& bnBase, bnum& bnM)
{
    extern bnum g_bnOne;
    int         sizeM= bnM.mpSize();
    bnum        bnE(sizeM);
    bnum        bnR(sizeM);
    bool        fRet= mpModSub(bnM, g_bnOne, bnM, bnE);

    if(!fRet)
        return false;
    fRet= mpModExp(bnBase, bnE, bnM, bnR);
    if(!fRet)
        return false;
    if(s_isEqualTo== mpUCompare(bnR, g_bnOne))
        return true;
    return false;
}


bool mpFermatTest(bnum& bnBase, bnum& bnM, bnum& bnR)
{
    extern bnum g_bnOne;
    bool        fRet= true;
    int         maxSize= mpWordsinNum(bnBase.mpSize(), bnBase.m_pValue);
    int         lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);

    if(lM>maxSize)
        maxSize= lM;

    try {
        bnum     bnE(lM);
        bool     fRet= mpModSub(bnM, g_bnOne, bnM, bnE);

        if(!fRet)
            throw("mpModSub failed");
        fRet= mpModExp(bnBase, bnE, bnM, bnR);
    }
    catch(const char* sz) {
        sz= NULL;
        fRet= false;
    }
    return fRet;
}


bool mpRSACalculateFastRSAParameters(bnum& bnE, bnum& bnP, bnum& bnQ, 
                    bnum& bnPM1, bnum& bnDP, bnum& bnQM1, bnum& bnDQ)
//  Compute e d(p) + (p-1) t(p) =1 with EUA
//  Compute e d(q) + (q-1) t(q) =1 with EUA
{
    bool            fRet= true;
    extern bnum     g_bnOne;

    int     size= mpWordsinNum(bnP.mpSize(), bnP.m_pValue);
    int     lQ= mpWordsinNum(bnQ.mpSize(), bnQ.m_pValue);

    if(lQ>size)
        size= lQ;
    size*= 2;

    try {
        bnum    bnG(size);
        bnum    bnTP(size);
        bnum    bnTQ(size);

        if(mpUSub(bnP, g_bnOne, bnPM1)!=0ULL) 
            throw("Can't compute PM1");
    
        if(mpUSub(bnQ, g_bnOne, bnQM1)!=0ULL)
            throw("Can't compute QM1");

        if(!mpExtendedGCD(bnE, bnPM1, bnDP, bnTP, bnG))
            throw("Can't compute mpExtendedGCD (1)");

        if(mpCompare(bnG, g_bnOne)!=s_isEqualTo)
            throw("PM1 common factor is not 1");

        if(!mpExtendedGCD(bnE, bnQM1, bnDQ, bnTQ, bnG)) 
            throw("Can't compute mpExtendedGCD (2)");

        if(mpCompare(bnG, g_bnOne)!=s_isEqualTo)
            throw("QM1 common factor is not 1");

        while(bnDP.mpSign())
            mpAddTo(bnDP, bnPM1);

        while(bnDQ.mpSign())
            mpAddTo(bnDQ, bnQM1);
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpRSACalculateFastRSAParameters error: %s", sz);
        fRet= false;
    }

    return fRet;
}


bool mpRSADEC(bnum& bnMsg, bnum& bnP, bnum& bnPM1, bnum& bnDP, 
              bnum& bnQ, bnum& bnQM1, bnum& bnDQ, bnum& bnM, bnum& bnR)
//  Fast RSA Decrypt using Chinese remainer theorem
//  Call mpCRT(Msg^d(p),p,Msg^d(q),q, R)
//  Return R
{
    bool    fRet= true;
    int     maxSize= mpWordsinNum(bnMsg.mpSize(), bnMsg.m_pValue);
    int     lM= mpWordsinNum(bnM.mpSize(), bnM.m_pValue);
    int     size;

    if(lM>maxSize)
        maxSize= lM;

    size= mpWordsinNum(bnDP.mpSize(), bnDP.m_pValue);
    if(size>maxSize)
        maxSize= size;
    size= mpWordsinNum(bnDQ.mpSize(), bnDQ.m_pValue);
    if(size>maxSize)
        maxSize= size;
    maxSize*= 2;

    try {
        bnum    bnT1(maxSize);
        bnum    bnT2(maxSize);

#ifndef MONTGOMERYENABLED
        if(!mpModExp(bnMsg, bnDP, bnP, bnT1))
            throw("mpModExp fails");
        if(!mpModExp(bnMsg, bnDQ, bnQ, bnT2))
            throw("mpModExp fails");
#else
        if(!mpMontModExp(bnMsg, bnDP, bnP, bnT1))
            throw("mpModExp fails");
        if(!mpMontModExp(bnMsg, bnDQ, bnQ, bnT2))
            throw("mpModExp fails");
#endif

        if(!mpCRT(bnT1, bnP, bnT2, bnQ, bnR))
            throw("mpCRT fails");
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpRSADEC error: %s\n", sz);
        fRet= false;
    }

    return fRet;
}


bool mpRSAENC(bnum& bnMsg, bnum& bnE, bnum& bnM, bnum& bnR)
{
    bool fRet= mpModExp(bnMsg, bnE, bnM, bnR);

    return fRet;
}


bool mpRSAGen(int numBits, bnum& bnE, bnum& bnP, bnum& bnQ, bnum& bnM, 
              bnum& bnD, bnum& bnOrder)
{
    bool        fRet= true;
    extern bnum g_bnOne;
    int         sizeP= bnP.mpSize();
    int         sizeQ= bnQ.mpSize();
    int         sizeM= bnM.mpSize();

#ifdef TEST
    fprintf(g_logFile, "mpRSAGen: GenPrime start %d %d %d\n", sizeP, sizeQ, sizeM);
#endif
    // Get two primes
    if(!mpGenPrime(numBits/2, bnP)) {
        fprintf(g_logFile, "Cant find P\n");
        return false;
    }

    if(!mpGenPrime(numBits/2, bnQ)) {
        fprintf(g_logFile, "Cant find Q\n");
        return false;
    }

    // Multiply to get bnM
    int     lP= mpWordsinNum(sizeP, bnP.m_pValue);
    if((lP*NUMBITSINU64)>numBits/2) {
        fprintf(g_logFile, "P too big\n");
        return false;
    }
    int     lQ= mpWordsinNum(sizeQ, bnQ.m_pValue);
    if((lQ*NUMBITSINU64)>numBits/2) {
        fprintf(g_logFile, "Q too big\n");
        return false;
    }
    mpUMult(bnP, bnQ, bnM);
    int     lM= mpWordsinNum(sizeM, bnM.m_pValue);
    if(lM*NUMBITSINU64>numBits) {
        fprintf(g_logFile, "Modulus too big\n");
        return false;
    }

    // Dec to get bnP-1 and bnQ-1
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: exponent modulus\n");
#endif
    try {
        bnum bnPM1(sizeP);
        bnum bnQM1(sizeQ);
        mpUSub(bnP, g_bnOne, bnPM1);
        mpUSub(bnQ, g_bnOne, bnQM1);

        // Compute Order
        mpUMult(bnPM1, bnQM1, bnOrder);

#ifdef ARITHTEST
        fprintf(g_logFile, "mpRSAGen: computing order\n");
#endif
        // get bnD
        bnum bnT(sizeM);
        bnum bnG(sizeM);
        if(!mpExtendedGCD(bnE, bnOrder, bnD, bnT, bnG))
            throw("Cant find D");
#ifdef ARITHTEST
        fprintf(g_logFile, "mpRSAGen: computed order\n");
#endif
        if(mpCompare(bnG, g_bnOne)!=s_isEqualTo)
            throw("Exponent and Order are not coprime");
        while(bnD.mpSign()) {
            // D is negative, add bnOrder
            mpAddTo(bnD, bnOrder);
        }
    }
    catch(const char* sz) {
        fprintf(g_logFile, "mpRSAGen error: %s", sz);
        fRet= false;
    }

    return fRet;
}


// ---------------------------------------------------------------------------------


