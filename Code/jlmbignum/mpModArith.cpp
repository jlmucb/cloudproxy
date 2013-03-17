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
    int     maxSize= bnA.mpSize();
    int     i= bnM.mpSize();
    bool    fRet= false;

    if(i>maxSize)
        maxSize= i;

    try {
        bnum    bnQ(maxSize);
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
    int         maxSize= bnA.mpSize();
    int         i= bnM.mpSize();
    extern bnum g_bnOne;

    if(i>maxSize)
        maxSize= i;

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
    int     maxSize= bnA.mpSize();
    int     i= bnB.mpSize();
    int     j= bnM.mpSize();

    if(i>maxSize)
        maxSize= i;
    if(j>maxSize)
        maxSize= j;

    if(!(mpCompare(bnA, bnB)==s_isLessThan)) {
        mpUSub(bnA, bnB, bnR);
    }
    else {
        bnum  bnC(maxSize+2);
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
    int     maxSize= bnA.mpSize();
    int     i= bnB.mpSize();
    int     j= bnM.mpSize();
    bool    fRet= false;

    if(i>maxSize)
        maxSize= i;
    if(j>maxSize)
        maxSize= j;
    maxSize*= 2;

    try {
        bnum  bnC(maxSize+1);
        bnum  bnQ(maxSize+1);
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
    int     sizeA= bnA.mpSize();
    int     sizeM= bnM.mpSize();
    int     maxSize;
    bool    fRet= false;

    if(sizeA>sizeM)
        maxSize= sizeA;
    else
        maxSize= sizeM;

    try {
        bnum bnT(maxSize);
        bnum bnG(maxSize);
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
    int     maxSize= bnA.mpSize();
    int     i= bnM.mpSize();
    bool    fRet= false;

    if(i>maxSize)
        maxSize= i;
    maxSize*= 2;

    try {
        bnum    bna(maxSize);
        bnum    bnc(maxSize);
        bnum    bnb(maxSize);
        bnum    bnG(maxSize);

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
    int     maxSizeB= bnBase.mpSize();
    int     maxSizeM= bnM.mpSize();
    int     maxSize;
    int     j;

    if(maxSizeB>maxSizeM) {
        maxSize= 2*maxSizeB+1;
    }
    else {
        maxSize= 2*maxSizeM+1;
    }

    bnum    bnBasePow(maxSize);    // Base to powers of 2
    bnum    bnAccum(maxSize);      // Exponent so far
    bnum    bnTemp(maxSize);       // Temporary storage
    bnum    bnQ(maxSize);          // Quotient

    UNUSEDVAR(maxSize);
    bnBase.mpCopyNum(bnBasePow);
    bnAccum.m_pValue[0]= 1ULL;

    int iLeadBit= mpBitsinNum(bnExp.mpSize(), bnExp.m_pValue);
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
    int         sizeM= bnM.mpSize();
    bnum        bnE(sizeM);
    bool        fRet= mpModSub(bnM, g_bnOne, bnM, bnE);

    if(!fRet)
        return false;
    fRet= mpModExp(bnBase, bnE, bnM, bnR);
    return fRet;
}


bool mpRSACalculateFastRSAParameters(bnum& bnE, bnum& bnP, bnum& bnQ, 
                    bnum& bnPM1, bnum& bnDP, bnum& bnQM1, bnum& bnDQ)
//  Compute e d(p) + (p-1) t(p) =1 with EUA
//  Compute e d(q) + (q-1) t(q) =1 with EUA
{
    extern bnum     g_bnOne;
    bool            fRet= false;
    bnum*           pbnTP= NULL;
    bnum*           pbnTQ= NULL;
    bnum*           pbnG= NULL;

    int size= (int)bnP.mpSize();
    if((int)bnQ.mpSize()>size)
        size= (int)bnQ.mpSize();
    size*= 2;

    pbnG= new bnum(size);
    if(pbnG==NULL)
        goto done;
    pbnTP= new bnum(size);
    if(pbnTP==NULL)
        goto done;
    pbnTQ= new bnum(size);
    if(pbnTQ==NULL)
        goto done;

    if(mpUSub(bnP, g_bnOne, bnPM1)!=0ULL) {
        fprintf(g_logFile, "Can't compute PM1\n");
        fRet= false;
        goto done;
    }

    if(mpUSub(bnQ, g_bnOne, bnQM1)!=0ULL) {
        fprintf(g_logFile, "Can't compute QM1\n");
        fRet= false;
        goto done;
    }

    fRet= mpBinaryExtendedGCD(bnE, bnPM1, bnDP, *pbnTP, *pbnG);
    if(!fRet)
        goto done;
    if(mpCompare(*pbnG, g_bnOne)!=s_isEqualTo) {
        fprintf(g_logFile, "PM1 common factor is not 1\n");
        fRet= false;
        goto done;
    }
    fRet= mpBinaryExtendedGCD(bnE, bnQM1, bnDQ, *pbnTQ, *pbnG);
    if(!fRet)
        goto done;
    if(mpCompare(*pbnG, g_bnOne)!=s_isEqualTo) {
        fprintf(g_logFile, "QM1 common factor is not 1\n");
        fRet= false;
        goto done;
    }

done:
    if(pbnTP!=NULL) {
        delete pbnTP;
        pbnTP= NULL;
    }
    if(pbnTQ!=NULL) {
        delete pbnTQ;
        pbnTQ= NULL;
    }
    if(pbnG!=NULL) {
        delete pbnG;
        pbnG= NULL;
    }

    return fRet;
}


bool mpRSADEC(bnum& bnMsg, bnum& bnP, bnum& bnPM1, bnum& bnDP, 
              bnum& bnQ, bnum& bnQM1, bnum& bnDQ, bnum& bnM, bnum& bnR)
//  Fast RSA Decrypt using Chinese remainer theorem
//  Call mpCRT(Msg^d(p),p,Msg^d(q),q, R)
//  Return R
{
    extern bnum     g_bnOne;
    bool            fRet= false;
    bnum*           pbnT1= NULL;
    bnum*           pbnT2= NULL;

    int size= (int)bnDP.mpSize();
    if((int)bnDQ.mpSize()>size)
        size= (int)bnDQ.mpSize();

    pbnT1= new bnum(size);
    if(pbnT1==NULL)
        goto done;
    pbnT2= new bnum(size);
    if(pbnT2==NULL)
        goto done;

    fRet= mpModExp(bnMsg, bnDP, bnP, *pbnT1);
    if(!fRet)
        goto done;
    fRet= mpModExp(bnMsg, bnDQ, bnQ, *pbnT2);
    if(!fRet)
        goto done;

    fRet= mpCRT(*pbnT1, bnP, *pbnT2, bnQ, bnR);
    if(!fRet) {
        fprintf(g_logFile, "mpRSADEC: mpCRT failed\n");
    }

done:
    if(pbnT1!=NULL) {
        delete pbnT1;
        pbnT1= NULL;
    }
    if(pbnT2!=NULL) {
        delete pbnT2;
        pbnT2= NULL;
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
    extern bnum g_bnOne;
    int         sizeP= bnP.mpSize();
    int         sizeQ= bnQ.mpSize();
    int         sizeM= bnM.mpSize();

#ifdef TEST
    fprintf(g_logFile, "mpRSAGen: GenPrime start\n");
#endif
    // Get two primes
    if(!mpGenPrime(numBits/2, bnP)) {
        fprintf(g_logFile, "Cant find P\n");
        return false;
    }
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: GenPrime got first prime\n");
#endif
    if(!mpGenPrime(numBits/2, bnQ)) {
        fprintf(g_logFile, "Cant find Q\n");
        return false;
    }
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: GenPrime got second prime\n");
#endif

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
    if(!mpBinaryExtendedGCD(bnE, bnOrder, bnD, bnT, bnG)) {
        fprintf(g_logFile, "Cant find D\n");
        return false;
    }
#ifdef ARITHTEST
    fprintf(g_logFile, "mpRSAGen: computed order\n");
#endif
    if(mpCompare(bnG, g_bnOne)!=s_isEqualTo) {
        fprintf(g_logFile, "Exponent and Order are not coprime\n");
        printNum(bnG); printf("\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "mpRSAGen: returns true\n");
#endif
    return true;
}


// ---------------------------------------------------------------------------------


