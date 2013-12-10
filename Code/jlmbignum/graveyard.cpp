//
//  File: graveyard
//  Description: 
//
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


//#define BINARYGCDDEBUG
//  Function: bool mpBinaryExtendedGCD
//  Arguments:
//      IN bnum bnA
//      IN bnum bnB
//      OUT bnum bnX
//      OUT bnum bnY
//      OUT bnum bnG
//  Description:
//      Compute x, y, g:  ax+by=g=(x,y)
bool mpBinaryExtendedGCD(bnum& bnA, bnum& bnB, bnum& bnX, bnum& bnY, bnum& bnG)

{
    bool    fRet= true;

    if(bnA.mpSign() || bnB.mpSign()) {
        fprintf(g_logFile, "mpBinaryExtendedGCD: negative arguments forbidden\n");
        return false;       
    }

    int     compare;
    int     sizeA= bnA.mpSize();
    int     sizeB= bnB.mpSize();
    int     size;

    if(sizeA>=sizeB)
        size= 4*sizeA;
    else
        size= 4*sizeB;

#ifdef BINARYGCDDEBUG
    fprintf(g_logFile, "mpBinaryExtendedGCD: \n"); 
    fprintf(g_logFile, "A: ");printNum(bnA);fprintf(g_logFile, "\n");
    fprintf(g_logFile, "B: ");printNum(bnB);fprintf(g_logFile, "\n");
#endif

    try {
        bnum  bnAred(size);
        bnum  bnBred(size);
        bnum  bnTG(size);
        bnum  bnTA(size);
        bnum  bnTB(size);
        bnum  bnTC(size);
        bnum  bnTD(size);
        bnum  bnTU(size);
        bnum  bnTV(size);

        bnTA.m_pValue[0]= 1ULL;
        bnTD.m_pValue[0]= 1ULL;
        bnTG.m_pValue[0]= 1ULL;

        // highest power of 2 dividing both
        int   pow2X= max2PowerDividing(bnA);
        int   pow2Y= max2PowerDividing(bnB);
        int   power;

        if(pow2X<=pow2Y)
            power= pow2X;
        else
            power= pow2Y;
        if(!mpShift(bnA, -power, bnAred)) {
            fprintf(g_logFile, "mpShift failed 1\n");
        }
        if(!mpShift(bnB, -power, bnBred)) {
            fprintf(g_logFile, "mpShift failed 2\n");
        }

        // put shifted X into U and shifted Y into V
        bnAred.mpCopyNum(bnTU);
        bnBred.mpCopyNum(bnTV);

#ifdef BINARYGCDDEBUG
        fprintf(g_logFile, "before loop, size: %d, power: %d\n", size, power);
        fprintf(g_logFile, "Ared: ");printNum(bnAred); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "Bred: ");printNum(bnBred); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "TA: ");printNum(bnTA); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "TB: ");printNum(bnTB); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "TC: ");printNum(bnTC); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "TD: ");printNum(bnTD); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "TU: ");printNum(bnTU); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "TV: ");printNum(bnTV); fprintf(g_logFile, "\n");
        fprintf(g_logFile, "TG: ");printNum(bnTG); fprintf(g_logFile, "\n");
#endif

        for(;;) {

            // U even?
            // u/= 2L;
            // if(A!=0 && B!=0 && (A&0x1L)==0 && (B&0x1)==0) {
            //     A/= 2L;
            //     B/= 2L;
            // }
            // else {
            //     A= (A+y)/2L;
            //     B= (B-x)/2L;
            // }
            while(!bnTU.mpIsZero() && (bnTU.m_pValue[0]&0x1ULL)==0) {
                shiftdowninplace(bnTU, 1);
                if(!bnTA.mpIsZero() && !bnTB.mpIsZero() &&
                   ((bnTA.m_pValue[0]&0x1ULL)==0) && ((bnTB.m_pValue[0]&0x1ULL)==0) ) {
                    shiftdowninplace(bnTA, 1);
                    shiftdowninplace(bnTB, 1);
                }
                else {
                    mpAddTo(bnTA, bnBred);
                    mpSubFrom(bnTB, bnAred);
                    shiftdowninplace(bnTA, 1);
                    shiftdowninplace(bnTB, 1);
                }
#ifdef BINARYGCDDEBUG
                fprintf(g_logFile, "U even clause\n");
                fprintf(g_logFile, "Ared: ");printNum(bnAred); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "Bred: ");printNum(bnBred); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TA: ");printNum(bnTA); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TB: ");printNum(bnTB); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TC: ");printNum(bnTC); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TD: ");printNum(bnTD); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TU: ");printNum(bnTU); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TV: ");printNum(bnTV); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TG: ");printNum(bnTG); fprintf(g_logFile, "\n");
#endif
            }

            // V even?
            //     v/= 2L;
            // if(C!=0 && D!=0 && (C&0x1L)==0 && (D&0x1)==0) {
            //     C/= 2L;
            //     D/= 2L;
            // }
            // else {
            //     C= (C+y)/2L;
            //     D= (D-x)/2L;
            // }
            while(!bnTV.mpIsZero() && (bnTV.m_pValue[0]&0x1ULL)==0) {
                shiftdowninplace(bnTV, 1);
                if(!bnTC.mpIsZero() && !bnTD.mpIsZero() &&
                   ((bnTC.m_pValue[0]&0x1ULL)==0) && ((bnTD.m_pValue[0]&0x1ULL)==0) ) {
                    shiftdowninplace(bnTC, 1);
                    shiftdowninplace(bnTD, 1);
                }
                else {
                    mpAddTo(bnTC, bnBred);
                    mpSubFrom(bnTD, bnAred);
                    shiftdowninplace(bnTC, 1);
                    shiftdowninplace(bnTD, 1);
                }
#ifdef BINARYGCDDEBUG
                fprintf(g_logFile, "V even clause\n");
                fprintf(g_logFile, "Ared: ");printNum(bnAred); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "Bred: ");printNum(bnBred); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TA: ");printNum(bnTA); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TB: ");printNum(bnTB); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TC: ");printNum(bnTC); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TD: ");printNum(bnTD); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TU: ");printNum(bnTU); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TV: ");printNum(bnTV); fprintf(g_logFile, "\n");
                fprintf(g_logFile, "TG: ");printNum(bnTG); fprintf(g_logFile, "\n");
#endif
            }

            // if(u>=v) {
            //    u= u-v;
            //    A= A-C;
            //    B= B-D;
            // }
            // else {
            //    v= v-u;
            //    C= C-A;
            //    D= D-B;
            // }
            compare= mpCompare(bnTU, bnTV);
            if(compare!=s_isLessThan) {
                mpSubFrom(bnTU, bnTV);
                mpSubFrom(bnTA, bnTC);
                mpSubFrom(bnTB, bnTD);
            }
            else {
                mpSubFrom(bnTV, bnTU);
                mpSubFrom(bnTC, bnTA);
                mpSubFrom(bnTD, bnTB);
            }
#ifdef BINARYGCDDEBUG
            fprintf(g_logFile, "reduce clause\n");
            fprintf(g_logFile, "Ared: ");printNum(bnAred); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "Bred: ");printNum(bnBred); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "TA: ");printNum(bnTA); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "TB: ");printNum(bnTB); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "TC: ");printNum(bnTC); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "TD: ");printNum(bnTD); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "TU: ");printNum(bnTU); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "TV: ");printNum(bnTV); fprintf(g_logFile, "\n");
            fprintf(g_logFile, "TG: ");printNum(bnTG); fprintf(g_logFile, "\n");
#endif
            // if(u==0L) were done
            if(bnTU.mpIsZero()) {
                bnTC.mpCopyNum(bnX);
                bnTD.mpCopyNum(bnY);
                if(!mpShift(bnTV, power, bnG)) {
                    fprintf(g_logFile, "mpShift failed 3\n");
                }
                break;
            }
        }
    }
    catch(const char* sz) {
        fRet= false;
    }
#ifdef BINARYGCDDEBUG
        fprintf(g_logFile, "about to return\n");
#endif
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

// ---------------------------------------------------------------------------------


