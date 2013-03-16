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

#include "bignum.h"
#include "mpFunctions.h"


// ---------------------------------------------------------------------------------


void UCompareTest(bnum& bnA, bnum& bnB)
{
    int r= mpUCompare(bnA, bnB);

    printNum(bnA);
    switch(r) {
      case 1:
        printf(" > ");
        break;
      case -1:
        printf(" < ");
        break;
      case 0:
        printf(" = ");
        break;
    }
    printNum(bnB);
    printf("\n");
}


// ---------------------------------------------------------------------------------

int main(int an, char** av)
{
    int             i, k;
    u64             uM;
    u64             uR;
    u64             uCarry;
    extern void     initBigNum();
    extern bool     initCryptoRand();
    extern  bnum    g_bnTwo;
    extern  bnum    g_bnOne;

    initBigNum();
    initCryptoRand();

    bnum bnTest1(3);
    bnum bnTest2(2);
    bnum bnTest3(2);
    bnum bnTest4(2);
    bnum bnTest5(2);
    bnum bnTest6(2);
    bnum bnTest7(3);

    bnum bnTest12(16);
    bnum bnTest14(16);

    bnum bnTest8(8);
    bnum bnTest9(8);
    bnum bnTest10(8);
    bnum bnTest11(8);
    bnum bnTestMsg(8);

    bnum bnPrimeTest(80);
    bnum bnExpP(80);
    bnum bnExpQ(80);
    bnum bnExpR(160);
    bnum bnExpM(160);
    bnum bnExpE(160);
    bnum bnExpD(160);
    bnum bnExpO(160);
    bnum bnExpT(160);

    u64 rguTest1[2]= {0xffffffffffffffffULL, 0xffffffffffffffffULL};
    u64 rguTest2[2]= {0x0101010100000000ULL, 0xccccaaaaeeeebbbbULL};
    u64 rguTest3[3]= {0xccccaaaa01010101ULL, 0xeeeebbbb33333333ULL};
    u64 rguTest4[2]= {0ULL, 0x0000000400000000ULL};
    u64 rguTest5[3]= {0ULL, 0x0000000500000000ULL, 0x0000000000000000ULL};
    u64 rguTest6[2]= {0x0000008100000000ULL, 0x0000000000000000ULL};
    u64 rguTest7[3]= {0xccccaaaa01010101ULL, 0xeeeebbbb33333333ULL, 0x00356ab299771254ULL};

    u64 rguTest10[7]= {0x00000b255a6beefdULL, 0xf7ee4e1f44d6d60cULL, 0x565bfcecf309e0d0ULL, 
                       0xe4c2b4b837e8591cULL, 0x1d3605a82eb76d22ULL, 0xa90a55e332313240ULL};
    u64 rguTest11[2]= {0x0ULL, 0x1ULL};
    u64 rguTest12[4]= {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL};

    for(i=5;i>=0;i--)
        bnTest10.m_pValue[5-i]= rguTest10[i];

    for(i=0; i<2; i++) {
        bnTest1.m_pValue[i]= rguTest1[i];
        bnTest2.m_pValue[i]= rguTest2[i];
        bnTest3.m_pValue[i]= rguTest3[i];
        bnTest4.m_pValue[i]= rguTest4[i];
        bnTest5.m_pValue[i]= rguTest5[i];
        bnTest6.m_pValue[i]= rguTest6[i];
        bnTest7.m_pValue[i]= rguTest7[i];
        bnTest11.m_pValue[i]= rguTest11[i];
    }
    bnTest7.m_pValue[i]= rguTest7[i];
    for(i=0; i<4; i++) {
        bnTest12.m_pValue[i]= rguTest12[i];
    }
    bnPrimeTest.m_pValue[0]= 0ULL;


    try {
        // Multiple Precision Tests
        printf("\n");
        printf("Number 2: "); printNum(bnTest2, true); printf("\n"); 
        printf("Number 3: "); printNum(bnTest3, true); printf("\n"); 
        printf("Zero: "); printNum(bnTest8); printf("\n"); 
        printf("\n");

        printf("Shift tests\n");
        k= 64;
        if(!mpShift(bnTest1, k, bnTest8)) {
            printf("Shift returns false\n");
        }
        else {
            printNum(bnTest1); printf("<<%d=\n\t",k); printNum(bnTest8); printf("\n");
        }
        mpZeroNum(bnTest8);

        k= 3;
        if(!mpShift(bnTest1, k, bnTest8)) {
            printf("Shift returns false\n");
        }
        else {
            printNum(bnTest1); printf("<<%d=\n\t",k); printNum(bnTest8); printf("\n");
        }
        mpZeroNum(bnTest8);

        k= -64;
        if(!mpShift(bnTest1, k, bnTest8)) {
            printf("Shift returns false\n");
        }
        else {
            printNum(bnTest1); printf("<<%d=\n\t",k); printNum(bnTest8); printf("\n");
        }
        mpZeroNum(bnTest8);

        k= -3;
        if(!mpShift(bnTest1, k, bnTest8)) {
            printf("Shift returns false\n");
        }
        else {
            printNum(bnTest1); printf("<<%d=\n\t", k); printNum(bnTest8); printf("\n");
        }
        mpZeroNum(bnTest8);

        printf("\n");
        printf("Unsigned compare tests\n");
        UCompareTest(bnTest2, bnTest3);
        UCompareTest(bnTest3, bnTest3);
        UCompareTest(bnTest3, bnTest2);

        printf("\n");
        printf("Unsigned addition tests\n");
        printNum(bnTest1); printf(" + "); printNum(g_bnOne); printf("=\n\t");
        uCarry= mpUAdd(bnTest1, g_bnOne, bnTest8);
        printNum(bnTest8); printf(", Carry: %lx\n", (up64) uCarry); 
        mpZeroNum(bnTest8);
        printNum(bnTest1); printf(" + "); printNum(bnTest2); printf("=\n\t");
        uCarry= mpUAddTo(bnTest1, bnTest2);
        printNum(bnTest1); printf(", Carry: %lx\n", (up64) uCarry); 
        mpZeroNum(bnTest8);
        printNum(bnTest1); printf(" + "); printNum(bnTest2); printf("=\n\t");
        uCarry= mpUAdd(bnTest1, bnTest2, bnTest8);
        printNum(bnTest8); printf(", Carry: %lx\n", (up64) uCarry); 
        mpZeroNum(bnTest8);
        uM= 23;
        printNum(bnTest7); printf(" + %016lx= \n\t", (up64) uM);
        mpSingleUAddTo(bnTest7, uM);
        printNum(bnTest7);
        printf("\n");
        mpZeroNum(bnTest8);

        printf("\n");
        printf("Unsigned subtraction tests\n");
        printNum(bnTest11); printf(" - ");
        printNum(g_bnOne); printf("=\n\t");
        mpUSub(bnTest11, g_bnOne, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        printNum(bnTest3); printf(" - ");
        printNum(bnTest2); printf("=\n\t");
        mpUSub(bnTest3, bnTest2, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        printNum(bnTest3); printf(" - ");
        printNum(bnTest2); printf("=\n\t");
        mpUSubFrom(bnTest3, bnTest2);
        printNum(bnTest3); printf("\n"); 

        printf("\n");
        printf("Unsigned multiplication tests\n");
        printNum(bnTest12); printf(" * "); printNum(g_bnOne); printf("=\n\t"); 
        mpUMult(bnTest12, g_bnOne, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        printNum(bnTest12); printf(" * "); printNum(g_bnTwo); printf("=\n\t"); 
        mpUMult(bnTest12, g_bnTwo, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        uM= 4ULL;
        bnTest3.m_pValue[0]= rguTest3[0];
        bnTest3.m_pValue[1]= rguTest3[1];
        printNum(bnTest3); printf(" * %016lx= \n\t", (up64) uM);
        uCarry= mpUSingleMultBy(bnTest3, uM);
        printNum(bnTest3); printf(", Carry: %016lx\n", (up64) uCarry); 
        mpZeroNum(bnTest8);
        uM= 4ULL;
        bnTest3.m_pValue[0]= rguTest3[0];
        bnTest3.m_pValue[1]= rguTest3[1];
        printNum(bnTest3); printf(" * %016lx << %d= \n\t", (up64) uM, 2);
        mpUSingleMultAndShift(bnTest3, uM, 2, bnTest8);
        printNum(bnTest8); printf("\n");
        mpZeroNum(bnTest8);
        printNum(bnTest4); printf(" * "); printNum(bnTest5); printf("=\n\t"); 
        mpUMult(bnTest4, bnTest5, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        printNum(bnTest3); printf(" * "); printNum(bnTest2); printf("=\n\t"); 
        mpUMult(bnTest3, bnTest2, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        printNum(bnTest3); printf(" * "); printNum(bnTest3); printf("=\n\t"); 
        mpUMult(bnTest3, bnTest3, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        printNum(bnTest3); printf(" * "); printNum(bnTest3); printf("=\n\t"); 
        mpUMult(bnTest3, bnTest3, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);

        printf("\n");
        printf("Unsigned division tests\n");
        printNum(bnTest4); printf("/ %016lx= \n", (up64) uM);
        mpSingleUDiv(bnTest4, uM, bnTest8, &uR, true);
        printNum(bnTest8);
        printf(", Rem %016lx\n", (up64) uR);
        mpZeroNum(bnTest8);
        uM= 23;
        printNum(bnTest6); printf("/ %016lx= \n\t", (up64) uM);
        mpSingleUDiv(bnTest6, uM, bnTest8, &uR, true);
        printNum(bnTest8);
        printf(", Rem %016lx\n", (up64) uR);
        mpZeroNum(bnTest8);
        printNum(bnTest2); printf(" / "); printNum(bnTest4); printf("=\n\t");
        mpUDiv(bnTest2, bnTest4, bnTest8, bnTest9);
        printNum(bnTest8); printf(", Rem "); printNum(bnTest9); printf("\n");

        mpZeroNum(bnTest8);
        mpZeroNum(bnTest9);
        printNum(bnTest10); printf(" / "); printNum(bnTest3); printf("=\n\t");
        mpUDiv(bnTest10, bnTest3, bnTest8, bnTest9);
        printNum(bnTest8); printf(", Rem "); printNum(bnTest9); printf("\n");
        mpZeroNum(bnTest8);
        mpZeroNum(bnTest9);

        printf("\n");
        printf("Signed arithmetic tests\n");
        bnTest1.mpNegate();
        printNum(bnTest1); printf(" + "); printNum(bnTest2); printf("=\n\t");
        uCarry= mpAdd(bnTest1, bnTest2, bnTest8);
        printNum(bnTest8); printf(", Carry: %lx\n", (up64) uCarry); 
        mpZeroNum(bnTest8);
        bnTest2.mpNegate();
        printNum(bnTest1); printf(" + "); printNum(bnTest2); printf("=\n\t");
        uCarry= mpAdd(bnTest1, bnTest2, bnTest8);
        printNum(bnTest8); printf(", Carry: %lx\n", (up64) uCarry); 
        mpZeroNum(bnTest8);
        bnTest2.mpNegate();
        bnTest3.mpNegate();
        printNum(bnTest3); printf(" - ");
        printNum(bnTest2); printf("=\n\t");
        mpSub(bnTest3, bnTest2, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        bnTest1.mpNegate();
        bnTest2.mpNegate();
        mpZeroNum(bnTest8);
        printNum(bnTest3); printf(" * "); printNum(bnTest2); printf("=\n\t"); 
        mpMult(bnTest3, bnTest2, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);
        bnTest3.mpNegate();
        printNum(bnTest3); printf(" * "); printNum(bnTest2); printf("=\n\t"); 
        mpMult(bnTest3, bnTest2, bnTest8);
        printNum(bnTest8); printf("\n"); 
        mpZeroNum(bnTest8);

        printf("\n");
        // Conversion Tests
        char rgszAns[256];
        printf("\nFormatting tests\n");

        if(!ConvertToDecimalString(bnTest4, 256, (char*)rgszAns))
            printf("Bad Conversion\n");
        else {
            printNum(bnTest4); printf("_2= "); printf("%s_10\n", rgszAns); 
        }

        if(!ConvertToDecimalString(bnTest2, 256, rgszAns))
            printf("Bad Conversion\n");
        else {
            printNum(bnTest2); printf("_2= "); printf("%s_10\n", rgszAns); 
        }
        bnum bnCB1(20);
        if(!ConvertFromDecimalString(bnCB1, rgszAns))   
            printf("Bad Conversion\n");
        else {
            printf("Converted back: "); printNum(bnCB1); printf("\n"); 
        }
        printf("\n");
#ifdef OLD
        int iLeadBit= LeadingNonZeroBit(bnTest1.mpSize(), bnTest1.m_pValue);
#else
        int iLeadBit= mpBitsinNum(bnTest1.mpSize(), bnTest1.m_pValue);
#endif
        printf("LeadBit in\n"); printNum(bnTest1); 
        printf("\n is %d\n", iLeadBit);
#ifdef OLD
        iLeadBit= LeadingNonZeroBit(g_bnOne.mpSize(), g_bnOne.m_pValue);
#else
        iLeadBit= mpBitsinNum(g_bnOne.mpSize(), g_bnOne.m_pValue);
#endif
        printf("LeadBit in\n"); printNum(g_bnOne); 
        printf("\n is %d\n", iLeadBit);
        printf("\n");
        printf("Modular Tests\n");
        k= -2;
        printf("mpShiftinPlace: "); printNum(bnTest1);
        printf(" <<  %d = ", k); 
        mpShiftInPlace(bnTest1,k);
        printNum(bnTest1); printf("\n");
        k= 3;
        printf("mpShiftinPlace: "); printNum(bnTest1);
        printf(" <<  %d = ", k); 
        mpShiftInPlace(bnTest1,k);
        printNum(bnTest1); printf("\n");
        mpZeroNum(bnTest8);
        mpMod(bnTest7, bnTest5, bnTest8);
        printf("mpMod: "); printNum(bnTest7);
        printf(" mod "); printNum(bnTest5);
        printf(" = "); printNum(bnTest8); printf("\n");
        bnTest8.mpNegate();
        printf("mpModNormalize: "); printNum(bnTest8);
        mpModNormalize(bnTest8, bnTest5);
        printf(" mod "); printNum(bnTest5);
        printf(" = "); printNum(bnTest8); printf("\n");
        mpZeroNum(bnTest8);
        mpModAdd(bnTest3, bnTest7, bnTest5, bnTest8);
        printf("mpModAdd: "); printNum(bnTest3); printf(" + "); printNum(bnTest7);
        printf(" mod "); printNum(bnTest5);
        printf(" = "); printNum(bnTest8); printf("\n");
        mpZeroNum(bnTest9);
        mpModNormalize(bnTest7, bnTest5);
        mpModSub(bnTest8, bnTest7, bnTest5, bnTest9);
        printf("mpModSub: "); printNum(bnTest8); printf(" - "); printNum(bnTest7);
        printf(" mod "); printNum(bnTest5);
        printf(" = "); printNum(bnTest9); printf("\n");
        mpZeroNum(bnTest9);
        mpZeroNum(bnTest8);
        mpModMult(bnTest3, bnTest4, bnTest5, bnTest8);
        printf("mpModMult: "); printNum(bnTest3); printf(" * "); printNum(bnTest4);
        printf(" mod "); printNum(bnTest5);
        printf(" = "); printNum(bnTest8); printf("\n");
        mpZeroNum(bnTest8);
        mpZeroNum(bnTest9);

        printf("\n");
        printf("Big GCD tests and exponentiate\n");
        bnum bncA(5);
        bnum bncB(5);
        bnum bnGcd(5);

        bnGcd.m_pValue[0]= 1;
        if(!mpBinaryExtendedGCD(bnTest3, bnTest4, bncA, bncB, bnGcd)) {
            printf("mpBinaryExtendedGCD returns false\n");
        }
        else {
            printf("mpBinaryExtendedGCD: "); 
            printNum(bnTest3); 
            printf("("); printNum(bncA); printf(") + ");
            printNum(bnTest4);
            printf("("); printNum(bncB); printf(") = ");
            printNum(bnGcd);
            printf("\n"); 
        }
        mpModInv(bnTest7, bnTest3, bnTest8);
        printf("mpModInv: "); printNum(bnTest7); printf("^-1 (mod "); printNum(bnTest3);
        printf(")= "); printNum(bnTest8); printf("\n"); printf("\n");
        mpZeroNum(bnTest8);
        mpModDiv(bnTest7, bnTest7, bnTest3, bnTest8);
        printf("mpDiv: "); printNum(bnTest7); printf(" / "); 
        printNum(bnTest7); printf(" (mod "); 
        printNum(bnTest3); printf(")= "); printNum(bnTest8); printf("\n"); printf("\n");
        mpZeroNum(bnTest8);
        mpModExp(bnTest7, bnTest4, bnTest3, bnTest8);
        printNum(bnTest7); printf(" ** "); 
        printNum(bnTest4); printf(" (mod "); 
        printNum(bnTest3); printf(")= "); printNum(bnTest8); printf("\n"); printf("\n");
        mpZeroNum(bnTest8);

        // Prime Test
        printf("Prime Test\n");
        if(mpGenPrime(100, bnPrimeTest)) {
            printf("Prime: ");
            printNum(bnPrimeTest); printf("\n");
            printf("\n");
        }
        else {
            printf("Prime test failed\n\n");
        }

        // Fermat Test bool 3671
        printf("Fermat Test Test\n");
        bnum    bnTP(1);
        bnTP.m_pValue[0]= 3671ULL;
        if(mpFermatTest(g_bnTwo, bnTP, bnExpR)) {
            printf("Fermat test with base\n    ");
            printNum(g_bnTwo);
            printf("\nand proposed prime\n    ");
            printNum(bnTP);
            printf("\nyields\n    ");
            printNum(bnExpR);
            printf("   ---   Should be 1\n\n");
        }
        else {
            printf("Fermat test returns false\n\n");
        }
        mpZeroNum(bnExpR);

        // Fermat Test on generated prime
        printf("Fermat Test\n");
        mpZeroNum(bnExpR);
        if(mpFermatTest(g_bnTwo, bnPrimeTest, bnExpR)) {
            printf("Fermat test with base\n    ");
            printNum(g_bnTwo);
            printf("\nand proposed prime\n    ");
            printNum(bnPrimeTest);
            printf("\nyields\n    ");
            printNum(bnExpR);
            printf("   ---   Should be 1\n\n");
        }
        else {
            printf("Fermat test returns false\n\n");
        }
        mpZeroNum(bnExpR);

        // RSA Tests
        bnExpE.m_pValue[0]= (1ULL<<31)|1ULL;
        bool fContinue= mpRSAGen(128, bnExpE, bnExpP, bnExpQ, bnExpM, bnExpD, bnExpO);
        if(fContinue) {
            printf("RSA Key:\n");
            printf("\tE: "); printNum(bnExpE); printf("\n");
            printf("\tP: "); printNum(bnExpP); printf("\n");
            printf("\tQ: "); printNum(bnExpQ); printf("\n");
            printf("\tM: "); printNum(bnExpM); printf("\n");
            printf("\tD: "); printNum(bnExpD); printf("\n");
            printf("\tOrder: "); printNum(bnExpO); printf("\n");
            if(mpTestFermatCondition(g_bnTwo, bnExpP)) {
                printf("\tP passes Fermat condition\n");
            }
            else {
                printf("\tP fails Fermat condition\n");
            }
            if(mpTestFermatCondition(g_bnTwo, bnExpQ)) {
                printf("\tQ passes Fermat condition\n");
            }
            else {
                printf("\tQ fails Fermat condition\n");
            }
            mpZeroNum(bnTest8);
            printf("\tE*D (mod Order)= ");
            mpModMult(bnExpE, bnExpD, bnExpO, bnTest8);
            printNum(bnTest8);
            printf("\n\n");

        }
        else {
            printf("mpRSAGen returns false\n\n");
        }

        if(fContinue) {
            bnTestMsg.m_pValue[0]= 0x2310057ULL;
            fContinue= mpRSAENC(bnTestMsg, bnExpE, bnExpM, bnExpR);
            if(fContinue) {
                printf("RSA Encrypt:\n");
                printf("\tE: "); printNum(bnExpE); printf("\n");
                printf("\tM: "); printNum(bnExpM); printf("\n");
                printf("\tMessage: "); printNum(bnTestMsg); printf("\n");
                printf("\tResult: "); printNum(bnExpR); printf("\n");
                printf("\n");
            }
            else {
                printf("mpRSAENC returns false\n\n");
            }
        }
        if(fContinue) {
            fContinue= mpRSAENC(bnExpR, bnExpD, bnExpM, bnExpT);
            if(fContinue) {
                printf("RSA Decrypt:\n");
                printf("\tD: "); printNum(bnExpD); printf("\n");
                printf("\tM: "); printNum(bnExpM); printf("\n");
                printf("\tMessage: "); printNum(bnExpR); printf("\n");
                printf("\tResult: "); printNum(bnExpT); printf("\n");
                printf("\n");
            }
            else {
                printf("mpRSADEC returns false\n\n");
            }
        }

        // Square test
        mpUMult(bnTest12, bnTest12, bnTest14);
        printf("mpUMult: "); printNum(bnTest12); printf("^2="); 
        printf("= "); printNum(bnTest14); printf("\n"); printf("\n");

        u64 s1= 0xffffffffULL;
        u64 s2= s1*s1;
        printf("%016lx^2= %016lx\n", (long unsigned int) s1, (long unsigned int) s2);

        bnum P(128);
        bnum R(128);
        if(!mpGenPrime(512,P)) {
            printf("Cant generate prime\n");
        }
        else {
            if(mpFermatTest(g_bnTwo,P,R)) {
                printNum(P); printf(" passes fermat test\n");
            }
            else {
                printNum(P); printf(" fails fermat test\n");
            }
        }

        printf("Tests completed\n");
        return 0;
        }
        catch(char* szError) {
            printf("\n\nMain Error! %s.\n",szError);
            return 1;
        }
}


// ----------------------------------------------------------------------------


