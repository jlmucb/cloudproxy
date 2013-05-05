//  File: fastArith.cpp
//	fast arithmetic for jmbignum
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


#include "fastArith.h"
#include "jlmTypes.h"
#include "stdio.h"


// -----------------------------------------------------------------


u64 longaddwithcarry(u64* puOut, u64 uIn1, u64 uIn2, u64 uCarryIn)

{
    u64 uCarryOut;

    asm volatile(
        "movq    $0, %[carryout]\n" \
        "\tmovq    %[op1], %%rax\n" \
        "\taddq    %[carryin], %%rax\n" \
        "\tjnc     1f\n" \
        "\tmovq    $1, %[carryout]\n" \
        "1:\n" \
        "\taddq    %[op2], %%rax\n" \
        "\tjnc     2f\n" \
        "\tmovq    $1, %[carryout]\n" \
        "2:\n" \
        "\tmovq    %[outaddress], %%rcx\n" \
        "\tmovq    %%rax, (%%rcx)\n" 
        : [carryout] "=m"(uCarryOut) 
        : [outaddress] "m" (puOut), [op1] "m" (uIn1), [op2] "m" (uIn2), [carryin] "m" (uCarryIn)
        : "%rax", "%rcx");
        /*, "%eax", "ebx", "%esi", "%rsi", "%rdi", "%rdx"); --- remove this */

    return uCarryOut;
}


u64 longmultiplystep(u64* puOut, u64 uIn1, u64 uIn2, u64 uCarryIn)

{
    u64 uCarryOut;

    // result of mulq is in %rdx:%rax
    asm volatile(
        "\tmovq    $0, %[carryout]\n" \
        "\tmovq    %[op1], %%rax\n" \
        "\tmulq    %[op2]\n" \
        "\taddq    %[carryin], %%rax\n" \
        "\tjnc     1f\n" \
        "\taddq    $1, %%rdx\n" \
        "1:\n" \
        "\tmovq    %%rdx,%[carryout]\n" \
        "\tmovq    %[outaddress],%%rcx\n" \
        "\tmovq    %%rax,(%%rcx)\n" 
        : [carryout] "=m"(uCarryOut) 
        : [outaddress] "m" (puOut), [op1] "m" (uIn1), [op2] "m" (uIn2), [carryin] "m" (uCarryIn)
        : "%rax", "%rcx", "%rdx");

    return uCarryOut;
}


const u64 longradixminus1= 0xffffffffffffffffULL;


u64 longsubstep(u64* puOut, u64 uIn1, u64 uIn2, u64 uBorrowIn)
{

    if(uBorrowIn==0) {
        if(uIn1 >= uIn2) {
            *puOut= uIn1-uIn2;
            return 0ULL;
        }
        else {
            *puOut= (longradixminus1-uIn2)+uIn1+1;
            return 1ULL;
        }
    }
    else {
        if(uIn1 > uIn2) {
            *puOut= uIn1-uIn2-1;
            return 0ULL;
        }
        else {
            *puOut= (longradixminus1-uIn2)+uIn1;
            return 1ULL;
        }
    }
}


u64 longdivstep(u64* puQ, u64 uDivHi, u64 uDivLo, u64 uDivBy)
{
    u64 uRem;

    // %rdx:%rax contains numerator
    asm volatile(
        "movq    $0,%[rem]\n" \
        "\tmovq    %[op1], %%rdx\n" \
        "\tmovq    %[op2], %%rax\n" \
        "\tdivq    %[divisor]\n" \
        "\tmovq    %%rdx,%[rem]\n" \
        "\tmovq    %[outaddress],%%rcx\n" \
        "\tmovq    %%rax,(%%rcx)\n"
        : [rem] "=m"(uRem) 
        : [outaddress] "m" (puQ), [op1] "m" (uDivHi), [op2] "m" (uDivLo), 
          [divisor] "m" (uDivBy)
        : "%rax", "%rcx", "%rdx");

    return uRem;
}


#define ALLASSEMBLER

//  Function: u64 mpUAddLoop
//      Caller guarentees lA>=lB, lR>=lA
u64 mpUAddLoop(int lA, u64* pA, int lB, u64* pB, u64* pR)
{
    u64     uCarry= 0;

#ifdef ALLASSEMBLER
    asm volatile(
        // esi is j
        // rbx is pA
        // rcx is pB
        // rdx is pR
        // carry is in r12
        "movl     $0, %%esi\n" \
        "\tmovq   %[pR], %%rdx\n"\
        "\tmovq   %[pA], %%rbx\n" \
        "\tmovq   %[pB], %%rcx\n" \
        "\tmovq   $0, %%r12\n" \
        "1:\n" \
        "\tcmpl   %%esi, %[lB]\n"\
        "\tjle    4f\n" \
        "\tmovq   (%%rbx), %%rax\n" \
        "\tclc\n" \
        "\taddq   %%r12, %%rax\n"\
        "\tmovq   $0, %%r12\n" \
        "jnc      2f\n"\
        "\tmovq   $1, %%r12\n"\
        "2:\n" \
        "\tclc\n" \
        "\taddq   (%%rcx), %%rax\n"\
        "jnc      3f\n"\
        "\tmovq   $1, %%r12\n"\
        "3:\n"\
        "\tmovq   %%rax, (%%rdx)\n"\
        "\taddq   $8, %%rbx\n"\
        "\taddq   $8, %%rcx\n"\
        "\taddq   $8, %%rdx\n"\
        "\tincl   %%esi\n"\
        "\tjmp    1b\n" \
        "4:\n" \
        "\tcmpl   %%esi, %[lA]\n" \
        "\tjle    6f\n" \
        "\tmovq   (%%rbx), %%rax\n"\
        "\tclc\n" \
        "\taddq   %%r12, %%rax\n"\
        "\tmovq   $0, %%r12\n"\
        "jnc      5f\n"\
        "\tmovq   $1, %%r12\n"\
        "5:\n" \
        "\tmovq   %%rax, (%%rdx)\n"\
        "\taddq   $8, %%rbx\n"\
        "\taddq   $8, %%rdx\n"\
        "\tincl   %%esi\n"\
        "\tjmp    4b\n" \
        "6:\n" \
        "\tmovq  %%r12, %[uCarry]\n"
        : [uCarry] "=m"(uCarry) 
        : [pR] "m" (pR), [lA] "m" (lA), [pA] "m" (pA), [lB] "m" (lB), [pB] "m" (pB)
        : "%rax", "%rbx", "%rcx", "%rdx", "%esi", "%r12");
#else
    int     j;

    for(j=0; j<lB; j++) {
        uCarry= longaddwithcarry(pR, *pA, *pB, uCarry);
        pA++;
        pB++;
        pR++;
    }
    for(j=lB; j<lA; j++) {
        uCarry= longaddwithcarry(pR, *pA, 0ULL, uCarry);
        pA++;
        pB++;
        pR++;
    }
#endif
    return uCarry;
}


//  Function: u64 mpUSubLoop
u64 mpUSubLoop(int lA, u64* pA, int lB, u64* pB, u64* pR, u64 uBorrow)
//      Caller guarentees lA>=lB, lR>=lA
{
    int     j;
    for(j=0; j<lB; j++) {
        uBorrow= longsubstep(pR, *pA, *pB, uBorrow);
        pA++;
        pB++;
        pR++;
    }

    for(j=lB; j<lA; j++) {
        uBorrow= longsubstep(pR, *pA, 0ULL, uBorrow);
        pA++;
        pB++;
        pR++;
    }
    return 0ULL;
}


inline void mpMultiplyStep(u64* pCarry, u64* pResult, u64 uIn1, u64 uIn2, u64 uToAdd, u64 uCarry)
// (*pCarry, *pResult)= uIn1*uIn2 + uToAdd + uCarry
{
    u64 mCarry;
    u64 aCarry;
    u64 mResult;

    mCarry= longmultiplystep(&mResult, uIn1, uIn2, uCarry);
    aCarry= longaddwithcarry(pResult, mResult, uToAdd, 0ULL);

    *pCarry= mCarry+aCarry;   // should never have further carry
}


//  Function: bool mpUMultByLoop
u64 mpUMultByLoop(int lA, u64* pA, u64 uB)
{
    u64     uCarry= 0ULL;
    int     i;

    for(i=0; i<lA; i++) {
	uCarry= longmultiplystep(&pA[i], pA[i], uB, uCarry);
    }
    return uCarry;
}


//  Function: bool mpUMultLoop
//      Caller guarentees lA>=lB, lR>=lA+lB
u64 mpUMultLoop(int lA, u64* pA, int lB, u64* pB, u64* pR)
{
    u64     uCarry= 0ULL;
    int     i, j;

    for(i=0; i<lA; i++) {
        uCarry= 0ULL;
        for(j=0; j<lB; j++)
            mpMultiplyStep(&uCarry, &pR[i+j], pA[i], pB[j], pR[i+j], uCarry);
        pR[i+j]= uCarry;
    }

    return uCarry;
}


//  Function: bool mpSingleUDivLoop
bool mpSingleUDivLoop(int lA, u64* pA, u64 uB, u64* pR)
{
    int     i;
    u64     uRem= 0ULL;
    u64     uOut= 0ULL;

    for(i=(lA-1); i>=0; i--)
        uRem= longdivstep(&uOut, uRem, pA[i], uB);

    *pR=  uRem;
    return true;
}


// -----------------------------------------------------------------


