//  File: fastArith.cpp
//  Description: fast arithmetic for jmbignum
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
    u64 uCarryOut= 0ULL;

    asm volatile(
        "\tmovq    %[op1], %%rax\n" \
        "\taddq    %[carryin], %%rax\n" \
        "\tsetc    %[carryout]\n" \
        "\taddq    %[op2], %%rax\n" \
        "\tjnc     2f\n" \
        "\tmovq    $1, %[carryout]\n" \
        ".balign 16\n" \
        "2:\n" \
        "\tmovq    %[outaddress], %%rcx\n" \
        "\tmovq    %%rax, (%%rcx)\n" 
        : [carryout] "=m"(uCarryOut) 
        : [outaddress] "m" (puOut), [op1] "m" (uIn1), [op2] "m" (uIn2), [carryin] "m" (uCarryIn)
        : "%rax", "%rcx");

    return uCarryOut;
}


u64 longmultiplystep(u64* puOut, u64 uIn1, u64 uIn2, u64 uCarryIn)

{
    u64 uCarryOut= 0ULL;

    // result of mulq is in %rdx:%rax
    asm volatile(
        "\tmovq    %[op1], %%rax\n" \
        "\tmulq    %[op2]\n" \
        "\taddq    %[carryin], %%rax\n" \
        "\tadcq    $0, %%rdx\n" \
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
    u64 uRem= 0ULL;

    // %rdx:%rax contains numerator
    asm volatile(
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
        "xorl     %%esi, %%esi\n" \
        "\tmovq   %[pR], %%rdx\n"\
        "\tmovq   %[pA], %%rbx\n" \
        "\tmovq   %[pB], %%rcx\n" \
        "\txorq   %%r12, %%r12\n" \
        ".balign 16\n"\
        "1:\n" \
        "\tcmpl   %%esi, %[lB]\n"\
        "\tjle    4f\n" \
        "\tmovq   (%%rbx), %%rax\n" \
        "\taddq   %%r12, %%rax\n"\
        "\txorq   %%r12, %%r12\n" \
        "jnc      2f\n"\
        "\tmovq   $1, %%r12\n"\
        ".balign 16\n"\
        "2:\n" \
        "\taddq   (%%rcx), %%rax\n"\
        "jnc      3f\n"\
        "\tmovq   $1, %%r12\n"\
        ".balign 16\n"\
        "3:\n"\
        "\tmovq   %%rax, (%%rdx)\n"\
        "\taddq   $8, %%rbx\n"\
        "\taddq   $8, %%rcx\n"\
        "\taddq   $8, %%rdx\n"\
        "\tincl   %%esi\n"\
        "\tjmp    1b\n" \
        ".balign 16\n"\
        "4:\n" \
        "\tcmpl   %%esi, %[lA]\n" \
        "\tjle    6f\n" \
        "\tmovq   (%%rbx), %%rax\n"\
        "\taddq   %%r12, %%rax\n"\
        "\txorq   %%r12, %%r12\n"\
        "jnc      5f\n"\
        "\tmovq   $1, %%r12\n"\
        ".balign 16\n"\
        "5:\n" \
        "\tmovq   %%rax, (%%rdx)\n"\
        "\taddq   $8, %%rbx\n"\
        "\taddq   $8, %%rdx\n"\
        "\tincl   %%esi\n"\
        "\tjmp    4b\n" \
        ".balign 16\n"\
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


/*inline*/ 
void mpMultiplyStep(u64* pCarry, u64* pResult, u64 uIn1, u64 uIn2, u64 uToAdd, u64 uCarry)
// (*pCarry, *pResult)= uIn1*uIn2 + uToAdd + uCarry
{
#ifdef ALLASSEMBLER
    //  mulq    op:     rdx:rax= rax*op
    asm volatile(
        "\tmovq    %[op1], %%rax\n" \
        "\tmulq    %[op2]\n" \
        "\taddq    %[uC], %%rax\n" \
        "\tadcq    $0, %%rdx\n" \
        "\taddq    %[uA], %%rax\n" \
        "\tadcq    $0, %%rdx\n" \
        "\tmovq    %[pR], %%rcx\n" \
        "\tmovq    %%rax, (%%rcx)\n" \
        "\tmovq    %[pC], %%rcx\n" \
        "\tmovq    %%rdx, (%%rcx)\n"
        :: [pC] "m" (pCarry), [pR] "m" (pResult), [op1] "m" (uIn1), [op2] "m" (uIn2), 
           [uA] "m" (uToAdd), [uC] "m" (uCarry)
        :  "%rax", "%rcx", "%rdx");
#else
    u64 mCarry;
    u64 aCarry;
    u64 mResult;

    mCarry= longmultiplystep(&mResult, uIn1, uIn2, uCarry);
    aCarry= longaddwithcarry(pResult, mResult, uToAdd, 0ULL);
    *pCarry= mCarry+aCarry;   // should never have further carry
#endif
}


//  Function: bool mpUMultByLoop
u64 mpUMultByLoop(int lA, u64* pA, u64 uB)
{
    u64     uCarry= 0ULL;
#ifdef ALLASSEMBLER
    u64     ulA=  (u64)lA;
    //  mulq    op:     rdx:rax= rax*op
    //  r8:  i
    //  r9: uB 
    //  rbx: pA
    //  r13: uCarry
    //  cmp a,b:  jge succeeds if b>=a
    asm volatile(
        "\tmovq    %[pA], %%rbx\n"\
        "\txorq    %%r8, %%r8\n"\
        "\tmovq    %[uB], %%r9\n"\
        "\txorq    %%r13, %%r13\n"\
        ".balign 16\n"\
        "1:\n"\
        "\tcmpq    %%r8, %[ulA]\n"\
        "\tjle     2f\n"\
        "\tmovq    (%%rbx, %%r8, 0x8), %%rax\n" \
        "\tmulq    %%r9\n" \
        "\taddq    %%r13, %%rax\n" \
        "\tadcq    $0, %%rdx\n" \
        "\tmovq    %%rax,(%%rbx, %%r8, 0x8)\n" \
        "\tmovq    %%rdx, %%r13\n" \
        "\taddq    $1, %%r8\n"\
        "\tjmp     1b\n"\
        ".balign 16\n"\
        "2:\n"\
        "\tmovq    %%r13, %[uC]\n"\
        :: [pA] "m" (pA), [uB] "m" (uB), [ulA] "m" (ulA), [uC] "m" (uCarry)
        :  "%rax", "%rbx", "%rdx", "%r8", "%r9", "%r13");
#else
    int     i;
    for(i=0; i<lA; i++) {
        uCarry= longmultiplystep(&pA[i], pA[i], uB, uCarry);
    }
#endif
    return uCarry;
}


//  Function: bool mpUMultLoop
//      Caller guarentees lA>=lB, lR>=lA+lB
void mpUMultLoop(int ilA, u64* pA, int ilB, u64* pB, u64* pR)
{
    i64 lA= (i64)ilA;
    i64 lB= (i64)ilB;

#ifdef ALLASSEMBLER
    //  mulq    op:     rdx:rax= rax*op
    //  r8:  i
    //  r9:  j
    //  r12: i+j
    //  rbx: pA
    //  rcx: pB
    //  r14: pR
    //  r13: uCarry
    //  cmp a,b:  jge succeeds if b>=a
    asm volatile(
        "\tmovq    %[pA], %%rbx\n"\
        "\tmovq    %[pB], %%rcx\n"\
        "\tmovq    %[pR], %%r14\n"\
        "\txorq    %%r8, %%r8\n"\
        ".balign 16\n"\
        "1:\n"\
        "\tcmpq    %%r8, %[lA]\n"\
        "\tjle     4f\n"\
        "\txorq    %%r9, %%r9\n"\
        "\txorq    %%r13, %%r13\n"\
        "\tmovq    %%r8, %%r12\n"\
        ".balign 16\n"\
        "2:\n"\
        "\tcmpq    %%r9, %[lB]\n"\
        "\tjle     3f\n"\
        "\tmovq    (%%rbx, %%r8, 0x8), %%rax\n"\
        "\tmulq    (%%rcx, %%r9, 0x8)\n"\
        "\taddq    %%r13, %%rax\n"\
        "\tadcq    $0, %%rdx\n"\
        "\taddq    (%%r14, %%r12, 0x8), %%rax\n"\
        "\tadcq    $0, %%rdx\n"\
        "\tmovq    %%rax, (%%r14, %%r12, 0x8)\n"\
        "\tmovq    %%rdx, %%r13\n"\
        "\taddq    $1, %%r9\n"\
        "\taddq    $1, %%r12\n"\
        "\tjmp     2b\n"\
        ".balign 16\n"\
        "3:\n"\
        "\tmovq    %%r13, (%%r14, %%r12, 0x8)\n"\
        "\taddq    $1, %%r8\n"\
        "\tjmp     1b\n"\
        "4:\n"
        :
        : [lA] "m" (lA), [pA] "m" (pA), [lB] "m" (lB), [pB] "m" (pB), [pR] "m" (pR)
        : "%rax", "rbx", "%rcx", "%rdx", "%r8", "%r9", "%r12", "%r13", "%r14");
#else
    int     i, j;
    u64     uCarry= 0ULL;

    for(i=0; i<lA; i++) {
        uCarry= 0ULL;
        for(j=0; j<lB; j++)
            mpMultiplyStep(&uCarry, &pR[i+j], pA[i], pB[j], pR[i+j], uCarry);
        pR[i+j]= uCarry;
    }
#endif
    return;
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

