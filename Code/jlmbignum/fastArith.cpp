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
        : "%rax", "%rcx", 
          "%eax", "ebx", "%esi", "%rsi", "%rdi", "%rdx");

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

    // %rdx:%rax contains numerator for uDivBy
    asm volatile(
        "movq    $0,%[rem]\n" \
        "\tmovq    %[op1], %%rdx\n" \
        "\tmovq    %[op2], %%rax\n" \
        "\tdivq    %[divisor]\n" \
        "\tmovq    %%rdx,%[rem]\n" \
        "\tmovq    %[outaddress],%%rcx\n" \
        "\tmovq    %%rax,(%%rcx)\n"
        : [rem] "=m"(uRem) 
        : [outaddress] "m" (puQ), [op1] "m" (uDivHi), [op2] "m" (uDivLo), [divisor] "m" (uDivBy)
        : "%rax", "%rcx", "%rdx");

    return uRem;
}


// -----------------------------------------------------------------

