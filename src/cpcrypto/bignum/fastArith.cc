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
#include "common.h"

// -----------------------------------------------------------------

u64 longaddwithcarry(u64* out, u64 op1, u64 op2, u64 carry_in) {
  u64 carry_out = 0ULL;

  asm volatile("\tmovq    %[op1], %%rax\n"
               "\taddq    %[carryin], %%rax\n"
               "\tsetc    %[carryout]\n"
               "\taddq    %[op2], %%rax\n"
               "\tjnc     2f\n"
               "\tmovq    $1, %[carryout]\n"
               ".balign 16\n"
               "2:\n"
               "\tmovq    %[outaddress], %%rcx\n"
               "\tmovq    %%rax, (%%rcx)\n"
               : [carryout] "=m"(carry_out)
               : [outaddress] "m"(out), [op1] "m"(op1), [op2] "m"(op2),
                 [carryin] "m"(carry_in)
               : "%rax", "%rcx");

  return carry_out;
}

u64 longmultiplystep(u64* out, u64 op1, u64 op2, u64 carry_in) {
  u64 carry_out = 0ULL;

  // result of mulq is in %rdx:%rax
  asm volatile("\tmovq    %[op1], %%rax\n"
               "\tmulq    %[op2]\n"
               "\taddq    %[carryin], %%rax\n"
               "\tadcq    $0, %%rdx\n"
               "\tmovq    %%rdx,%[carryout]\n"
               "\tmovq    %[outaddress],%%rcx\n"
               "\tmovq    %%rax,(%%rcx)\n"
               : [carryout] "=m"(carry_out)
               : [outaddress] "m"(out), [op1] "m"(op1), [op2] "m"(op2),
                 [carryin] "m"(carry_in)
               : "%rax", "%rcx", "%rdx");

  return carry_out;
}

const u64 longradixminus1 = 0xffffffffffffffffULL;

u64 longsubstep(u64* out, u64 op1, u64 op2, u64 borrow_in) {
  if (borrow_in == 0) {
    if (op1 >= op2) {
      *out = op1 - op2;
      return 0ULL;
    } else {
      *out = (longradixminus1 - op2) + op1 + 1;
      return 1ULL;
    }
  } else {
    if (op1 > op2) {
      *out = op1 - op2 - 1;
      return 0ULL;
    } else {
      *out = (longradixminus1 - op2) + op1;
      return 1ULL;
    }
  }
}

u64 longdivstep(u64* quotient, u64 div_hi_digit, u64 div_low_digit, u64 divisor) {
  u64 remainder = 0ULL;

  // %rdx:%rax contains numerator
  asm volatile("\tmovq    %[op1], %%rdx\n"
               "\tmovq    %[op2], %%rax\n"
               "\tdivq    %[divisor]\n"
               "\tmovq    %%rdx,%[rem]\n"
               "\tmovq    %[outaddress],%%rcx\n"
               "\tmovq    %%rax,(%%rcx)\n"
               : [rem] "=m"(remainder)
               : [outaddress] "m"(quotient), [op1] "m"(div_hi_digit), 
                 [op2] "m"(div_low_digit), [divisor] "m"(divisor)
               : "%rax", "%rcx", "%rdx");

  return remainder;
}

#define ALLASSEMBLER

//  Function: u64 mpUAddLoop
//      Caller guarentees size_op1>=size_op2, size_result>=size_op1
u64 mpUAddLoop(int size_op1, u64* op1, int size_op2, u64* op2, u64* result) {
  u64 carry = 0;

#ifdef ALLASSEMBLER
  asm volatile(
      // esi is j
      // rbx is op1
      // rcx is op2
      // rdx is result
      // carry is in r12
      "xorl     %%esi, %%esi\n"
      "\tmovq   %[result], %%rdx\n"
      "\tmovq   %[op1], %%rbx\n"
      "\tmovq   %[op2], %%rcx\n"
      "\txorq   %%r12, %%r12\n"
      ".balign 16\n"
      "1:\n"
      "\tcmpl   %%esi, %[size_op2]\n"
      "\tjle    4f\n"
      "\tmovq   (%%rbx), %%rax\n"
      "\taddq   %%r12, %%rax\n"
      "\txorq   %%r12, %%r12\n"
      "jnc      2f\n"
      "\tmovq   $1, %%r12\n"
      ".balign 16\n"
      "2:\n"
      "\taddq   (%%rcx), %%rax\n"
      "jnc      3f\n"
      "\tmovq   $1, %%r12\n"
      ".balign 16\n"
      "3:\n"
      "\tmovq   %%rax, (%%rdx)\n"
      "\taddq   $8, %%rbx\n"
      "\taddq   $8, %%rcx\n"
      "\taddq   $8, %%rdx\n"
      "\tincl   %%esi\n"
      "\tjmp    1b\n"
      ".balign 16\n"
      "4:\n"
      "\tcmpl   %%esi, %[size_op1]\n"
      "\tjle    6f\n"
      "\tmovq   (%%rbx), %%rax\n"
      "\taddq   %%r12, %%rax\n"
      "\txorq   %%r12, %%r12\n"
      "jnc      5f\n"
      "\tmovq   $1, %%r12\n"
      ".balign 16\n"
      "5:\n"
      "\tmovq   %%rax, (%%rdx)\n"
      "\taddq   $8, %%rbx\n"
      "\taddq   $8, %%rdx\n"
      "\tincl   %%esi\n"
      "\tjmp    4b\n"
      ".balign 16\n"
      "6:\n"
      "\tmovq  %%r12, %[carry]\n"
      : [carry] "=m"(carry)
      : [result] "m"(result), [size_op1] "m"(size_op1), [op1] "m"(op1), 
        [size_op2] "m"(size_op2), [op2] "m"(op2)
      : "%rax", "%rbx", "%rcx", "%rdx", "%esi", "%r12");
#else
  int j;

  for (j = 0; j < size_op2; j++) {
    carry = longaddwithcarry(result, *op1, *op2, carry);
    op1++;
    op2++;
    result++;
  }
  for (j = size_op2; j < size_op1; j++) {
    carry = longaddwithcarry(result, *op1, 0ULL, carry);
    op1++;
    op2++;
    result++;
  }
#endif
  return carry;
}

//  Function: u64 mpUSubLoop
u64 mpUSubLoop(int size_op1, u64* op1, int size_op2, u64* op2, u64* result, 
               u64 borrow_digit)
    //      Caller guarentees size_op1>=size_op2, size_result>=size_op1
    {
  int j;
  for (j = 0; j < size_op2; j++) {
    borrow_digit = longsubstep(result, *op1, *op2, borrow_digit);
    op1++;
    op2++;
    result++;
  }

  for (j = size_op2; j < size_op1; j++) {
    borrow_digit = longsubstep(result, *op1, 0ULL, borrow_digit);
    op1++;
    op2++;
    result++;
  }
  return 0ULL;
}

/*inline*/
void mpMultiplyStep(u64* hi_result, u64* lo_result, u64 op1, u64 op2, u64 carry1,
                    u64 carry2)
    // (*hi_result, *lo_result)= op1*op2 + carry1 + carry2
    {
#ifdef ALLASSEMBLER
  //  mulq    op:     rdx:rax= rax*op
  asm volatile("\tmovq    %[op1], %%rax\n"
               "\tmulq    %[op2]\n"
               "\taddq    %[uC], %%rax\n"
               "\tadcq    $0, %%rdx\n"
               "\taddq    %[uA], %%rax\n"
               "\tadcq    $0, %%rdx\n"
               "\tmovq    %[result], %%rcx\n"
               "\tmovq    %%rax, (%%rcx)\n"
               "\tmovq    %[pC], %%rcx\n"
               "\tmovq    %%rdx, (%%rcx)\n" ::[pC] "m"(hi_result),
               [result] "m"(lo_result), [op1] "m"(op1), [op2] "m"(op2),
               [uA] "m"(carry1), [uC] "m"(carry2)
               : "%rax", "%rcx", "%rdx");
#else
  u64 mult_carry;
  u64 add_carry;
  u64 result_digit;

  mult_carry = longmultiplystep(&result_digit, op1, op2, carry2);
  add_carry = longaddwithcarry(lo_result, result_digit, carry1, 0ULL);
  *hi_result = mult_carry + add_carry;  // should never have further carry
#endif
}

//  Function: bool mpUMultByLoop
u64 mpUMultByLoop(int size_op1, u64* op1, u64 multiply_digit) {
  u64 carry = 0ULL;
#ifdef ALLASSEMBLER
  u64 usize_op1 = (u64)size_op1;
  //  mulq    op:     rdx:rax= rax*op
  //  r8:  i
  //  r9: multiply_digit
  //  rbx: op1
  //  r13: carry
  //  cmp a,b:  jge succeeds if b>=a
  asm volatile("\tmovq    %[op1], %%rbx\n"
               "\txorq    %%r8, %%r8\n"
               "\tmovq    %[multiply_digit], %%r9\n"
               "\txorq    %%r13, %%r13\n"
               ".balign 16\n"
               "1:\n"
               "\tcmpq    %%r8, %[usize_op1]\n"
               "\tjle     2f\n"
               "\tmovq    (%%rbx, %%r8, 0x8), %%rax\n"
               "\tmulq    %%r9\n"
               "\taddq    %%r13, %%rax\n"
               "\tadcq    $0, %%rdx\n"
               "\tmovq    %%rax,(%%rbx, %%r8, 0x8)\n"
               "\tmovq    %%rdx, %%r13\n"
               "\taddq    $1, %%r8\n"
               "\tjmp     1b\n"
               ".balign 16\n"
               "2:\n"
               "\tmovq    %%r13, %[uC]\n" 
               ::[op1] "m"(op1), [multiply_digit] "m"(multiply_digit), 
                 [usize_op1] "m"(usize_op1), [uC] "m"(carry)
               : "%rax", "%rbx", "%rdx", "%r8", "%r9", "%r13");
#else
  int i;
  for (i = 0; i < size_op1; i++) {
    carry = longmultiplystep(&op1[i], op1[i], multiply_digit, carry);
  }
#endif
  return carry;
}

//  Function: bool mpUMultLoop
//      Caller guarentees size_op1>=size_op2, size_result>=size_op1+size_op2
void mpUMultLoop(int isize_op1, u64* op1, int isize_op2, u64* op2, u64* result) {
  i64 size_op1 = (i64)isize_op1;
  i64 size_op2 = (i64)isize_op2;

#ifdef ALLASSEMBLER
  //  mulq    op:     rdx:rax= rax*op
  //  r8:  i
  //  r9:  j
  //  r12: i+j
  //  rbx: op1
  //  rcx: op2
  //  r14: result
  //  r13: carry
  //  cmp a,b:  jge succeeds if b>=a
  asm volatile(
      "\tmovq    %[op1], %%rbx\n"
      "\tmovq    %[op2], %%rcx\n"
      "\tmovq    %[result], %%r14\n"
      "\txorq    %%r8, %%r8\n"
      ".balign 16\n"
      "1:\n"
      "\tcmpq    %%r8, %[size_op1]\n"
      "\tjle     4f\n"
      "\txorq    %%r9, %%r9\n"
      "\txorq    %%r13, %%r13\n"
      "\tmovq    %%r8, %%r12\n"
      ".balign 16\n"
      "2:\n"
      "\tcmpq    %%r9, %[size_op2]\n"
      "\tjle     3f\n"
      "\tmovq    (%%rbx, %%r8, 0x8), %%rax\n"
      "\tmulq    (%%rcx, %%r9, 0x8)\n"
      "\taddq    %%r13, %%rax\n"
      "\tadcq    $0, %%rdx\n"
      "\taddq    (%%r14, %%r12, 0x8), %%rax\n"
      "\tadcq    $0, %%rdx\n"
      "\tmovq    %%rax, (%%r14, %%r12, 0x8)\n"
      "\tmovq    %%rdx, %%r13\n"
      "\taddq    $1, %%r9\n"
      "\taddq    $1, %%r12\n"
      "\tjmp     2b\n"
      ".balign 16\n"
      "3:\n"
      "\tmovq    %%r13, (%%r14, %%r12, 0x8)\n"
      "\taddq    $1, %%r8\n"
      "\tjmp     1b\n"
      "4:\n"
      :
      : [size_op1] "m"(size_op1), [op1] "m"(op1), [size_op2] "m"(size_op2), [op2] "m"(op2), [result] "m"(result)
      : "%rax", "rbx", "%rcx", "%rdx", "%r8", "%r9", "%r12", "%r13", "%r14");
#else
  int i, j;
  u64 carry = 0ULL;

  for (i = 0; i < size_op1; i++) {
    carry = 0ULL;
    for (j = 0; j < size_op2; j++)
      mpMultiplyStep(&carry, &result[i + j], op1[i], op2[j], result[i + j], carry);
    result[i + j] = carry;
  }
#endif
  return;
}

//  Function: bool mpSingleUDivLoop
bool mpSingleUDivLoop(int size_op1, u64* op1, u64 divisor_digit, u64* result) {
  int i;
  u64 remainder = 0ULL;
  u64 quotient_digit = 0ULL;

  for (i = (size_op1 - 1); i >= 0; i--) 
    remainder = longdivstep(&quotient_digit, remainder, op1[i], divisor_digit);

  *result = remainder;
  return true;
}

// -----------------------------------------------------------------
