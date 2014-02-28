//  File: fastArith.h
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

// -----------------------------------------------------------------

#include "common.h"

u64 longaddwithcarry(u64* out, u64 op1, u64 op2, u64 carry_in);
u64 longmultiplystep(u64* out, u64 op1, u64 op2, u64 carry_in);
u64 longsubstep(u64* out, u64 op1, u64 op2, u64 borrow_digit);
u64 longdivstep(u64* quotient, u64 hi_digit, u64 low_digit, 
                u64 divisor);

u64 mpUAddLoop(i32 size_op1, u64* op1, i32 size_op2, u64* op2, 
               u64* result);
u64 mpUSubLoop(i32 size_op1, u64* op1, i32 size_op2, u64* op2, 
               u64* result, u64 borrow_digit);
void mpUMultLoop(i32 size_op1, u64* op1, i32 size_op2, u64* op2, 
                 u64* result);
u64 mpUMultByLoop(i32 size_op1, u64* op1, u64 uB);
bool mpSingleUDivLoop(i32 size_op1, u64* op1, u64 uB, u64* result);

// -----------------------------------------------------------------
