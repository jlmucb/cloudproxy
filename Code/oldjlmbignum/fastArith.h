//  File: fastArith.h
//	Ast arithmetic for jmbignum
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

#include "jlmTypes.h"

u64 longaddwithcarry(u64* puOut, u64 uIn1, u64 uIn2, u64 uCarryIn);
u64 longmultiplystep(u64* puOut, u64 uIn1, u64 uIn2, u64 uCarryIn);
u64 longsubstep(u64* puOut, u64 uIn1, u64 uIn2, u64 uBorrowIn);
u64 longdivstep(u64* puQ, u64 uDivHi, u64 uDivLo, u64 uDivBy);


// -----------------------------------------------------------------



