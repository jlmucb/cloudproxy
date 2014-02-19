//
//  File: common.h
//  Description: commonly used data types and definitions for crypto
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
//  Some contributions may be (c) Intel Corporation
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//    Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the disclaimer below.
//    Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the disclaimer below in the
//      documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// ---------------------------------------------------------------------------------

#ifndef _COMMON__H
#define _COMMON__H
typedef long long int i64;
typedef long long unsigned u64;
typedef int i32;
typedef unsigned u32;
typedef short int i16;
typedef short unsigned u16;
typedef char i8;
typedef unsigned char u8;
#ifndef byte
typedef unsigned char byte;
#endif

#define NBITSINBYTE 8

#ifndef NULL
#define NULL 0
#endif

#ifndef UNUSEDVAR
// satisfy the compiler and mark a variable as unused
#define UNUSEDVAR(x) \
  if (x)             \
    ;
#endif

#endif  // _COMMON__H

// -------------------------------------------------------------------------------------
