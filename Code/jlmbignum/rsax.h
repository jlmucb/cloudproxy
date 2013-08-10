//  File: rsax.h
//      Assembly arithmetic for bignum arithmetic
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


// This file is the interface definitions for the rsax library 
// downloaded from Intel.com on 23 July 2013. and is subject to 
// the following license:
// 
// Copyright (c) 2012, Intel Corporation
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the
// distribution.
// 
// Neither the name of the Intel Corporation nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
// 
// 
// THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION ""AS IS"" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


// -----------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"


// Common Data Structure:
struct MOD_EXP_1024_DATA {
    u64       R[16];     // 2^1024 mod m
    u64       R2[16];    // 2^2048 mod m
    u64       M[16];     // m
    u64       m_1[1];    // (-1/m) mod 2^64
};


extern "C" void rsax_mod_exp_1024(
                    u64 *result, // 1024 bits, 16 qwords
                    u64 *g,      // 1024 bits, 16 qwords
                    u64 *exp,    // 1024 bits, 16 qwords
                    MOD_EXP_1024_DATA *data);


/*
bool pre_compute_data(u64 *m, MOD_EXP_1024_DATA *data)
{
    int         i;
    large_int   two_2048, two_1024, two_64;
    large_int   tmp;
    large_int   _m(16, m);

    // 2^2048
    two_2048= 1;
    two_2048<<= 2048;

    //2^1024
    two_1024= 1;
    two_1024<<= 1024;

    //2^64
    two_64= 1;
    two_64<<= 64;

    // Code is optimised and verified for 1024-bit modulus.
    if(0==(m[15] & 0x8000000000000000)) {
        fprintf(g_logFile, "Invalid modulus: %I64u\n", m[7]);
        return false;
    }
    // Odd modulus required for Montgomery Reduction
    if(0==(m[0] & 0x1)) { 
        fprintf(g_logFile, "Invalid modulus: %I64u\n", m[0]);
        return false;
    }

    // R = 2^1024 mod m
    // In Montgomery space, 1 is represented as 1*R = R. 
    // We store g^0 = 1 as R in Montgomery space.
    tmp= two_1024.Modulo(_m);
    tmp.extract(16, &data->R[0]);

    // R2= 2^2048 mod m
    // we need R2 for converting g into the Montgomery space:
    // MM(R2, g) = g*R
    tmp= two_2048.Modulo(_m);
    tmp.extract(16, &data->R2[0]);

    // insert modulus into the data structure
    for(i=0; i<16; i++)
        data->M[i]= m[i];

    // Precompute k1, a 64b number = (-m^-1 ) mod 2^64; k1 should be non-negative.
    tmp= (_m.Times(-1)).InverseMod(two_64);
    tmp.extract(1, &data->m_1[0]);
    return true;
}
*/


// -----------------------------------------------------------------


