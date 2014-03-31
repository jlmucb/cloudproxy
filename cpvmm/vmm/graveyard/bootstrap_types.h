/*
 * bootstrap_types.h:  defines size-based types for 32b builds
 *
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __BOOTSTRAP_TYPES_H__
#define __BOOTSTRAP_TYPES_H__

#define NULL ((void*)0)

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef long long unsigned uint64_t;

typedef int                 bool;
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef long long unsigned  u64;

typedef signed short        s16;

typedef unsigned char       u_char;

typedef unsigned int        u_int;

typedef unsigned char       u_int8_t;
typedef unsigned short      u_int16_t;
typedef unsigned int        u_int32_t;

// typedef unsigned long       size_t;

#ifndef false
#define false 0
#define true 1
#endif

#define BYTES_PER_LONG 4

#if __GNUC__ > 3
#define offsetof(type, field) __builtin_offsetof(type, field)
#else
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#endif 

