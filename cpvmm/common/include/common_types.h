/****************************************************************************
* Copyright (c) 2013 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
****************************************************************************/

#ifndef _COMMON_TYPES_H_
#define _COMMON_TYPES_H_

#define MAX_CPUS       80 

#define TOTAL_INT_VECTORS	256 // vectors in the IDT

#define MAX_INSTRUCTION_LENGTH 15

// Num/Len of 64-bit array requred to represent
// the bitmap vectors of max count n (n >= 1).
#define NUM_OF_64BIT_ARRAY(n)  (((n) + 63 ) >> 6)

#define CPU_BITMAP_MAX	NUM_OF_64BIT_ARRAY(MAX_CPUS)

#ifdef _WIN64
#define VOID_RETURN     void
#define DATA_TYPE       UINT64
#define UINT32_RETURN   UINT32
#else
#define VOID_RETURN     void __cdecl
#define DATA_TYPE       UINT32
#define UINT32_RETURN   UINT32 __cdecl
#endif

#define MSR_LOW_FIRST   0
#define MSR_LOW_LAST    0x1FFF
#define MSR_HIGH_FIRST  0xC0000000
#define MSR_HIGH_LAST   0xC0001FFF

// used for CPUID leaf 0x3.
// if the signature is matched, then eVmm is running.
#define EVMM_RUNNING_SIGNATURE_CORP 0x43544E49   //"INTC", edx
#define EVMM_RUNNING_SIGNATURE_VMM  0x4D4D5645   //"EVMM", ecx

#endif
