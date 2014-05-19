/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UVMM_COMMON_CRT_H_
#define _UVMM_COMMON_CRT_H_

#include "vmm_defs.h"


// Subset of CRT-like routines to be used in VMM and loader environments

void *  CDECL vmm_memset(void *dest, int filler, size_t count);
void *  CDECL vmm_memcpy(void *dest, const void* src, size_t count);
void *  CDECL vmm_memmove(void *dest, const void* src, int count);
void *  CDECL vmm_lock_memcpy(void *dest, const void* src, size_t count);
size_t  CDECL vmm_strlen(const char* string);
char*   CDECL vmm_strcpy(char* dst, const char* src);
char*   CDECL vmm_strcpy_s(char* dst, size_t dst_length, const char* src);
int     CDECL vmm_strcmp(const char* string1, const char* string2);
void    CDECL vmm_memcpy_assuming_mmio(UINT8 *dst, UINT8 *src, INT32 count);
int CDECL vmm_memcmp(const void* mem1, const void* mem2, size_t count);

#define vmm_zeromem(dest_, count_) vmm_memset(dest_, 0, count_);

// sprintf_s() - secure sprintf. Includes size of input buffer


//
// Format specification
//
//  Types:
//      %X - hex uppercase unsigned integer
//      %x - hex lowercase unsigned integer
//      %P - hex uppercase unsigned integer, 32bit on x86 and 64bit on em64t
//           default width - 10 chars, starting with '0x' prefix and including
//           leading zeroes
//      %p - hex lowercase unsigned integer, 32bit on x86 and 64bit on em64t
//           default width - 10 chars, starting with '0x' prefix and including
//           leading zeroes
//      %u - unsigned decimal
//      %d - signed decimal
//      %i - signed decimal
//      %s - ascii string
//      %c - ascii char
//      %g - VMM_GUID*
//      %t - VMM_TIME*
//      %% - %
//
//  Width and flags:
//      '-' - left justify
//      '+' - in numbers: print '+' sign for positives
//      ' ' - fill extra width with spaces
//      ',' - print ',' each 3 digits in numbers
//      '#' - prefix hex numbers with '0x' and fill extra width with 0
//              ex: "%#6x" for "0xf" will result in 0x000f
//      'L'
//      'l' - 64bit integer, ex: "%lx"
//      'I' - size_t value. That is 32bit on x86 and 64bit on em64t
//      '*' - the width is specified in params,
//            ex: ("%*x", 3, 5), 3 - width, 5 - number to print
//      '0' - print leading zeroes
//      positive_number - field width
//


int CDECL vmm_sprintf_s( char *buffer, size_t size_of_buffer, const char *format, ...);
int CDECL vmm_vsprintf_s( char *buffer, size_t size_of_buffer, const char *format, va_list argptr );

// printf() have to be implemented independently in each project
int CDECL vmm_printf( const char *format, ... );
int CDECL vmm_vprintf(const char *format, va_list args);

extern void vmm_lock_xchg_qword(UINT64 *dst, UINT64 *src);
extern void vmm_lock_xchg_dword(UINT32 *dst, UINT32 *src);

#ifdef ARCH_ADDRESS_WIDTH
	#if 8 == ARCH_ADDRESS_WIDTH
		#define VMM_LONG UINT64
		#define BIT_SHIFT 3
		#define REM_MASK 7
		#define vmm_lock_xchg_32_64_word(x, y) \
				vmm_lock_xchg_qword((UINT64*)(x), (UINT64*)(y))
	#else
		#define VMM_LONG UINT32
		#define BIT_SHIFT 2
		#define REM_MASK 3
		#define vmm_lock_xchg_32_64_word(x, y) \
				vmm_lock_xchg_dword((UINT32*)(x), (UINT32*)(y))
	#endif
#else
	#define VMM_LONG UINT32
	#define BIT_SHIFT 2
	#define REM_MASK 3
	#define vmm_lock_xchg_32_64_word(x, y) \
			vmm_lock_xchg_dword((UINT32*)(x), (UINT32*)(y))
#endif

#define COUNT_32_64(x) ((x) >> (BIT_SHIFT))
#define REMAINDER_32_64(x) ((x) & (REM_MASK))
#define SHL_32_64(x) ((x) << (BIT_SHIFT))

#endif // _UVMM_COMMON_CRT_H_
