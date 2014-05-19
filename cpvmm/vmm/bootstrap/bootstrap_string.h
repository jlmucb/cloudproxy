/*
 * File: bootstrap_string.h
 * Description: string support for bootstrap
 * Author: John Manferdelli 
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


#ifndef _BOOTSTRAP_STRING_H_
#define _BOOTSTRAP_STRING_H_

#include "bootstrap_types.h"
#include "e820.h"


extern char*    vmm_strncpy(char *dest, const char *src, int n);
extern char*    vmm_strcpy(char *dest, const char *src);
extern char*    vmm_strchr (const char * str, int character);
extern int      vmm_strncmp (const char * str1, const char * str2, int n);
extern int      vmm_strcmp (const char * str1, const char * str2);
#ifdef INVMM
extern unsigned long long   vmm_strlen(const char* p);
extern void*    vmm_memset(void *dest, int val, unsigned long long count);
extern void*    vmm_memcpy(void *dest, const void* src, unsigned long long count);
#else
extern uint32_t vmm_strlen(const char* p);
extern void*    vmm_memset(void *dest, int val, uint32_t count);
extern void*    vmm_memcpy(void *dest, const void* src, uint32_t count);
#endif
extern uint64_t vmm_strtoul (const char* str, char** endptr, int base);
extern void HexDump(uint8_t* start, uint8_t* end);


#define _XA     0x00    /* extra alphabetic - not supported */
#define _XS     0x40    /* extra space */
#define _BB     0x00    /* BEL, BS, etc. - not supported */
#define _CN     0x20    /* CR, FF, HT, NL, VT */
#define _DI     0x04    /* ''-'9' */
#define _LO     0x02    /* 'a'-'z' */
#define _PU     0x10    /* punctuation */
#define _SP     0x08    /* space */
#define _UP     0x01    /* 'A'-'Z' */
#define _XD     0x80    /* ''-'9', 'A'-'F', 'a'-'f' */

extern bool isdigit(int c);
extern bool isspace(int c);
extern bool isxdigit(int c);
extern bool isupper(int c);
extern bool islower(int c);
extern bool isprint(int c);
extern bool isalpha(int c);


// command line parsing

typedef struct {
    const char *name;          // set to NULL for last item in list
    const char *def_val;
} cmdline_option_t;

#define MAX_VALUE_LEN 64
extern const char*  get_option_val(const cmdline_option_t *options,
                              char vals[][MAX_VALUE_LEN], const char *opt_name);
extern void         cmdline_parse(const char *cmdline, const cmdline_option_t *options,
                          char vals[][MAX_VALUE_LEN]);
extern const char*  skip_filename(const char *cmdline);
#endif
