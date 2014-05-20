/*
 * File: bootstrap_string.c
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


// this is all 32 bit code
#include "bootstrap_types.h"
#include "bootstrap_string.h"
#include "common_libc.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

char* vmm_strncpy(char *dest, const char *src, int n)
{
    char* out= dest;

    while(n>0 && *src!='\0') {
        *(dest++)= *(src++);
        n--;
    }
    *dest= 0;
    return out;
}


#ifndef INVMM
char* vmm_strcpy(char *dest, const char *src)
{
    char* out= dest;

    while(*src!='\0') {
        *(dest++)= *(src++);
    }
    *dest= 0;
    return out;
}
#endif


char* vmm_strchr (const char * str, int character)
{
    const char* p= str;

    while(1) {
        if(*p==character)
            return (char*) p;
        if(*p=='\0')
            break;
        p++;
    }
    return NULL;
}


#ifndef INVMM
int vmm_strcmp (const char * str1, const char * str2)
{
    while(*str1!='\0' && *str2!='\0') {
        if(*str1>*str2)
            return 1;
        if(*str1<*str2)
            return -1;
        str1++; str2++;
    }
    return 0;
}
#endif


int vmm_strncmp (const char * str1, const char * str2, int n)
{

    while(n>=0 && *str1!='\0' && *str2!='\0') {
        if(*str1>*str2)
            return 1;
        if(*str1<*str2)
            return -1;
        str1++; str2++;
        n--;
    }
    return 0;
}


#ifndef INVMM
void *vmm_memset(void *dest, int val, uint32_t count)
{
    uint8_t* p= (uint8_t*) dest;
    while(count-->0)
	*(p++)= (uint8_t) val;
    return dest;
}


void *vmm_memcpy(void *dest, const void* src, uint32_t count)
{
    uint8_t* p= (uint8_t*) dest;
    uint8_t* q= (uint8_t*) src;
    while(count-->0)
	*(p++)= *(q++);
    return dest;
}


uint32_t vmm_strlen(const char* p)
{
    uint32_t count= 0;

    if(p==NULL)
        return 0;
    while(*(p++)!=0) {
        count++;
    }
    return count;
}
#endif


uint64_t vmm_strtoul (const char* str, char** endptr, int base)
{
    return 0;
}


void HexDump(uint8_t* start, uint8_t* end)
{
    uint8_t* p= start;
    int      i;

    while(p<=end) {
        bprint("%p: ", p);
        i= 0;
        while(p<=end) {
            bprint("%u ", *(uint32_t*)p);
            p+= 4;
            i++;
            if(i>3)
                break;
        } 
        bprint("\n");
    }
    bprint("\n");
}



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


const uint8_t _ctype[257] = {
    _CN,            /* 0x0      0.     */
    _CN,            /* 0x1      1.     */
    _CN,            /* 0x2      2.     */
    _CN,            /* 0x3      3.     */
    _CN,            /* 0x4      4.     */
    _CN,            /* 0x5      5.     */
    _CN,            /* 0x6      6.     */
    _CN,            /* 0x7      7.     */
    _CN,            /* 0x8      8.     */
    _CN|_SP,        /* 0x9      9.     */
    _CN|_SP,        /* 0xA     10.     */
    _CN|_SP,        /* 0xB     11.     */
    _CN|_SP,        /* 0xC     12.     */
    _CN|_SP,        /* 0xD     13.     */
    _CN,            /* 0xE     14.     */
    _CN,            /* 0xF     15.     */
    _CN,            /* 0x10    16.     */
    _CN,            /* 0x11    17.     */
    _CN,            /* 0x12    18.     */
    _CN,            /* 0x13    19.     */
    _CN,            /* 0x14    20.     */
    _CN,            /* 0x15    21.     */
    _CN,            /* 0x16    22.     */
    _CN,            /* 0x17    23.     */
    _CN,            /* 0x18    24.     */
    _CN,            /* 0x19    25.     */
    _CN,            /* 0x1A    26.     */
    _CN,            /* 0x1B    27.     */
    _CN,            /* 0x1C    28.     */
    _CN,            /* 0x1D    29.     */
    _CN,            /* 0x1E    30.     */
    _CN,            /* 0x1F    31.     */
    _XS|_SP,        /* 0x20    32. ' ' */
    _PU,            /* 0x21    33. '!' */
    _PU,            /* 0x22    34. '"' */
    _PU,            /* 0x23    35. '#' */
    _PU,            /* 0x24    36. '$' */
    _PU,            /* 0x25    37. '%' */
    _PU,            /* 0x26    38. '&' */
    _PU,            /* 0x27    39. ''' */
    _PU,            /* 0x28    40. '(' */
    _PU,            /* 0x29    41. ')' */
    _PU,            /* 0x2A    42. '*' */
    _PU,            /* 0x2B    43. '+' */
    _PU,            /* 0x2C    44. ',' */
    _PU,            /* 0x2D    45. '-' */
    _PU,            /* 0x2E    46. '.' */
    _PU,            /* 0x2F    47. '/' */
    _XD|_DI,        /* 0x30    48. '' */
    _XD|_DI,        /* 0x31    49. '1' */
    _XD|_DI,        /* 0x32    50. '2' */
    _XD|_DI,        /* 0x33    51. '3' */
    _XD|_DI,        /* 0x34    52. '4' */
    _XD|_DI,        /* 0x35    53. '5' */
    _XD|_DI,        /* 0x36    54. '6' */
    _XD|_DI,        /* 0x37    55. '7' */
    _XD|_DI,        /* 0x38    56. '8' */
    _XD|_DI,        /* 0x39    57. '9' */
    _PU,            /* 0x3A    58. ':' */
    _PU,            /* 0x3B    59. ';' */
    _PU,            /* 0x3C    60. '<' */
    _PU,            /* 0x3D    61. '=' */
    _PU,            /* 0x3E    62. '>' */
    _PU,            /* 0x3F    63. '?' */
    _PU,            /* 0x40    64. '@' */
    _XD|_UP,        /* 0x41    65. 'A' */
    _XD|_UP,        /* 0x42    66. 'B' */
    _XD|_UP,        /* 0x43    67. 'C' */
    _XD|_UP,        /* 0x44    68. 'D' */
    _XD|_UP,        /* 0x45    69. 'E' */
    _XD|_UP,        /* 0x46    70. 'F' */
    _UP,            /* 0x47    71. 'G' */
    _UP,            /* 0x48    72. 'H' */
    _UP,            /* 0x49    73. 'I' */
    _UP,            /* 0x4A    74. 'J' */
    _UP,            /* 0x4B    75. 'K' */
    _UP,            /* 0x4C    76. 'L' */
    _UP,            /* 0x4D    77. 'M' */
    _UP,            /* 0x4E    78. 'N' */
    _UP,            /* 0x4F    79. 'O' */
    _UP,            /* 0x50    80. 'P' */
    _UP,            /* 0x51    81. 'Q' */
    _UP,            /* 0x52    82. 'R' */
    _UP,            /* 0x53    83. 'S' */
    _UP,            /* 0x54    84. 'T' */
    _UP,            /* 0x55    85. 'U' */
    _UP,            /* 0x56    86. 'V' */
    _UP,            /* 0x57    87. 'W' */
    _UP,            /* 0x58    88. 'X' */
    _UP,            /* 0x59    89. 'Y' */
    _UP,            /* 0x5A    90. 'Z' */
    _PU,            /* 0x5B    91. '[' */
    _PU,            /* 0x5C    92. '\' */
    _PU,            /* 0x5D    93. ']' */
    _PU,            /* 0x5E    94. '^' */
    _PU,            /* 0x5F    95. '_' */
    _PU,            /* 0x60    96. '`' */
    _XD|_LO,        /* 0x61    97. 'a' */
    _XD|_LO,        /* 0x62    98. 'b' */
    _XD|_LO,        /* 0x63    99. 'c' */
    _XD|_LO,        /* 0x64   100. 'd' */
    _XD|_LO,        /* 0x65   101. 'e' */
    _XD|_LO,        /* 0x66   102. 'f' */
    _LO,            /* 0x67   103. 'g' */
    _LO,            /* 0x68   104. 'h' */
    _LO,            /* 0x69   105. 'i' */
    _LO,            /* 0x6A   106. 'j' */
    _LO,            /* 0x6B   107. 'k' */
    _LO,            /* 0x6C   108. 'l' */
    _LO,            /* 0x6D   109. 'm' */
    _LO,            /* 0x6E   110. 'n' */
    _LO,            /* 0x6F   111. 'o' */
    _LO,            /* 0x70   112. 'p' */
    _LO,            /* 0x71   113. 'q' */
    _LO,            /* 0x72   114. 'r' */
    _LO,            /* 0x73   115. 's' */
    _LO,            /* 0x74   116. 't' */
    _LO,            /* 0x75   117. 'u' */
    _LO,            /* 0x76   118. 'v' */
    _LO,            /* 0x77   119. 'w' */
    _LO,            /* 0x78   120. 'x' */
    _LO,            /* 0x79   121. 'y' */
    _LO,            /* 0x7A   122. 'z' */
    _PU,            /* 0x7B   123. '{' */
    _PU,            /* 0x7C   124. '|' */
    _PU,            /* 0x7D   125. '}' */
    _PU,            /* 0x7E   126. '~' */
    _CN,            /* 0x7F   127.     */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 0x80 to 0x8F
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 0x90 to 0x9F
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 0xA0 to 0xAF
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 0xB0 to 0xBF
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 0xC0 to 0xCF
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 0xD0 to 0xDF
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 0xE0 to 0xEF
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 // 0xF0 to 0x100
};

bool isdigit(int c)
{
    return (_ctype[(unsigned char)(c)] & (_DI));
}


bool isspace(int c)
{
    return (_ctype[(unsigned char)(c)] & (_SP));
}


bool isxdigit(int c)
{
    return (_ctype[(unsigned char)(c)] & (_XD));
}


bool isupper(int c)
{
    return (_ctype[(unsigned char)(c)] & (_UP));
}


bool islower(int c)
{
    return (_ctype[(unsigned char)(c)] & (_LO));
}


bool isprint(int c)
{
    return (_ctype[(unsigned char)(c)] & (_LO | _UP | _DI |
                                          _SP | _PU));
}


bool isalpha(int c)
{
    return (_ctype[(unsigned char)(c)] & (_LO | _UP));
}


const char* get_option_val(const cmdline_option_t *options,
                              char vals[][MAX_VALUE_LEN], const char *opt_name)
{
    int i;
    for (i = 0; options[i].name != NULL; i++ ) {
        if ( vmm_strcmp(options[i].name, opt_name) == 0 )
            return vals[i];
    }
    bprint("requested unknown option: %s\n", opt_name);
    return NULL;
}


void cmdline_parse(const char *cmdline, const cmdline_option_t *options,
                          char vals[][MAX_VALUE_LEN])
{
    const char *p = cmdline;
    int i;

    /* copy default values to vals[] */
    for ( i = 0; options[i].name != NULL; i++ ) {
        vmm_strncpy(vals[i], options[i].def_val, MAX_VALUE_LEN-1);
        vals[i][MAX_VALUE_LEN-1] = '\0';
    }

    if ( p == NULL )
        return;

    /* parse options */
    while ( 1 ) {
        /* skip whitespace */
        while ( isspace(*p) )
            p++;
        if ( *p == '\0' )
            break;

        /* find end of current option */
        const char *opt_start = p;
        const char *opt_end = (const char*)vmm_strchr(opt_start, ' ');
        if ( opt_end == NULL )
            opt_end = opt_start + vmm_strlen(opt_start);
        p = opt_end;

        /* find value part; if no value found, use default and continue */
        const char *val_start = vmm_strchr(opt_start, '=');
        if ( val_start == NULL || val_start > opt_end )
            continue;
        val_start++;

        unsigned int opt_name_size = val_start - opt_start - 1;
        unsigned int copy_size = opt_end - val_start;
        if ( copy_size > MAX_VALUE_LEN - 1 )
            copy_size = MAX_VALUE_LEN - 1;
        if ( opt_name_size == 0 || copy_size == 0 )
            continue;

        /* value found, so copy it */
        for ( i = 0; options[i].name != NULL; i++ ) {
            if ( vmm_strncmp(options[i].name, opt_start, opt_name_size ) == 0 ) {
                vmm_strncpy(vals[i], val_start, copy_size);
                vals[i][copy_size] = '\0'; /* add '\0' to the end of string */
                break;
            }
        }
    }
}


const char *skip_filename(const char *cmdline)
{
    if ( cmdline == NULL || *cmdline == '\0' )
        return cmdline;

    /* strip leading spaces, file name, then any spaces until the next
     non-space char (e.g. "  /foo/bar   baz" -> "baz"; "/foo/bar" -> "")*/
    while ( *cmdline != '\0' && isspace(*cmdline) )
        cmdline++;
    while ( *cmdline != '\0' && !isspace(*cmdline) )
        cmdline++;
    while ( *cmdline != '\0' && isspace(*cmdline) )
        cmdline++;
    return cmdline;
}


