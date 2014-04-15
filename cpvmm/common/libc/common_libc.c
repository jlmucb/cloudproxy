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


//   commonly used libc utilities


#include "common_libc.h"

extern void vmm_lock_xchg_byte(UINT8 *dst, UINT8 *src);

#pragma optimize( "", off )
void *  vmm_memset(void *dest, int filler, size_t count)
{
    size_t i = 0, j, cnt_64bit;
    UINT64 filler_64;
    UINT64 *fill = &filler_64;

    cnt_64bit = count >> 3;

    if (cnt_64bit) {
        if (filler != 0) {
            *(UINT8*)fill = (UINT8)filler;
            *((UINT8*)fill + 1) = (UINT8)filler;
            *((UINT16*)fill + 1) = *(UINT16*)fill;
            *((UINT32*)fill + 1) = *(UINT32*)fill;
        }

        for (i = 0; i < cnt_64bit; i++) {
            if (filler == 0)
                ((UINT64*) dest)[i] = 0;
            else    
                ((UINT64*) dest)[i] = filler_64;
        }
        i = i << 3;
    }

    for (j = i; j < count; j++) {
        ((UINT8*) dest)[j] = (UINT8)filler;
    }
    return dest;
}
#pragma optimize( "", on )

void *  vmm_memcpy_ascending(void *dest, const void* src, size_t count)
{
    size_t i = 0, j, cnt_64bit;
    UINT64 *d = (UINT64 *)dest;
    const UINT64 *s = (const UINT64*)src;

    cnt_64bit = count >> 3;
    if (cnt_64bit) {
        for(i = 0; i < cnt_64bit; i++)
            ((UINT64*) d)[i] = ((UINT64*) s)[i];
        i = i << 3;
    }

    for (j = i; j < count; j++) {
        ((UINT8*) dest)[j] = ((UINT8*)src)[j];
    }
    return dest;
}

void *  vmm_memcpy_descending(void *dest, const void* src, size_t count)
{
    size_t i, cnt, rem;
    VMM_LONG *d = (VMM_LONG*)dest;
    const VMM_LONG *s = (const VMM_LONG*)src;

    cnt = COUNT_32_64(count);
    rem = REMAINDER_32_64(count);

    for (i = 0; i < rem; i++) {
        ((UINT8*) d)[count - i - 1] = ((UINT8*)s)[count - i - 1];
    }

    if (cnt) {
        for(i = cnt; i > 0; i--)
            ((VMM_LONG*)d)[i - 1] = ((VMM_LONG*)s)[i - 1];
    }
    return dest;
}

void *  vmm_memcpy(void *dest, const void* src, size_t count)
{
    if (dest >= src) {
        return vmm_memcpy_descending(dest, src, count);
    }
    else {
        return vmm_memcpy_ascending(dest, src, count);
    }
}

void *  vmm_memmove(void *dest, const void* src, int count)
{
    if (dest == src) {
        return dest;
    } 
    else if (dest >= src) {
        return vmm_memcpy_descending(dest, src, count);
    } 
    else {
        return vmm_memcpy_ascending(dest, src, count);
    }
}

size_t  vmm_strlen(const char* string)
{
    size_t len = 0;
    const char* next = string;

    if (! string) {
        return SIZE_T_ALL_ONES;
    }
    for (; *next != 0; ++next) {
        ++len;
    }
    return len;
}

char*  vmm_strcpy(char* dst, const char* src)
{
    if (! src || ! dst) {
        return NULL;
    }

    while ((*dst++ = *src++) != 0);
    return dst;
}

char*  vmm_strcpy_s(char* dst, size_t dst_length, const char* src)
{
    size_t src_length = vmm_strlen(src);
    const char* s = src;

    if (! src || ! dst || ! dst_length || dst_length < src_length + 1) {
        return NULL;
    }
    while (*s != 0) {
        *dst++ = *s++;
    }
    *dst = '\0';
    return dst;
}

UINT32  vmm_strcmp(const char* string1, const char* string2)
{
    const char* str1 = string1;
    const char* str2 = string2;

    if(str1 == str2) {
        return 0;
    }
    if(NULL == str1) {
        return (UINT32) -1;
    }
    if(NULL == str2) {
        return 1;
    }
    while(*str1 == *str2) {
        if('\0' == *str1) {
            break;
        }
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

int vmm_memcmp(const void* mem1, const void* mem2, size_t count)
{
    const char *m1 = mem1;
    const char *m2 = mem2;

    while (count) {
        count--;
        if (m1[count] != m2[count])
            break;
    }
    return (m1[count] - m2[count]);
}

void vmm_memcpy_assuming_mmio( UINT8 *dst, UINT8 *src, INT32 count)
{
    switch (count) {
    case 0:
        break;

    case 1:
        *dst = *src;
        break;

    case 2:
        *(UINT16 *) dst = *(UINT16 *) src;
        break;

    case 4:
        *(UINT32 *) dst = *(UINT32 *) src;
      break;

    case 8:
        *(UINT64 *) dst = *(UINT64 *) src;
        break;

    case 16:
        *(UINT64 *) dst = *(UINT64 *) src;
        dst += sizeof(UINT64);
        src += sizeof(UINT64);
        *(UINT64 *) dst = *(UINT64 *) src;
        break;

    default:
        vmm_memcpy(dst, src, count);
        break;
    }
}

/******************* Locked versions of functions ***********************/

/*
 * NOTE: Use vmm_lock_memcpy with caution. Although it is a locked version of
 * memcpy, it locks only at the DWORD level. Users need to implement their
 * own MUTEX LOCK to ensure other processor cores don't get in the way.
 * This copy only ensures that at DWORD level there are no synchronization
 * issues.
 */
void *  vmm_lock_memcpy_ascending(void *dest, const void* src, size_t count)
{
    size_t i = 0, j, cnt;
    VMM_LONG *d = (VMM_LONG *)dest;
    const VMM_LONG *s = (const VMM_LONG*)src;

    cnt = COUNT_32_64(count);
    if (cnt) {
        for(i = 0; i < cnt; i++) {
            vmm_lock_xchg_32_64_word(&((VMM_LONG*) d)[i], &((VMM_LONG*) s)[i]);
        }
        i = SHL_32_64(i);
    }
    for (j = i; j < count; j++) {
        vmm_lock_xchg_byte(&((UINT8*) dest)[j], &((UINT8*)src)[j]);
    }
    return dest;
}

void *  vmm_lock_memcpy_descending(void *dest, const void* src, size_t count)
{
    size_t i, cnt, rem;
    VMM_LONG *d = (VMM_LONG*)dest;
    const VMM_LONG *s = (const VMM_LONG*)src;

    cnt = COUNT_32_64(count);
    rem = REMAINDER_32_64(count);
    for (i = 0; i < rem; i++) {
        vmm_lock_xchg_byte(&((UINT8*)d)[count - i - 1],
                           &((UINT8*)s)[count - i - 1]);
    }
    if (cnt) {
        for(i = cnt; i > 0; i--) {
            vmm_lock_xchg_32_64_word(&((VMM_LONG*)d)[i - 1],
                                     &((VMM_LONG*)s)[i - 1]);
        }
    }
    return dest;
}

/*
 * NOTE: READ THE NOTE AT BEGINNING OF Locked Versions of functions.
 */
void *  vmm_lock_memcpy(void *dest, const void* src, size_t count)
{
    if (dest >= src) {
        return vmm_lock_memcpy_descending(dest, src, count);
    }
    else {
        return vmm_lock_memcpy_ascending(dest, src, count);
    }
}

