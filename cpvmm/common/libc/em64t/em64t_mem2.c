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

#include "vmm_defs.h"
#include "common_libc.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

void vmm_lock_xchg_qword (UINT64 *dst, UINT64 *src) 
{
#ifdef JLMDEBUG
    bprint("vmm_lock_xchg_qword\n");
    LOOP_FOREVER
#endif
    // CHECK(JLM)
    asm volatile(
        "\tmovq %[src], %%r8\n"
        "\tmovq %[src], %%rdx\n"
        "\tmovq %[dst], %%rcx\n"
        "\tmovq %%r8, (%%rdx)\n"
        "\tlock; xchg %%r8, (%%rcx)\n"
    :
    : [dst] "m" (dst), [src] "m" (src)
    :"rcx", "rdx", "r8");
}


void vmm_lock_xchg_byte (UINT8 *dst, UINT8 *src) 
{
#ifdef JLMDEBUG
    bprint("vmm_lock_xchg_byte\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tmovq %[src], %%rdx\n"
        "\tmovq %[dst], %%rcx\n"
        "\tmovb (%%rdx), %%bl\n"
        "\tlock xchg %%bl, (%%rcx)\n" // byte exchange
    :
    : [dst] "m" (dst), [src] "m" (src)
    :"rcx", "rbx", "rdx");
}

