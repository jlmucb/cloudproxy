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

#include "stdio.h"
#include "stdlib.h"


#if 0
INT32 hw_interlocked_add(INT32 volatile * addend, INT32 value)
{
    UINT64 ret = 1ULL;

#ifdef JLMDEBUG
    bprint("hw_interlocked_add\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tlock; movl %[value], %%eax\n"
        "\tadd (%[addend]), %%rax\n"
        "\tmovq %%rax, %[ret]\n"
    :"=m" (ret)
    :[ret] "r" (ret), [addend] "p" (addend), [value] "r" (value)
    :"memory", "cc");
    return ret;
}

#endif


bool hw_scan_bit_backward( unsigned *bit_number_ptr, unsigned bitset )
{
    bool ret = false;

    asm volatile(
        "\tbsrl %[bitset], %%eax\n"
        "\tmov %[bit_number_ptr], %%rbx\n"
        "\tmovl %%eax, (%%rbx)\n"
    : 
    : [bit_number_ptr] "p" (bit_number_ptr), [bitset] "g"(bitset)
    : "%eax", "%rbx");
    return bitset ? true: false;
}


int main(int an, char** av)
{
    unsigned a, b;
    unsigned* pa= &a;
    b= 0x00400;
    bool ret= hw_scan_bit_backward(pa, b);

    printf("Number: 0x%08x, %d; ret: %d\n", b, *pa, ret);
    return 0;
}


