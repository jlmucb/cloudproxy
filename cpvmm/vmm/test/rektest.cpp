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

typedef int INT32;
typedef long long unsigned UINT64;


INT32 hw_interlocked_add(INT32 volatile * addend, INT32 value)
{
    asm volatile(
        "\tmovq     %[addend], %%rbx\n"
        "\tmovl     %[value], %%eax\n"
        "\tlock;    addl %%eax, (%%rbx)\n"
    : 
    : [addend] "p" (addend), [value] "r" (value)
    : "%eax", "%rbx");
    return *addend;
}


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

    int i, j, k, n;
    i= 5;
    j= 6;
    n= i; 

    printf("next test\n");

    k= hw_interlocked_add(&i, j);
    printf("%d %d, %d %d\n", n,j,i,k);

    return 0;
}


