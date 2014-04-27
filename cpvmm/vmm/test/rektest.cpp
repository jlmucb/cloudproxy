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
typedef long long int INT64;


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

INT32 hw_interlocked_assign(INT32 volatile * target, INT32 new_value)
{
    asm volatile(
        "\tmovq     %[target], %%rbx\n"
        "\tmovl     %[new_value], %%eax\n"
        "\tlock;    xchgl %%eax, (%%rbx)\n"
    :
    : [new_value] "m" (new_value), [target] "r" (target)
    : "%eax", "%rbx");
    return *target;
}


// CHECK(JLM)
INT32 gcc_interlocked_compare_exchange(INT32 volatile * destination,
                                       INT32 exchange, INT32 comperand)
{
    asm volatile(
        "\tmovq     %[destination], %%rbx\n"
        "\tmovl     %[exchange], %%eax\n"
        "\tmovl     %[comperand], %%ecx\n"
        "\tcmpxchgl %%ecx, %%eax\n"
        "\tmovl     %%eax, (%%rbx)\n"
    :
    : [exchange] "m" (exchange), [comperand] "m" (comperand),
      [destination] "m" (destination)
    :"%eax", "%ecx", "%rbx");
    return *destination;
}

INT64 gcc_interlocked_compare_exchange_64(INT64 volatile * destination,
            INT64 exchange, INT64 comperand)
{
    asm volatile(
        "\tmovq     %[destination], %%rbx\n"
        "\tmovq     %[exchange], %%rax\n"
        "\tmovq     %[comperand], %%rcx\n"
        "\tcmpxchgq %%rcx, %%rax\n"
        "\tmovq     %%rax, (%%rbx)\n"
    :
    : [exchange] "m" (exchange), [comperand] "m" (comperand),
      [destination] "m" (destination)
    :"%rax", "%rcx", "%rbx");
    return *destination;
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

    i= 10;
    n= 10;
    k= hw_interlocked_assign(&i, 12);
    printf("orig %d, %d %d\n", n,i,k);

    i= 11;
    j= 12;
    k= gcc_interlocked_compare_exchange(&n, i, j);
    printf("%d %d <-- %d %d\n", k, n, i, j);

    i= 11;
    j= 11;
    k= gcc_interlocked_compare_exchange(&n, i, j);
    printf("%d %d <-- %d %d\n", k, n, i, j);

    return 0;
}


