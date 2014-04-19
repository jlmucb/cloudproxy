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


INT32  hw_interlocked_increment(INT32 *addend)
{
#ifdef JLMDEBUG
    bprint("hw_interlocked_increment\n");
    LOOP_FOREVER
#endif
    asm volatile(
      "\tlock; incl (%[addend])\n"
    :"=m"(addend)
    :[addend] "p" (addend)
    :"memory");
    return *addend;
}


UINT64 hw_interlocked_increment64(INT64* p_counter)
{
    UINT64 ret = 1ULL;

#ifdef JLMDEBUG
    bprint("hw_interlocked_increment64\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tlock; addq (%[p_counter]), %[ret]\n"
    :"=m" (ret)
    :[ret] "r" (ret), [p_counter] "p" (p_counter)
    :"memory");
    return ret;
}

INT32 hw_interlocked_decrement(INT32 * minuend)
{
#ifdef JLMDEBUG
    bprint("hw_interlocked_decrement\n");
    LOOP_FOREVER
#endif
    asm volatile(
      "\tlock; decl (%[minuend])\n"
    :"=m"(minuend)
    :[minuend] "p" (minuend)
    :"memory");
    return *minuend;
}

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

INT32 hw_interlocked_or(INT32 volatile * value, INT32 mask)
{
    INT32 ret = 0ULL;

#ifdef JLMDEBUG
    bprint("hw_interlocked_or\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tlock; or %[mask], (%[value])\n"
        "\tmov (%[value]), %[ret]\n"
    :"=m" (ret)
    :[ret] "r" (ret), [value] "p" (value), [mask] "r" (mask)
    :"memory");
    return ret;
}

INT32 hw_interlocked_xor(INT32 volatile * value, INT32 mask)
{
    INT32 ret = 0ULL;
#ifdef JLMDEBUG
    bprint("hw_interlocked_xor\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tlock; xor %[mask], (%[value])\n"
        "\tmovl (%[value]), %[ret]\n"
    :"=m" (ret)
    :[ret] "r" (ret), [value] "p" (value), [mask] "r" (mask)
    :"memory");
    return ret;
}

void hw_store_fence(void)
{
#if 0
    asm volatile(
        "\tlock; sfence\n"
    :::);
#endif
    return;
}

INT32 gcc_interlocked_compare_exchange( INT32 volatile * destination,
            INT32 exchange, INT32 comperand)
{
    INT32 ret = 0ULL;
#ifdef JLMDEBUG
    bprint("gcc_interlocked_compare_exchange\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tlock; cmpxchgl %[exchange], %[comperand]\n"
    :"=a" (ret), "+m" (*destination)
    :[ret] "r" (ret), [exchange] "r" (exchange), [comperand] "r" (comperand), [destination] "p" (destination)
    :"memory");

    return ret;
}


//RNB: this should probably be interlocked_compare_exchange_64 instead of _8?
INT64 gcc_interlocked_compare_exchange_8(INT64 volatile * destination,
            INT64 exchange, INT64 comperand)
{
    INT64 ret = 0ULL;
#ifdef JLMDEBUG
    bprint("gcc_interlocked_compare_exchange_8\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "lock; cmpxchgq %[exchange], %[comperand] \n\t"
    :"=a" (ret), "+m" (*destination)
    :[ret] "r" (ret), [exchange] "r" (exchange), 
     [comperand] "r" (comperand), [destination] "p" (destination)
    :"memory");
    return ret;
}


INT32 hw_interlocked_assign(INT32 volatile * target, INT32 new_value)
{
    INT64 ret = 0ULL;
#ifdef JLMDEBUG
    bprint("hw_interlocked_assign\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tlock; xchgl (%[target]), %[new_value]\n"
    :"=a" (ret), "+m" (new_value)
    :[ret] "r" (ret), [target] "p" (target), [new_value] "r" (new_value)
    :"memory", "cc"
    );
    return ret;
}


BOOLEAN hw_scan_bit_forward( UINT32 *bit_number_ptr, UINT32 bitset )
{
    BOOLEAN ret = FALSE;
#ifdef JLMDEBUG
    bprint("hw_scan_bit_forward\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tbsfl (%[bit_number_ptr]), %[bitset]\n"
    :"=a" (ret), "+m" (bit_number_ptr)
    :[ret] "r" (ret), [bit_number_ptr] "p" (bit_number_ptr), [bitset] "r" (bitset)
    :"memory", "cc");
    return bitset ? TRUE : FALSE;
}

BOOLEAN hw_scan_bit_forward64( UINT32 *bit_number_ptr, UINT64 bitset )
{
    BOOLEAN ret = FALSE;
#ifdef JLMDEBUG
    bprint("hw_scan_bit_forward64\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tbsfq (%[bit_number_ptr]), %[bitset]\n"
    :"=a" (ret), "+m" (bit_number_ptr)
    :[ret] "r" (ret), [bit_number_ptr] "p" (bit_number_ptr), 
     [bitset] "r" (bitset)
    :"memory", "cc");
    return bitset ? TRUE : FALSE;
}


BOOLEAN hw_scan_bit_backward64( UINT32 *bit_number_ptr, UINT64 bitset )
{
#ifdef JLMDEBUG
    bprint("hw_scan_bit_backward64\n");
    LOOP_FOREVER
#endif
    BOOLEAN ret = FALSE;
    asm volatile(
        "\tbsrq (%[bit_number_ptr]), %[bitset]\n"
    :"=a" (ret), "+m" (bit_number_ptr)
    :[ret] "r" (ret), [bit_number_ptr] "p" (bit_number_ptr), [bitset] "r" (bitset)
    :"memory", "cc");
    return bitset ? TRUE : FALSE;
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


