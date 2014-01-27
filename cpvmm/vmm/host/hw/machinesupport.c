/*
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
 */

#include "local_apic.h"
#include "em64t_defs.h"
#include "hw_utils.h"
#include "vmm_dbg.h"
#include "host_memory_manager_api.h"
#include "memory_allocator.h"
#include "file_codes.h"
#include "hw_vmx_utils.h"


UINT64 hw_rdtsc(void)
{
    UINT64      out;
    UINT64*     pout= &out;

    asm volatile (
        "\trdtsc\n"
        "\tmovq     %[pout],%%rcx\n"
        "\tmovl     %%eax, (%%rcx)\n"
        "\tmovl     %%edx, 4(%%rcx)\n"
    :[out] "=g" (out)
    :[pout] "m" (pout): "%rcx");
    return out;
}


UINT8 hw_read_port_8( UINT16 port )
{
    UINT8 out;

    asm volatile(
        "\tinb      %[port], %[out]\n"
    :[out] "=a" (out)
    :[port] "Nd" (port)
    :
    );
    return out;
}


UINT16 hw_read_port_16( UINT16 port )
{
    UINT16 out;

    asm volatile(
        "\tinw      %[port], %[out]\n"
    :[out] "=a" (out)
    :[port] "Nd" (port) :);
    return out;
}


UINT32 hw_read_port_32( UINT16 port )
{
    UINT32 out;

    asm volatile(
        "\tinl      %[port], %[out]\n"
    :[out] "=a" (out)
    :[port] "Nd" (port) :);
    return out;
}


void hw_write_port_8(UINT16 port, UINT8 val)
{
    asm volatile(
        "\toutb     %[val], %[port]\n"
    ::[val] "a" (val), [port] "Nd" (port) :);
    return;
}


void hw_write_port_16( UINT16 port, UINT16 val)
{
    asm volatile(
        "\toutw     %[val], %[port]\n"
    ::[val] "a" (val), [port] "Nd" (port) :);
    return;
}


void hw_write_port_32( UINT16 port, UINT32 val)
{
    asm volatile(
        "\toutl     %[val], %[port]\n"
    ::[val] "a" (val), [port] "Nd" (port) :);
    return;
}


void hw_write_msr(UINT32 msr_id, UINT64 val)
{
    asm volatile (
        "\twrmsr\n"
    ::[val] "A" (val), [msr_id] "c" (msr_id):);
    return;
}


UINT64 hw_read_msr(UINT32 msr_id)
{
    UINT64 out;

    // RDMSR reads the processor Model-Specific Register (MSR) whose index is stored in ECX, 
    //   and stores the result in EDX:EAX. 

    asm volatile (
        "\trdmsr\n"
    :[out] "=A" (out)
    :[msr_id] "c" (msr_id):);
    return out;
}


UINT64 hw_read_cr0(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%cr0, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_cr2(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%cr2, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_cr3(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%cr3, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_cr4(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%cr4, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_cr8(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%cr8, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


void hw_write_cr0(UINT64 data)
{
    asm volatile (
        "\tmovq     %[data], %%cr0\n"
    ::[data] "g" (data):); 
    return;
}


void hw_write_cr3(UINT64 data)
{
    asm volatile (
        "\tmovq     %[data], %%cr3\n"
    ::[data] "g" (data):); 
    return;
}


void hw_write_cr4(UINT64 data)
{
    asm volatile (
        "\tmovq     %[data], %%cr4\n"
    ::[data] "g" (data):); 
    return;
}


void hw_write_cr8(UINT64 data)
{
    asm volatile (
        "\tmovq     %[data], %%cr8\n"
    ::[data] "g" (data):); 
    return;
}


UINT64 hw_read_dr0(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr0, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_dr1(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr1, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_dr2(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr2, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_dr3(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr3, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_dr4(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr4, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_dr5(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr5, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_dr6(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr6, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


UINT64 hw_read_dr7(void)
{
    UINT64  out;
    asm volatile (
        "\tmovq     %%dr7, %[out]\n"
    :[out] "=r" (out) ::); 
    return out;
}


void hw_write_dr0(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr0\n"
    ::[value] "g" (value):); 
    return;
}


void hw_write_dr1(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr1\n"
    ::[value] "g" (value):); 
    return;
}


void hw_write_dr2(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr2\n"
    ::[value] "g" (value):); 
    return;
}


void hw_write_dr3(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr3\n"
    ::[value] "g" (value):); 
    return;
}


void hw_write_dr4(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr4\n"
    ::[value] "g" (value):); 
    return;
}


void hw_write_dr5(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr5\n"
    ::[value] "g" (value):); 
    return;
}


void hw_write_dr6(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr6\n"
    ::[value] "g" (value):); 
    return;
}


void hw_write_dr7(UINT64 value)
{
    asm volatile (
        "\tmovq     %[value], %%dr7\n"
    ::[value] "g" (value):); 
    return;
}


void hw_invlpg(void *address)
{
    asm volatile (
        "\tinvlpg   %[address]\n"
    ::[address] "m" (address):); 
    return;
}


void hw_wbinvd(void)
{
    asm volatile(
        "\twbinvd\n"
    : : :);
    return;
}


void hw_halt( void )
{
    asm volatile(
        "\thlt\n"
    :::);
    return;
}


void hw_lidt(void *source)
{
    asm volatile(
        "\tlidt     (%[source])\n"
    ::[source] "p" (source):);
    return;
}


void hw_sidt(void *destination)
{
    asm volatile(
        "\tsidt (%[destination])\n\t"
    ::[destination] "p" (destination) 
    :
    );
    return;
}


INT32  hw_interlocked_increment(INT32 *addend)
{
    asm volatile(
      "lock; incl (%[addend]) \n\t"
    :"=m"(addend)
//    :"m" (p_counter) 
    :[addend] "p" (addend)
    :"memory"
    );
    return *addend;
}


UINT64 hw_interlocked_increment64(INT64* p_counter)
{
	UINT64 ret = 1ULL;
    asm volatile(
			"lock; addq (%[p_counter]), %[ret] \n\t"
    :"=m" (ret)
    :[ret] "r" (ret), [p_counter] "p" (p_counter)
    :"memory"
    );
	return ret;
}

INT32 hw_interlocked_decrement(INT32 * minuend)
{
    asm volatile(
      "lock; decl (%[minuend]) \n\t"
    :"=m"(minuend)
    :[minuend] "p" (minuend)
    :"memory"
    );
    return *minuend;
}

INT32 hw_interlocked_add(INT32 volatile * addend, INT32 value)
{
	UINT64 ret = 1ULL;
    asm volatile(
			"lock; movl %[value], %%eax \n\t"
			"add (%[addend]), %%rax \n\t"
			"movq %%rax, %[ret] \n\t"
    :"=m" (ret)
    :[ret] "r" (ret), [addend] "p" (addend), [value] "r" (value)
    :"memory", "cc"
    );
	return ret;
}

INT32 hw_interlocked_or(INT32 volatile * value, INT32 mask)
{
	INT32 ret = 0ULL;
    asm volatile(
			"lock; or %[mask], (%[value]) \n\t"
			"mov (%[value]), %[ret] \n\t"
    :"=m" (ret)
    :[ret] "r" (ret), [value] "p" (value), [mask] "r" (mask)
    :"memory"
    );
	return ret;
}

INT32 hw_interlocked_xor(INT32 volatile * value, INT32 mask)
{
	INT32 ret = 0ULL;
    asm volatile(
			"lock; xor %[mask], (%[value]) \n\t"
			"movl (%[value]), %[ret] \n\t"
    :"=m" (ret)
    :[ret] "r" (ret), [value] "p" (value), [mask] "r" (mask)
    :"memory"
    );
	return ret;
}

void hw_store_fence(void)
{
    asm volatile(
        "lock; sfence\n\t"
    :::
    );
    return;
}

INT32 gcc_interlocked_compare_exchange( INT32 volatile * destination,
            INT32 exchange, INT32 comperand)
{
	INT32 ret = 0ULL;
    asm volatile(
        "lock; cmpxchgl %[exchange], %[comperand] \n\t"
    :"=a" (ret), "+m" (*destination)
//    :"r" (exchange), "0"(comperand)
    :[ret] "r" (ret), [exchange] "r" (exchange), [comperand] "r" (comperand), [destination] "p" (destination)
    :"memory"
    );
    return ret;
}


INT64 gcc_interlocked_compare_exchange_8(INT64 volatile * destination,
            INT64 exchange, INT64 comperand)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0;
}

INT32 hw_interlocked_assign(INT32 volatile * target, INT32 new_value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0;
}

BOOLEAN hw_scan_bit_forward64( UINT32 *bit_number_ptr, UINT64 bitset )
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return TRUE;
}


//------------------------------------------------------------------------------
// find first bit set
//
//  forward: LSB->MSB
//  backward: MSB->LSB
//
// Return 0 if no bits set
// Fills "bit_number" with the set bit position zero based
//
// BOOLEAN hw_scan_bit_forward( UINT32& bit_number, UINT32 bitset )
// BOOLEAN hw_scan_bit_backward( UINT32& bit_number, UINT32 bitset )
//
// BOOLEAN hw_scan_bit_forward64( UINT32& bit_number, UINT64 bitset )
// BOOLEAN hw_scan_bit_backward64( UINT32& bit_number, UINT64 bitset )
//------------------------------------------------------------------------------
BOOLEAN hw_scan_bit_forward( UINT32 *bit_number_ptr, UINT32 bitset )
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return TRUE;
}


BOOLEAN hw_scan_bit_backward( UINT32 *bit_number_ptr, UINT32 bitset )
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return TRUE;
}


BOOLEAN hw_scan_bit_backward64( UINT32 *bit_number_ptr, UINT64 bitset )
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return TRUE;
}
