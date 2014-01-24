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


UINT64 hw_rdtsc(void)
{
    UINT64 out;

    asm volatile (
        "\trdtsc\n"
        "\tmovq     %%rax,%[out]\n"
    :[out] "=g" (out)
    :: "%rax");
    return 0ULL;
}


INT32    hw_interlocked_increment(INT32 * addend)
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


void    hw_store_fence(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
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


void hw_lidt(void *Source)
{
    asm volatile(
        "\tlidt     (%[Source])\n"
    ::[Source] "p" (Source):);
    return;
}


void hw_sidt(void *Destination)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_msr( UINT32 msr_id, UINT64 Value )
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


UINT64 hw_read_msr( UINT32 msr_id )
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
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
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_cr3(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_cr4(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_cr8(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


void hw_write_cr0(UINT64 Data)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_cr3(UINT64 Data)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_cr4(UINT64 Data)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_cr8(UINT64 Data)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


UINT64 hw_read_dr0(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_dr1(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_dr2(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_dr3(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_dr4(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_dr5(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_dr6(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


UINT64 hw_read_dr7(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}


void hw_write_dr0(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_dr1(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_dr2(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_dr3(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_dr4(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_dr5(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_dr6(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_write_dr7(UINT64 value)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_invlpg(void *address)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_wbinvd(void)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


void hw_halt( void )
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return;
}


INT32    hw_interlocked_assign(INT32 volatile * target, INT32 new_value)
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


INT32    gcc_interlocked_compare_exchange( INT32 volatile * destination,
            INT32 exchange, INT32 comperand)
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


INT32    hw_interlocked_decrement(INT32 * minuend)
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


INT32    hw_interlocked_add(INT32 volatile * addend, INT32 value)
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


INT32    hw_interlocked_or(INT32 volatile * value, INT32 mask)
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


INT32    hw_interlocked_xor(INT32 volatile * value, INT32 mask)
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


UINT64 hw_interlocked_increment64(INT64* p_counter)
{
#if 0
    asm volatile(
        "\t\n\t"
    :
    : 
    :
    );
#endif
    return 0ULL;
}



