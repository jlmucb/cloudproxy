/****************************************************************************
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
****************************************************************************/

#ifndef _HW_INTERLOCKED_H_
#define _HW_INTERLOCKED_H_

#include "vmm_defs.h"

#ifndef __GNUC__    // MS Compiler Intrinsics

extern long _InterlockedCompareExchange(
            long volatile * Destination,
            long Exchange,
            long Comperand );
extern __int64 _InterlockedCompareExchange64(
            __int64 volatile * Destination,
            __int64 Exchange,
            __int64 Comperand );
extern long _InterlockedDecrement(long * lpAddend);
extern long _InterlockedIncrement(long * lpAddend);
extern __int64 _InterlockedIncrement64(long long volatile * lpAddend);
extern long _InterlockedAdd(long volatile * Addend, long Value);
extern long _InterlockedOr(long volatile * Value,long Mask);
extern long _InterlockedAnd(long volatile * Value,long Mask);
extern long _InterlockedXor(long volatile * Value,long Mask);
extern long _InterlockedExchange(long * Target,long Value);
extern void __faststorefence(void);

#endif


////////////////////////////////////////////////////////////////////////////////
//
// Various interlocked routines
//
////////////////////////////////////////////////////////////////////////////////

//------------------------------------------------------------------------------
// returns previous value
// Assigns new value if previous value == expected_value
// If previous value != expected_value do not change it
//
// Compare returned value with expected to discover.
//
// INT32 ASM_FUNCTION
// hw_interlocked_compare_exchange(
//     volatile        INT32* p_number,
//     INT32           expected_value,
//     INT32           new_value
//    );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    gcc_interlocked_compare_exchange(
            INT32 volatile * destination,
            INT32 exchange,
            INT32 comperand );

#define hw_interlocked_compare_exchange( p_number, expected_value, new_value )  \
    (INT32) gcc_interlocked_compare_exchange(                                   \
            (INT32 volatile*)(p_number),                                        \
            (INT32)(new_value),                                                 \
            (INT32)(expected_value))

#else

#define hw_interlocked_compare_exchange( p_number, expected_value, new_value )  \
    (INT32)_InterlockedCompareExchange(                                         \
            (long volatile*)(p_number),                                         \
            (long)(new_value),                                                  \
            (long)(expected_value))

#endif

//------------------------------------------------------------------------------
// returns previous value
// Assigns new value if previous value == expected_value
// If previous value != expected_value do not change it
//
// Compare returned value with expected to discover.
//
// INT64 ASM_FUNCTION
// hw_interlocked_compare_exchange_8(
//     volatile UINT64 *p_number,
//     INT64 expected_value,
//     INT64 new_value
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT64   gcc_interlocked_compare_exchange_8(
            INT64 volatile * destination,
            INT64 exchange,
            INT64 comperand );

#define hw_interlocked_compare_exchange_8( p_number, expected_value, new_value )\
    (INT64)gcc_interlocked_compare_exchange_8(                                \
            (INT64 volatile*)(p_number),                                      \
            (INT64)(new_value),                                               \
            (INT64)(expected_value) )
#else
#define hw_interlocked_compare_exchange_8( p_number, expected_value, new_value )\
    (INT64)_InterlockedCompareExchange64(                                     \
            (INT64 volatile*)(p_number),                                      \
            (INT64)(new_value),                                               \
            (INT64)(expected_value) )
#endif

//------------------------------------------------------------------------------
//
// Decrement value by 1
//
// INT32 ASM_FUNCTION
// hw_interlocked_decrement(
//     volatile INT32 *p_counter
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    hw_interlocked_decrement(INT32 * minuend);
#else
#define hw_interlocked_decrement( p_counter )                                   \
    (INT32)_InterlockedDecrement( (long*)(p_counter) )
#endif

//------------------------------------------------------------------------------
//
// Decrement value by 1
//
// INT32 ASM_FUNCTION
// hw_interlocked_increment(
//     volatile INT32 *p_counter
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    hw_interlocked_increment(INT32 * addend);
#else
#define hw_interlocked_increment( p_counter )                                   \
    (INT32)_InterlockedIncrement( (long*)(p_counter) )

#define hw_interlocked_increment64( p_counter )                                   \
    (INT64)_InterlockedIncrement64( (long long*)(p_counter) )
   
#endif

//------------------------------------------------------------------------------
//
// This function guarantees to return the old value at the time of the addition
//
// INT32 ASM_FUNCTION
// hw_interlocked_add(
//     volatile INT32 *p_counter,
//     INT32 addend
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    hw_interlocked_add(INT32 volatile * addend, INT32 value);
#else
#define hw_interlocked_add( p_counter, addend )                                 \
    (INT32)_InterlockedAdd((long volatile*)(p_counter), (long)(addend))
#endif

//------------------------------------------------------------------------------
//
// returns previous value
//
// INT32 ASM_FUNCTION
// hw_interlocked_bit_or(
//     volatile INT32* p_bit_set,
//     INT32           mask
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    hw_interlocked_or(INT32 volatile * value, INT32 mask);
#else
#define hw_interlocked_or( p_bit_set, mask )                                 \
    (INT32)_InterlockedOr((long volatile*)(p_bit_set), (long)(mask))
#endif

//------------------------------------------------------------------------------
//
// returns previous value
//
// INT32 ASM_FUNCTION
// hw_interlocked_bit_and(
//     volatile INT32* p_bit_set,
//     INT32           mask
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    hw_interlocked_and(INT32 volatile * value, INT32 mask);
#else
#define hw_interlocked_and( p_bit_set, mask )                                 \
    (INT32)_InterlockedAnd((long volatile*)(p_bit_set), (long)(mask))
#endif

//------------------------------------------------------------------------------
//
// returns previous value
//
// INT32 ASM_FUNCTION
// hw_interlocked_bit_xor(
//     volatile INT32* p_bit_set,
//     INT32           mask
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    hw_interlocked_xor(INT32 volatile * value, INT32 mask);
#else
#define hw_interlocked_xor( p_bit_set, mask )                                 \
    (INT32)_InterlockedXor((long volatile*)(p_bit_set), (long)(mask))
#endif

//------------------------------------------------------------------------------
//
// returns previous value
//
// INT32 ASM_FUNCTION
// hw_interlocked_assign(
//     volatile INT32* p_number,
//     INT32           new_value
//     );
//------------------------------------------------------------------------------
#ifdef __GNUC__
INT32    hw_interlocked_assign(INT32 volatile * target, INT32 new_value);
#else
#define hw_interlocked_assign( p_number, new_value )                            \
    (INT32)_InterlockedExchange( (long*)(p_number), (long)(new_value))
#endif


#ifdef __GNUC__
void    hw_store_fence(void);
#else
#define hw_store_fence()              __faststorefence()
#endif


//------------------------------------------------------------------------------
//
// returns nothing
//
// void hw_assign_as_barrier( volatile UINT32* p_number, UINT32 new_value )
//
//------------------------------------------------------------------------------
#define hw_assign_as_barrier( p_number, new_value )                             \
        hw_store_fence(); \
        *(p_number) = (new_value)

//------------------------------------------------------------------------------
//
// Execute assembler 'pause' instruction
//
//------------------------------------------------------------------------------
void ASM_FUNCTION
hw_pause( void );

//------------------------------------------------------------------------------
//
// Execute assembler 'monitor' instruction
//
//------------------------------------------------------------------------------
void ASM_FUNCTION
hw_monitor( void* addr, UINT32 extension, UINT32 hint );

//------------------------------------------------------------------------------
//
// Execute assembler 'mwait' instruction
//
//------------------------------------------------------------------------------
void ASM_FUNCTION
hw_mwait( UINT32 extension, UINT32 hint );

#endif // _HW_INTERLOCKED_H_


