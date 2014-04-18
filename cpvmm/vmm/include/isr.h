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

#ifndef _ISR_H_
#define _ISR_H_

#include "vmm_defs.h"

#pragma PACK_ON

typedef struct _EXCEPTION_STACK_WITH_ERRCODE_LAYOUT {
    ADDRESS errcode;
    ADDRESS ip;
    ADDRESS cs;
    ADDRESS flags;
    ADDRESS sp;
} EXCEPTION_STACK_WITH_ERRCODE_LAYOUT;

typedef struct _EXCEPTION_STACK_LAYOUT {
    ADDRESS ip;
    ADDRESS cs;
    ADDRESS flags;
    ADDRESS sp;
    ADDRESS dummy;
} EXCEPTION_STACK_LAYOUT;

typedef struct {
    union {
        ADDRESS vector_id;     // assembler code sets this as an input to
                               // C handler
        ADDRESS except_ip_ptr; // C handler have to set this to point to the
                               // ip member of the EXCEPTION_STACK before
                               // return to assembler code
    } a;
    union {
        EXCEPTION_STACK_WITH_ERRCODE_LAYOUT errcode_exception;
        EXCEPTION_STACK_LAYOUT exception;
    } PACKED u;
} PACKED ISR_PARAMETERS_ON_STACK;

typedef void (*VMM_ISR_HANDLER)(ISR_PARAMETERS_ON_STACK *p_stack);

#pragma PACK_OFF

typedef enum {
    IA32_EXCEPTION_VECTOR_DIVIDE_ERROR,
    IA32_EXCEPTION_VECTOR_DEBUG_BREAKPOINT,
    IA32_EXCEPTION_VECTOR_NMI,
    IA32_EXCEPTION_VECTOR_BREAKPOINT,
    IA32_EXCEPTION_VECTOR_OVERFLOW,
    IA32_EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED,
    IA32_EXCEPTION_VECTOR_UNDEFINED_OPCODE,
    IA32_EXCEPTION_VECTOR_NO_MATH_COPROCESSOR,
    IA32_EXCEPTION_VECTOR_DOUBLE_FAULT,
    IA32_EXCEPTION_VECTOR_RESERVED_0X09,
    IA32_EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR,
    IA32_EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT,
    IA32_EXCEPTION_VECTOR_STACK_SEGMENT_FAULT,
    IA32_EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT,
    IA32_EXCEPTION_VECTOR_PAGE_FAULT,
    IA32_EXCEPTION_VECTOR_RESERVED_0X0F,
    IA32_EXCEPTION_VECTOR_MATH_FAULT,
    IA32_EXCEPTION_VECTOR_ALIGNMENT_CHECK,
    IA32_EXCEPTION_VECTOR_MACHINE_CHECK,
    IA32_EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR,
    IA32_EXCEPTION_VECTOR_VIRTUAL_EXCEPTION,
    IA32_EXCEPTION_VECTOR_RESERVED_0X15,
    IA32_EXCEPTION_VECTOR_RESERVED_0X16,
    IA32_EXCEPTION_VECTOR_RESERVED_0X17,
    IA32_EXCEPTION_VECTOR_RESERVED_0X18,
    IA32_EXCEPTION_VECTOR_RESERVED_0X19,
    IA32_EXCEPTION_VECTOR_RESERVED_0X1A,
    IA32_EXCEPTION_VECTOR_RESERVED_0X1B,
    IA32_EXCEPTION_VECTOR_RESERVED_0X1C,
    IA32_EXCEPTION_VECTOR_RESERVED_0X1D,
    IA32_EXCEPTION_VECTOR_RESERVED_0X1E,
    IA32_EXCEPTION_VECTOR_RESERVED_0X1F
} HW_APIC_EXCEPTION_VECTORS;


// FUNCTION     : isr_c_handler()
// PURPOSE      : Generic ISR handler which calls registered
//              : vector specific handlers.
//              : Clear FLAGS.IF
// ARGUMENTS    : IN ISR_PARAMETERS_ON_STACK *p_stack - points
//              : to the stack, where FLAGS register stored
//              : as a part of return from interrupt cycle
void isr_c_handler( IN OUT ISR_PARAMETERS_ON_STACK *p_stack);


// FUNCTION     : isr_register_handler()
// PURPOSE      : Registers ISR handler
// ARGUMENTS    : VMM_ISR_HANDLER handler - is called
//              : when vector interrupt/exception occurs
//              : VECTOR_ID vector_id
// RETURNS      : void
void isr_register_handler( IN VMM_ISR_HANDLER  handler, IN VECTOR_ID vector_id);


// FUNCTION     : isr_setup()
// PURPOSE      : Builds ISR wrappers, IDT tables and
//              : default high level ISR handlers for all CPUs.
// ARGUMENTS    : IN UINT8 number_of_cpus
void isr_setup(void);

void isr_handling_start(void);

// FUNCTION     : isr_error_code_required()
// PURPOSE      : Check if CPU pushes error code onto stack for given vector ID
// ARGUMENTS    : IN UINT8 number_of_cpus
// RETURNS      : BOOLEAN if error code is pushed
BOOLEAN isr_error_code_required( VECTOR_ID vector_id);
#endif // _ISR_H_


