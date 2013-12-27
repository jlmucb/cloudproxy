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

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#include "vmm_defs.h"
#include "libc.h"
#include "hw_utils.h"
#include "hw_setjmp.h"
#include "trial_exec.h"
#include "guest_cpu.h"
#include "idt.h"
#include "isr.h"
#include "vmm_dbg.h"
#include "vmcs_api.h"
#include "scheduler.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(ISR_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(ISR_C, __condition)

extern ISR_PARAMETERS_ON_STACK *g_exception_stack;

//------------ local macro definitions ------------//

#define INTERRUPT_COUNT_VECTORS 256
#define EXCEPTION_COUNT_VECTORS 32

#define ERROR_CODE_EXT_BIT 0x1
#define ERROR_CODE_IN_IDT  0x2
#define ERROR_CODE_TI      0x4

#define RFLAGS_IF           9   // Interrupt flag in RFLAGS register

typedef enum {
    INTERRUPT_CLASS,
    ABORT_CLASS,
    FAULT_CLASS,
    TRAP_CLASS,
    RESERVED_CLASS
} EXCEPTION_CLASS_ENUM;


//---------------- local variables ------------------//

static VMM_ISR_HANDLER isr_table[INTERRUPT_COUNT_VECTORS];

static const char *exception_message[] = {
    "Divide Error",
    "Debug Breakpoint",
    "NMI",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded",
    "Undefined Opcode",
    "No Math Coprocessor",
    "Double Fault",
    "Reserved 0x09",
    "Invalid Task Segment selector",
    "Segment Not present",
    "Stack Segment Fault",
    "General Protection Fault",
    "Page Fault",
    "Reserved 0x0f",
    "Math Fault",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating Point Numeric Error",
    "Reserved SIMD Floating Point Numeric Error"
};

const UINT8 exception_class[] = {
    FAULT_CLASS,    //Divide Error
    TRAP_CLASS,     //Debug Breakpoint
    INTERRUPT_CLASS,//NMI
    TRAP_CLASS,     //Breakpoint
    TRAP_CLASS,     //Overflow
    FAULT_CLASS,    //Bound Range Exceeded
    FAULT_CLASS,    //Undefined Opcode
    FAULT_CLASS,    //No Math Coprocessor
    ABORT_CLASS,    //Double Fault
    RESERVED_CLASS, //Reserved 0x09
    FAULT_CLASS,    //Invalid Task Segment selector
    FAULT_CLASS,    //Segment Not present
    FAULT_CLASS,    //Stack Segment Fault
    FAULT_CLASS,    //General Protection Fault
    FAULT_CLASS,    //Page Fault
    RESERVED_CLASS, //Reserved 0x0f
    FAULT_CLASS,    //Math Fault
    FAULT_CLASS,    //Alignment Check
    ABORT_CLASS,    //Machine Check
    FAULT_CLASS,    //SIMD Floating Point Numeric Error
    RESERVED_CLASS, //Reserved SIMD Floating Point Numeric Error
};



//---------------------- Code -----------------------//


/*-------------------------------------------------------*
*  FUNCTION     : isr_c_handler()
*  PURPOSE      : Generic ISR handler which calls registered
*               : vector specific handlers.
*               : Clear FLAGS.IF
*  ARGUMENTS    : IN ISR_PARAMETERS_ON_STACK *p_stack - points
*               : to the stack, where FLAGS register stored
*               : as a part of return from interrupt cycle
*  RETURNS      : void
*-------------------------------------------------------*/
void isr_c_handler(
    IN ISR_PARAMETERS_ON_STACK *p_stack)
{
    VECTOR_ID   vector_id = (VECTOR_ID) p_stack->a.vector_id;
    BOOLEAN     interrut_during_emulation;


    if (FALSE == (interrut_during_emulation = gcpu_process_interrupt(vector_id)))
    {
        BOOLEAN     handled = FALSE;

        // if it is a fault exception,
        // skip faulty instruction in case there is instruction length supplied
        if (vector_id < NELEMENTS(exception_class) && FAULT_CLASS == exception_class[vector_id])
        {
            TRIAL_DATA *p_trial_data = trial_execution_get_last();

            if (NULL != p_trial_data)
            {
                p_stack->u.errcode_exception.ip = (ADDRESS)hw_exception_post_handler;
                p_stack->u.errcode_exception.sp = (ADDRESS)p_trial_data->saved_env;
                p_trial_data->fault_vector = vector_id;
                p_trial_data->error_code   = (UINT32) p_stack->u.errcode_exception.errcode;
                handled = TRUE;
            }
        }

        if (FALSE == handled)
        {
            if (NULL == isr_table[vector_id])
            {
                VMM_LOG(mask_anonymous, level_trace,"Interrupt vector(%d) handler is not registered\n", vector_id);
            }
            else
            {
                (isr_table[vector_id])(p_stack);
            }
        }
    }

    if (vector_id >= EXCEPTION_COUNT_VECTORS || interrut_during_emulation)
    {
        // apparently interrupts were enabled
        // but we don't process more than one interrupt per VMEXIT,
        // and we don't process more than one interrupt per emulated instruction
        // p_stack->flags is actually eflags / rflags on the stack
        // clear flags.IF to prevent interrupt re-enabling
        BIT_CLR(p_stack->u.exception.flags, RFLAGS_IF);
    }

    // Before returning to the assmbler code, need to set pointer to the
    // EXCEPTION_STACK ip member.
    if (FALSE == interrut_during_emulation && isr_error_code_required(vector_id))
    {
        // case exception code DO was pushed on the stack
        p_stack->a.except_ip_ptr = (ADDRESS) &p_stack->u.errcode_exception.ip;
    }
    else
    {
        // case no exception code was pushed on the stack
        // (external interrupts or exception without error code)
        p_stack->a.except_ip_ptr = (ADDRESS) &p_stack->u.exception.ip;
    }

}


/*-------------------------------------------------------*
*  FUNCTION     : isr_register_handler()
*  PURPOSE      : Registers ISR handler
*  ARGUMENTS    : VMM_ISR_HANDLER handler - is called
*               : when vector interrupt/exception occurs
*               : VECTOR_ID vector_id
*  RETURNS      : void
*-------------------------------------------------------*/
void isr_register_handler(
    IN VMM_ISR_HANDLER  handler,
    IN VECTOR_ID        vector_id)
{
    isr_table[vector_id] = handler;
}

#pragma warning( push )
#pragma warning( disable : 4100 )
#ifdef DEBUG

static void print_exception_header(
            ADDRESS cs          USED_IN_DEBUG_ONLY,
            ADDRESS ip          USED_IN_DEBUG_ONLY,
            VECTOR_ID vector_id USED_IN_DEBUG_ONLY,
            size_t errcode      USED_IN_DEBUG_ONLY)
{
    CPU_ID cpu_id = hw_cpu_id();

    VMM_LOG_NOLOCK("*******************************************************************************\n");
    VMM_LOG_NOLOCK("*                                                                             *\n");
    VMM_LOG_NOLOCK("*                       Intel Virtual Machine Monitor                         *\n");
    VMM_LOG_NOLOCK("*                                                                             *\n");
    VMM_LOG_NOLOCK("*******************************************************************************\n");
    VMM_LOG_NOLOCK("\nException(%d) has occured on CPU(%d) at cs=%P ip=%P errcode=%Id", vector_id, cpu_id, cs, ip, errcode);
}
#pragma warning( pop )

static void print_errcode_generic(ADDRESS errcode)
{
    VMM_LOG_NOLOCK("Error code: 0X%X", errcode);

    if ((errcode & ERROR_CODE_EXT_BIT) != 0)
    {
        VMM_LOG_NOLOCK("External event\n");
    }
    else
    {
        VMM_LOG_NOLOCK("Internal event\n");
    }

    if ((errcode & ERROR_CODE_IN_IDT) != 0)
    {
        VMM_LOG_NOLOCK("Index is in IDT\n");
    }
    else if ((errcode & ERROR_CODE_TI) != 0)
    {
        VMM_LOG_NOLOCK("Index is in LDT\n");
    }
    else
    {
        VMM_LOG_NOLOCK("Index is in GDT\n");
    }
}
#endif //DEBUG

static void exception_handler_default_no_errcode(ISR_PARAMETERS_ON_STACK *p_stack)
{
    VMM_DEBUG_CODE(print_exception_header(p_stack->u.exception.cs,
                           p_stack->u.exception.ip,
                           (VECTOR_ID) p_stack->a.vector_id,
                           0));

    if (p_stack->a.vector_id < NELEMENTS(exception_message))
    {
        VMM_LOG_NOLOCK(" Error type: %s\n", exception_message[p_stack->a.vector_id]);
    }
}

static void exception_handler_default_with_errcode(ISR_PARAMETERS_ON_STACK *p_stack)
{
	VMM_DEBUG_CODE(print_exception_header(p_stack->u.errcode_exception.cs,
                           p_stack->u.errcode_exception.ip,
                           (VECTOR_ID) p_stack->a.vector_id,
                           p_stack->u.errcode_exception.errcode));

    if (p_stack->a.vector_id < NELEMENTS(exception_message))
    {
        VMM_LOG_NOLOCK(" Exception type: %s\n", exception_message[p_stack->a.vector_id]);
    }
}

static void exception_handler_default(ISR_PARAMETERS_ON_STACK *p_stack)
{
    if (isr_error_code_required((VECTOR_ID) p_stack->a.vector_id))
    {
        exception_handler_default_with_errcode( p_stack );
    }
    else
    {
        exception_handler_default_no_errcode( p_stack );
    }

    g_exception_stack = p_stack;
    VMM_DEADLOOP();
}


static void exception_handler_page_fault(ISR_PARAMETERS_ON_STACK *p_stack)
{
    GUEST_CPU_HANDLE        gcpu;
    VMCS_OBJECT             *vmcs;

    VMM_DEBUG_CODE(print_exception_header(p_stack->u.errcode_exception.cs,
                           p_stack->u.errcode_exception.ip,
                           (VECTOR_ID) p_stack->a.vector_id,
                           p_stack->u.errcode_exception.errcode));

    if (p_stack->a.vector_id < NELEMENTS(exception_message))
    {
        VMM_LOG_NOLOCK(" Error type: %s\n", exception_message[p_stack->a.vector_id]);
    }

    VMM_LOG_NOLOCK("Faulting address of page fault is %P   RSP=%P\n",
        hw_read_cr2(),
        p_stack->u.errcode_exception.sp);

    gcpu = scheduler_current_gcpu();
    vmcs = gcpu_get_vmcs(gcpu);
    VMM_LOG_NOLOCK("Last VMEXIT reason = %d\n", (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_REASON));

    g_exception_stack = p_stack;
    VMM_DEADLOOP();
}

static void exception_handler_undefined_opcode(ISR_PARAMETERS_ON_STACK *p_stack)
{
#ifdef DEBUG
    UINT64 ip = p_stack->u.exception.ip;
    UINT8* ip_ptr = (UINT8*)ip;
#endif

    VMM_DEBUG_CODE(print_exception_header(p_stack->u.exception.cs,
                           p_stack->u.exception.ip,
                           (VECTOR_ID) p_stack->a.vector_id,
                           0));

    if (p_stack->a.vector_id < NELEMENTS(exception_message))
    {
        VMM_LOG_NOLOCK(" Exception type: %s\n", exception_message[p_stack->a.vector_id]);
    }

    VMM_LOG_NOLOCK("IP = %P\n", ip_ptr);

    VMM_LOG_NOLOCK("Encoding: %2x %2x %2x %2x\n", *ip_ptr, *(ip_ptr + 1), *(ip_ptr + 2), *(ip_ptr + 3));

    g_exception_stack = p_stack;
    VMM_DEADLOOP();
}

static void isr_install_default_handlers(void)
{
    unsigned vector_id;
    for (vector_id = 0; vector_id < INTERRUPT_COUNT_VECTORS; ++vector_id)
    {
        isr_register_handler(exception_handler_default, (UINT8) vector_id);
    }
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_DIVIDE_ERROR);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_DEBUG_BREAKPOINT);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_NMI);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_BREAKPOINT);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_OVERFLOW);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED);
    isr_register_handler(exception_handler_undefined_opcode, IA32_EXCEPTION_VECTOR_UNDEFINED_OPCODE);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_NO_MATH_COPROCESSOR);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_DOUBLE_FAULT);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_STACK_SEGMENT_FAULT);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT);
    isr_register_handler(exception_handler_page_fault      , IA32_EXCEPTION_VECTOR_PAGE_FAULT);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_MATH_FAULT);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_ALIGNMENT_CHECK);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_MACHINE_CHECK);
    isr_register_handler(exception_handler_default         , IA32_EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR);
}


/*----------------------------------------------------*
*  FUNCTION     : isr_setup()
*  PURPOSE      : Builds ISR wrappers, IDT tables and
*               : default high level ISR handlers for all CPUs.
*  ARGUMENTS    : void
*  RETURNS      : void
*-------------------------------------------------------*/
void isr_setup(void)
{
    hw_idt_setup();
    isr_install_default_handlers();
}

void isr_handling_start(void)
{
    hw_idt_load();
}

BOOLEAN isr_error_code_required(VECTOR_ID vector_id)
{
    switch (vector_id)
    {
    case IA32_EXCEPTION_VECTOR_DOUBLE_FAULT:
    case IA32_EXCEPTION_VECTOR_PAGE_FAULT:
    case IA32_EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR:
    case IA32_EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT:
    case IA32_EXCEPTION_VECTOR_STACK_SEGMENT_FAULT:
    case IA32_EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT:
    case IA32_EXCEPTION_VECTOR_ALIGNMENT_CHECK:
        return TRUE;
    default:
        return FALSE;
    }
}

