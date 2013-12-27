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

#ifndef _GUEST_CPU_VMENTER_EVENT_H_
#define _GUEST_CPU_VMENTER_EVENT_H_

#include "vmm_objects.h"

typedef struct {
    IA32_VMX_VMCS_VM_ENTER_INTERRUPT_INFO   interrupt_info;
    UINT32                                  instruction_length;
    ADDRESS                                 error_code;
} VMENTER_EVENT;

#ifdef INCLUDE_UNUSED_CODE
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_nmi_injection_allowed
*  PURPOSE  : Checks if NMI injection is allowed for the guest CPU
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event injection allowed
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_nmi_injection_allowed(const  GUEST_CPU_HANDLE gcpu);
#endif


/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_event
*  PURPOSE  : Inject interrupt/exception into guest if allowed, otherwise
*           : set NMI/Interrupt window
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*           : VMENTER_EVENT *p_event
*  RETURNS  : TRUE if event was injected, FALSE
*  NOTES    : no checkings are done for event validity
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_event(
    GUEST_CPU_HANDLE    gcpu,
    VMENTER_EVENT       *p_event);

#ifdef INCLUDE_UNUSED_CODE
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_native_pf
*  PURPOSE  : Inject native PF
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*             UINT64 pf_address - gva
*           : UINT64 pfec - error code
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_native_pf(GUEST_CPU_HANDLE    gcpu,
                              UINT64 pf_address,
                              UINT64 pfec);
#endif

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_gp0
*  PURPOSE  : Inject GP with error code 0
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_gp0(GUEST_CPU_HANDLE gcpu);

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_fault
*  PURPOSE  : Inject a fault to guest CPU
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
              int vec - fault vector
              UINT32 code - error code pushed on guest stack
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_fault(
    GUEST_CPU_HANDLE gcpu,
    int vec,
    UINT32 code);

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_nmi
*  PURPOSE  : Inject NMI into guest if allowed, otherwise set NMI window
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_nmi(GUEST_CPU_HANDLE gcpu);

#ifdef INCLUDE_UNUSED_CODE
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_external_interrupt
*  PURPOSE  : Inject external interrupt into guest if allowed,
*           :  otherwise set Interruption window
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*           : VECTOR_ID vector_id
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_external_interrupt(
    GUEST_CPU_HANDLE    gcpu,
    VECTOR_ID           vector_id);
#endif

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_double_fault
*  PURPOSE  : Inject Double Fault exception into guest if allowed,
*           :  otherwise set Interruption window
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_double_fault(GUEST_CPU_HANDLE gcpu);


/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_set_pending_nmi
*  PURPOSE  : Cause NMI VMEXIT be invoked immediately when NMI blocking finished
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*           : BOOLEAN value
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_set_pending_nmi(
    GUEST_CPU_HANDLE        gcpu,
    BOOLEAN                 value);

#ifdef INCLUDE_UNUSED_CODE
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_get_pending_nmi
*  PURPOSE  : Get NMI pending state
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : BOOLEAN - TRUE if NMI is pended
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_get_pending_nmi(GUEST_CPU_HANDLE gcpu);
#endif

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_vmexit_exception_resolve
*  PURPOSE  : Called if exception, caused VMEXIT was resolved by VMM code
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_vmexit_exception_resolve(GUEST_CPU_HANDLE gcpu);

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_vmexit_exception_reflect
*  PURPOSE  : Reflect exception to guest.
*           : Called if exception, caused VMEXIT was caused by Guest SW
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_vmexit_exception_reflect(GUEST_CPU_HANDLE gcpu);

#ifdef ENABLE_VTLB
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_update_current_exception_error_code
*  PURPOSE  : Changes exception error code in current (merged) VMCS,
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*             error_code - new error code
*-----------------------------------------------------------------------------*/
void gcpu_update_current_exception_error_code(
    GUEST_CPU_HANDLE    gcpu,
    UINT32 error_code);
#endif

#ifdef VMCALL_NOT_ALLOWED_FROM_RING_1_TO_3
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_invalid_opcode_exception
*  PURPOSE  : Inject invalid opcode exception
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE if event was not injected.
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_invalid_opcode_exception(GUEST_CPU_HANDLE    gcpu);
#endif

#define gcpu_inject_ts(gcpu, code) \
    gcpu_inject_fault( \
        gcpu, \
        (int)IA32_EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR, \
        code \
        );

#define gcpu_inject_ss(gcpu, code) \
    gcpu_inject_fault( \
        gcpu, \
        (int)IA32_EXCEPTION_VECTOR_STACK_SEGMENT_FAULT, \
        code \
        );

#define gcpu_inject_np(gcpu, code) \
    gcpu_inject_fault( \
        gcpu, \
        (int)IA32_EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT, \
        code \
        );

#define gcpu_inject_db(gcpu) \
    gcpu_inject_fault( \
        gcpu, \
        (int)IA32_EXCEPTION_VECTOR_DEBUG_BREAKPOINT, \
        0 \
        );

#endif // _GUEST_CPU_VMENTER_EVENT_H_

