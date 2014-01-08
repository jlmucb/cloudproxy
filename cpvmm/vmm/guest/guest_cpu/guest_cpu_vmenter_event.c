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

#include "vmm_defs.h"
#include "vmcs_actual.h"
#include "vmx_ctrl_msrs.h"
#include "guest_cpu.h"
#include "guest_cpu_internal.h"
#include "scheduler.h"
#include "isr.h"
#include "guest_cpu_vmenter_event.h"
#include "vmm_dbg.h"
#include "libc.h"
#include "ipc.h"
#include "file_codes.h"
#include "vmm_callback.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_CPU_VMENTER_EVENT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_CPU_VMENTER_EVENT_C, __condition)

/*----------------------- Local Types and Variables --------------------------*/
/*
#define PRINT_GCPU_IDENTITY(__gcpu)                                            \
VMM_DEBUG_CODE(                                                                \
{                                                                              \
    const VIRTUAL_CPU_ID * __vcpuid = guest_vcpu(__gcpu);                      \
                                                                               \
    VMM_LOG(mask_anonymous, level_trace,"CPU(%d) Guest(%d) GuestCPU(%d)",                                 \
        hw_cpu_id(),                                                           \
        __vcpuid->guest_id,                                                    \
        __vcpuid->guest_cpu_id);                                              \
                                                                               \
}                                                                              \
)                                                                              \
*/
typedef enum {
    EXCEPTION_CLASS_BENIGN          = 0,
    EXCEPTION_CLASS_CONTRIBUTORY    = 1,
    EXCEPTION_CLASS_PAGE_FAULT      = 2,
    EXCEPTION_CLASS_TRIPLE_FAULT    = 3
} EXCEPTION_CLASS;

typedef enum {
    INJECT_2ND_EXCEPTION,
    INJECT_DOUBLE_FAULT,
    TEAR_DOWN_GUEST
} IDT_RESOLUTION_ACTION;


static IDT_RESOLUTION_ACTION idt_resolution_table[4][4] =
{
    { INJECT_2ND_EXCEPTION, INJECT_2ND_EXCEPTION, INJECT_2ND_EXCEPTION, TEAR_DOWN_GUEST },
    { INJECT_2ND_EXCEPTION, INJECT_DOUBLE_FAULT , INJECT_2ND_EXCEPTION, TEAR_DOWN_GUEST },
    { INJECT_2ND_EXCEPTION, INJECT_DOUBLE_FAULT , INJECT_DOUBLE_FAULT , TEAR_DOWN_GUEST },
    { TEAR_DOWN_GUEST     , TEAR_DOWN_GUEST     , TEAR_DOWN_GUEST     , TEAR_DOWN_GUEST }
};

/*-------------- Forward declarations for local functions --------------------*/

static EXCEPTION_CLASS vector_to_exception_class(VECTOR_ID vector_id
    );
static void gcpu_reinject_idt_exception(
    GUEST_CPU_HANDLE                            gcpu,
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info
    );
static void gcpu_reinject_vmexit_exception(
    GUEST_CPU_HANDLE                            gcpu,
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO   vmexit_exception_info
    );


INLINE void copy_exception_to_vmenter_exception(
    IA32_VMX_VMCS_VM_ENTER_INTERRUPT_INFO * vmenter_exception,
    UINT32 source_exception)
{
    vmenter_exception->Uint32 = source_exception;
    vmenter_exception->Bits.Reserved = 0;
}

/*------------------------------- Code Starts Here ---------------------------*/


#ifdef INCLUDE_UNUSED_CODE
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_nmi_injection_allowed
*  PURPOSE  : Checks if NMI injection is allowed for the guest CPU
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event injection allowed
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_nmi_injection_allowed(
    const GUEST_CPU_HANDLE gcpu)
{
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;
    BOOLEAN                                     injection_allowed = TRUE;
    VMCS_OBJECT                                 *vmcs;

    VMM_ASSERT(gcpu);
    VMM_ASSERT(0 == GET_EXCEPTION_RESOLUTION_REQUIRED_FLAG(gcpu));

    vmcs = gcpu_get_vmcs(gcpu);

    idt_vectoring_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_IDT_VECTORING);

    if (1 == idt_vectoring_info.Bits.Valid)
    {
        injection_allowed = FALSE;
    }
    else
    {
        IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY guest_interruptibility;
        guest_interruptibility.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_GUEST_INTERRUPTIBILITY);

        if (1 == guest_interruptibility.Bits.BlockNmi       ||
            1 == guest_interruptibility.Bits.BlockStackSegment)
        {
            injection_allowed = FALSE;
        }
    }
    return injection_allowed;
}
#endif

#ifdef ENABLE_VTLB
void gcpu_update_current_exception_error_code(
    GUEST_CPU_HANDLE    gcpu,
    UINT32 error_code)
{
    VMCS_HIERARCHY* vmcs_hierarchy =  gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_MERGED);

    vmcs_write_nocheck(vmcs, VMCS_EXIT_INFO_EXCEPTION_ERROR_CODE, error_code);
}
#endif



/*-----------------------------------------------------------------------------*
*  FUNCTION : vmentry_inject_event
*  PURPOSE  : Inject interrupt/exception into guest if allowed, otherwise
*           : set NMI/Interrupt window
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*           : VMENTER_EVENT  *p_event, function assumes valid input,
*  RETURNS  : TRUE if event was injected, FALSE
*  NOTES    : no checkings are done for event validity
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_event(
    GUEST_CPU_HANDLE    gcpu,
    VMENTER_EVENT      *p_event)
{
    VMCS_OBJECT                                 *vmcs;
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;
    BOOLEAN                                     injection_allowed = TRUE;
    const VIRTUAL_CPU_ID                        *vcpuid;

    VMM_ASSERT(gcpu);
    VMM_ASSERT(0 == GET_EXCEPTION_RESOLUTION_REQUIRED_FLAG(gcpu));

    vmcs = gcpu_get_vmcs(gcpu);
    idt_vectoring_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_IDT_VECTORING);

    if (1 == idt_vectoring_info.Bits.Valid)
    {
        injection_allowed = FALSE;
    }
    else
    {
        IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY guest_interruptibility;
        guest_interruptibility.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_GUEST_INTERRUPTIBILITY);

        switch (p_event->interrupt_info.Bits.InterruptType)
        {
        case VmEnterInterruptTypeExternalInterrupt:
            if (1 == guest_interruptibility.Bits.BlockNextInstruction ||
                1 == guest_interruptibility.Bits.BlockStackSegment)
            {
                injection_allowed = FALSE;
            }
            break;

        case VmEnterInterruptTypeNmi:
            if (1 == guest_interruptibility.Bits.BlockNmi       ||
                1 == guest_interruptibility.Bits.BlockStackSegment)
            {
                injection_allowed = FALSE;
            }
            break;

        case VmEnterInterruptTypeHardwareException:
        case VmEnterInterruptTypeSoftwareInterrupt:
        case VmEnterInterruptTypePrivilegedSoftwareInterrupt:
        case VmEnterInterruptTypeSoftwareException:
            if (1 == guest_interruptibility.Bits.BlockStackSegment)
            {
                if (IA32_EXCEPTION_VECTOR_BREAKPOINT       == p_event->interrupt_info.Bits.Vector ||
                    IA32_EXCEPTION_VECTOR_DEBUG_BREAKPOINT == p_event->interrupt_info.Bits.Vector)
                {
                    injection_allowed = FALSE;
                }
            }

            break;

        default:
            VMM_LOG(mask_anonymous, level_trace,"Invalid VmEnterInterruptType(%d)\n", p_event->interrupt_info.Bits.InterruptType);
            VMM_DEADLOOP();
            break;
        }

    }


    if (TRUE == injection_allowed)
    {
        p_event->interrupt_info.Bits.DeliverCode = 0;   // to be on safe side

        switch (p_event->interrupt_info.Bits.InterruptType)
        {
        case VmEnterInterruptTypeSoftwareInterrupt:
        case VmEnterInterruptTypePrivilegedSoftwareInterrupt:
        case VmEnterInterruptTypeSoftwareException:
            //
            // Write the Instruction Length field if this is any type of software interrupt
            //
            vmcs_write(vmcs, VMCS_ENTER_INSTRUCTION_LENGTH, (UINT64) p_event->instruction_length);
            break;

        case VmEnterInterruptTypeHardwareException:

            if (TRUE == isr_error_code_required((VECTOR_ID) p_event->interrupt_info.Bits.Vector))
            {
                vmcs_write(vmcs, VMCS_ENTER_EXCEPTION_ERROR_CODE, (UINT64 )p_event->error_code);
                p_event->interrupt_info.Bits.DeliverCode = 1;
            }
            break;

        case VmEnterInterruptTypeNmi: 		
            // VNMI Support- create an event so VNMI handler can handle it.
            vcpuid = guest_vcpu(gcpu);
            VMM_ASSERT(vcpuid);
            report_uvmm_event(UVMM_EVENT_NMI, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)vcpuid, NULL);
            break;

        default:
            break;
        }

        // to be on a safe side
        p_event->interrupt_info.Bits.Valid      = 1;
        p_event->interrupt_info.Bits.Reserved   = 0;

        vmcs_write(vmcs, VMCS_ENTER_INTERRUPT_INFO, (UINT64) (p_event->interrupt_info.Uint32));
    }
    else
    {
        // there are conditions which prevent injection of new event,
        // therefore NMI/interrupt window is established

        if (VmEnterInterruptTypeNmi == p_event->interrupt_info.Bits.InterruptType)
        {
            // NMI event cannot be injected, so set NMI-windowing
            gcpu_set_pending_nmi(gcpu, TRUE);   // vmcs_write_nmi_window_bit(vmcs, TRUE);

            // notify IPC component about inability to inject NMI
            ipc_mni_injection_failed();
        }
        else
        {
            // interrupt/exception cannot be injected, set interrupt-windowing
            gcpu_temp_exceptions_setup( gcpu, GCPU_TEMP_EXIT_ON_INTR_UNBLOCK );
        }
    }

    return injection_allowed;
}

#ifdef INCLUDE_UNUSED_CODE
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_native_pf
*  PURPOSE  : Inject native PF
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*           : UINT64 pf_address - gva
*           : UINT64 pfec - error code
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_native_pf(GUEST_CPU_HANDLE    gcpu,
                              UINT64 pf_address,
                              UINT64 pfec)
{
    VMENTER_EVENT pf_exception;
    VMCS_OBJECT *vmcs       = gcpu_get_vmcs(gcpu);


    VMM_ASSERT(gcpu);

    vmm_memset( &pf_exception, 0, sizeof(pf_exception) );
    gcpu_set_control_reg(gcpu, IA32_CTRL_CR2, pf_address);

    pf_exception.interrupt_info.Bits.Valid         = 1;
    pf_exception.interrupt_info.Bits.Vector        = IA32_EXCEPTION_VECTOR_PAGE_FAULT;
    pf_exception.interrupt_info.Bits.InterruptType = VmEnterInterruptTypeHardwareException;
    pf_exception.interrupt_info.Bits.DeliverCode   = 1;
    pf_exception.instruction_length                = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);
    pf_exception.error_code                        = pfec;

    return gcpu_inject_event(gcpu, &pf_exception);
}
#endif

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_gp0
*  PURPOSE  : Inject GP with error code 0
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_gp0(
    GUEST_CPU_HANDLE    gcpu)
{
    VMENTER_EVENT gp_exception;
    VMCS_OBJECT   *vmcs;

    VMM_ASSERT(gcpu);

    vmm_memset( &gp_exception, 0, sizeof(gp_exception) );

    vmcs = gcpu_get_vmcs(gcpu);

    gp_exception.interrupt_info.Bits.Valid         = 1;
    gp_exception.interrupt_info.Bits.Vector        = IA32_EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT;
    gp_exception.interrupt_info.Bits.InterruptType = VmEnterInterruptTypeHardwareException;
    gp_exception.interrupt_info.Bits.DeliverCode   = 1;
    gp_exception.instruction_length                = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);
    gp_exception.error_code                        = 0;

    return gcpu_inject_event(gcpu, &gp_exception);
}

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_fault
*  PURPOSE  : Inject a fault to guest CPU
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
              int vec               - fault vector
              UINT32 code           - error code pushed on guest stack
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_fault(
    GUEST_CPU_HANDLE gcpu,
    int vec,
    UINT32 code)
{
    VMCS_OBJECT *vmcs;
    VMENTER_EVENT e;

    VMM_ASSERT(gcpu);
    vmcs = gcpu_get_vmcs(gcpu);

    vmm_memset(&e, 0, sizeof(e));

    e.interrupt_info.Bits.Valid = 1;
    e.interrupt_info.Bits.Vector = vec;

    e.interrupt_info.Bits.InterruptType = 
        VmEnterInterruptTypeHardwareException;

    e.instruction_length = 
        (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);

    if (vec != IA32_EXCEPTION_VECTOR_DEBUG_BREAKPOINT)
    {
        e.interrupt_info.Bits.DeliverCode = 1;
        e.error_code = code;
    }

    if (vec == IA32_EXCEPTION_VECTOR_VIRTUAL_EXCEPTION) {
        e.interrupt_info.Bits.DeliverCode = 0;	// no error code
        e.interrupt_info.Bits.Reserved = 0;
    }

    return gcpu_inject_event(gcpu, &e);
}

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_nmi
*  PURPOSE  : Inject NMI into guest if allowed, otherwise set NMI window
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_nmi(
    GUEST_CPU_HANDLE    gcpu)
{
    VMENTER_EVENT nmi_event;

    VMM_ASSERT(gcpu);

    vmm_memset( &nmi_event, 0, sizeof(nmi_event) );

    nmi_event.interrupt_info.Bits.Valid           = 1;
    nmi_event.interrupt_info.Bits.Vector          = IA32_EXCEPTION_VECTOR_NMI;
    nmi_event.interrupt_info.Bits.InterruptType   = VmEnterInterruptTypeNmi;
    nmi_event.interrupt_info.Bits.DeliverCode     = 0;    // no error code delivered
    return gcpu_inject_event(gcpu, &nmi_event);
}

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
    VECTOR_ID       vector_id)
{
    VMENTER_EVENT interrupt_event;

    VMM_ASSERT(gcpu);

    vmm_memset( &interrupt_event, 0, sizeof(interrupt_event) );

    interrupt_event.interrupt_info.Bits.Valid          = 1;
    interrupt_event.interrupt_info.Bits.Vector         = vector_id;
    interrupt_event.interrupt_info.Bits.InterruptType  = VmEnterInterruptTypeExternalInterrupt;
    interrupt_event.interrupt_info.Bits.DeliverCode    = 0;    // no error code delivered
    return gcpu_inject_event(gcpu, &interrupt_event);
}
#endif

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_double_fault
*  PURPOSE  : Inject Double Fault exception into guest if allowed,
*           :  otherwise set Interruption window
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_double_fault(
    GUEST_CPU_HANDLE    gcpu)
{
    VMENTER_EVENT double_fault_event;

    VMM_ASSERT(gcpu);

    vmm_memset( &double_fault_event, 0, sizeof( double_fault_event ) );

    double_fault_event.interrupt_info.Bits.Valid            = 1;
    double_fault_event.interrupt_info.Bits.Vector           = IA32_EXCEPTION_VECTOR_DOUBLE_FAULT;
    double_fault_event.interrupt_info.Bits.InterruptType    = VmEnterInterruptTypeHardwareException;
    double_fault_event.interrupt_info.Bits.DeliverCode      = 1;
    double_fault_event.error_code                           = 0;

    return gcpu_inject_event(gcpu, &double_fault_event);
}



/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_set_pending_nmi
*  PURPOSE  : Cause NMI VMEXIT be invoked immediately when NMI blocking finished
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*           : BOOLEAN value
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_set_pending_nmi(
    GUEST_CPU_HANDLE        gcpu,
    BOOLEAN                 value)
{
    VMCS_OBJECT   *vmcs;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    // same for native and under emulator
    VMM_ASSERT(gcpu);

    vmcs = gcpu_get_vmcs(gcpu);
    vmcs_write_nmi_window_bit(vmcs, value);
}

#ifdef INCLUDE_UNUSED_CODE
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_get_pending_nmi
*  PURPOSE  : Get NMI pending state
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : BOOLEAN - TRUE if NMI is pended
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_get_pending_nmi(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT   *vmcs;

    // same for native and under emulator
    VMM_ASSERT(gcpu);

    vmcs = gcpu_get_vmcs(gcpu);
    return vmcs_read_nmi_window_bit(vmcs);
}
#endif

/*-----------------------------------------------------------------------------*
*  FUNCTION : vector_to_exception_class
*  PURPOSE  : Translate vector ID to exception "co-existence" class
*  ARGUMENTS: VECTOR_ID vector_id
*  RETURNS  : EXCEPTION_CLASS
*-----------------------------------------------------------------------------*/
EXCEPTION_CLASS vector_to_exception_class(
    VECTOR_ID vector_id)
{
    EXCEPTION_CLASS ex_class;

    switch (vector_id)
    {
    case IA32_EXCEPTION_VECTOR_PAGE_FAULT:
        ex_class = EXCEPTION_CLASS_PAGE_FAULT;
        break;

    case IA32_EXCEPTION_VECTOR_DIVIDE_ERROR:
    case IA32_EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR:
    case IA32_EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT:
    case IA32_EXCEPTION_VECTOR_STACK_SEGMENT_FAULT:
    case IA32_EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT:
        ex_class = EXCEPTION_CLASS_CONTRIBUTORY;
        break;

    case IA32_EXCEPTION_VECTOR_DOUBLE_FAULT:

        VMM_LOG(mask_anonymous, level_trace,"FATAL ERROR: Tripple Fault Occured\n");
        ex_class = EXCEPTION_CLASS_TRIPLE_FAULT; // have to tear down the guest
        VMM_DEADLOOP();
        break;

    default:
        ex_class = EXCEPTION_CLASS_BENIGN;
        break;
    }
    return ex_class;
}


/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_reinject_vmexit_exception
*  PURPOSE  : Reinject VMEXIT exception and optionally errcode, instruction length
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU . Argument is assumed valid.
*             Caller function validates.
*           : IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO   vmexit_exception_info
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_reinject_vmexit_exception(
    GUEST_CPU_HANDLE                            gcpu,
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO   vmexit_exception_info)
{
    VMENTER_EVENT event;
    VMCS_OBJECT   *vmcs = gcpu_get_vmcs(gcpu);

    copy_exception_to_vmenter_exception(&event.interrupt_info, vmexit_exception_info.Uint32);

    // some exceptions require error code
    if (vmexit_exception_info.Bits.ErrorCodeValid)
    {
        event.error_code = vmcs_read(vmcs, VMCS_EXIT_INFO_EXCEPTION_ERROR_CODE);
    }

    if (VmExitInterruptTypeSoftwareException == vmexit_exception_info.Bits.InterruptType)
    {
        event.instruction_length = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);
    }

    gcpu_inject_event(gcpu, &event);

}


/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_reinject_idt_exception
*  PURPOSE  : Reinject IDT Vectoring exception and optionally errcode, instruction length
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*           : IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING idt_vectoring_info
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_reinject_idt_exception(
    GUEST_CPU_HANDLE                            gcpu,
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info)
{
    VMENTER_EVENT event;
    VMCS_OBJECT   *vmcs = gcpu_get_vmcs(gcpu);

    // re-inject the event, by copying IDT vectoring info into VMENTER
    copy_exception_to_vmenter_exception(&event.interrupt_info, idt_vectoring_info.Uint32);

    // some exceptions require error code
    if (idt_vectoring_info.Bits.ErrorCodeValid)
    {
        event.error_code = vmcs_read(vmcs, VMCS_EXIT_INFO_IDT_VECTORING_ERROR_CODE);
    }

    // SW exceptions and interrupts require instruction length to be injected
    switch (idt_vectoring_info.Bits.InterruptType)
    {
    case IdtVectoringInterruptTypeSoftwareInterrupt:
    case IdtVectoringInterruptTypeSoftwareException:
    case IdtVectoringInterruptTypePrivilegedSoftwareInterrupt:
        event.instruction_length = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);
        break;
    default:
        break;
    }

    // clear IDT valid, so we can re-inject the event
    vmcs_write(vmcs, VMCS_EXIT_INFO_IDT_VECTORING, 0);

    // finally inject the event
    gcpu_inject_event(gcpu, &event);
}

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_vmexit_exception_resolve
*  PURPOSE  : Called if exception, caused VMEXIT was resolved by VMM code
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_vmexit_exception_resolve(
    GUEST_CPU_HANDLE gcpu)
{
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;
    VMCS_OBJECT                                 *vmcs;

    VMM_ASSERT(gcpu);

    vmcs = gcpu_get_vmcs(gcpu);

    CLR_EXCEPTION_RESOLUTION_REQUIRED_FLAG(gcpu);

    idt_vectoring_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_IDT_VECTORING);
    if (1 == idt_vectoring_info.Bits.Valid)
    {
        gcpu_reinject_idt_exception(gcpu, idt_vectoring_info);
    }
    else
    {
        IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO   vmexit_exception_info;

        vmexit_exception_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO);
        if (vmexit_exception_info.Bits.Valid                  == 1 &&
            vmexit_exception_info.Bits.NmiUnblockingDueToIret == 1 &&
            vmexit_exception_info.Bits.Vector                 != IA32_EXCEPTION_VECTOR_DOUBLE_FAULT)
        {
            IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY guest_interruptibility;
            guest_interruptibility.Uint32 = 0;
            guest_interruptibility.Bits.BlockNmi = 1;
            vmcs_update(
                vmcs,
                VMCS_GUEST_INTERRUPTIBILITY,
                (UINT64) guest_interruptibility.Uint32,
                (UINT64) guest_interruptibility.Uint32);
        }
    }
}


/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_vmexit_exception_reflect
*  PURPOSE  : Reflect exception to guest.
*           : Called if exception, caused VMEXIT was caused by Guest SW
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void gcpu_vmexit_exception_reflect(
    GUEST_CPU_HANDLE gcpu)
{
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;     // 1st exception
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO   vmexit_exception_info;  // 2nd exception
    EXCEPTION_CLASS                             exception1_class;
    EXCEPTION_CLASS                             exception2_class;
    IDT_RESOLUTION_ACTION                       action;
    VMCS_OBJECT                                 *vmcs;
    BOOLEAN                                     inject_exception = FALSE;

    VMM_ASSERT(gcpu);

    vmcs = gcpu_get_vmcs(gcpu);

    CLR_EXCEPTION_RESOLUTION_REQUIRED_FLAG(gcpu);

    idt_vectoring_info.Uint32   = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_IDT_VECTORING);
    vmexit_exception_info.Uint32= (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO);

    if (1 == idt_vectoring_info.Bits.Valid)
    {
        exception1_class = vector_to_exception_class((VECTOR_ID) idt_vectoring_info.Bits.Vector);
        exception2_class = vector_to_exception_class((VECTOR_ID) vmexit_exception_info.Bits.Vector);

        action = idt_resolution_table[exception1_class][exception2_class];

        // clear IDT valid, for we can re-inject the event
        vmcs_write(vmcs, VMCS_EXIT_INFO_IDT_VECTORING, 0);

        switch (action)
        {
        case INJECT_2ND_EXCEPTION:
            // inject 2nd exception, by copying VMEXIT exception info into VMENTER
            inject_exception = TRUE;
            break;
        case INJECT_DOUBLE_FAULT:
            gcpu_inject_double_fault(gcpu);
            break;
        case TEAR_DOWN_GUEST:
            // TBD
            VMM_LOG(mask_anonymous, level_trace,"Triple Fault occured. Tear down Guest CPU ");
            PRINT_GCPU_IDENTITY(gcpu);
            VMM_LOG(mask_anonymous, level_trace,"\n");
            break;
        }
    }
    else
    {
        inject_exception = TRUE;
    }

    if (inject_exception) {
        if (vmexit_exception_info.Bits.Vector == IA32_EXCEPTION_VECTOR_PAGE_FAULT) {
            // CR2 information resides in qualification
            IA32_VMX_EXIT_QUALIFICATION qualification;
            qualification.Uint64 = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
            gcpu_set_control_reg(gcpu, IA32_CTRL_CR2, qualification.PageFault.Address);
        }

        // re-inject the event, by copying VMEXIT exception info into VMENTER
        gcpu_reinject_vmexit_exception(gcpu, vmexit_exception_info);
    }
}

/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_inject_invalid_opcode_exception
*  PURPOSE  : Inject invalid opcode exception
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if event was injected, FALSE if event was not injected.
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_inject_invalid_opcode_exception(GUEST_CPU_HANDLE    gcpu)
{
    VMENTER_EVENT ud_exception;
    EM64T_RFLAGS    rflags;
    BOOLEAN inject_allowed;

    VMM_ASSERT(gcpu);

    vmm_memset( &ud_exception, 0, sizeof(ud_exception) );

    ud_exception.interrupt_info.Bits.Valid         = 1;
    ud_exception.interrupt_info.Bits.Vector        = IA32_EXCEPTION_VECTOR_UNDEFINED_OPCODE;
    ud_exception.interrupt_info.Bits.InterruptType = VmEnterInterruptTypeHardwareException;
    ud_exception.interrupt_info.Bits.DeliverCode   = 0;
    ud_exception.instruction_length                = 0;
    ud_exception.error_code                        = 0;

    inject_allowed = gcpu_inject_event(gcpu, &ud_exception);
    if (inject_allowed)
    {
         rflags.Uint64 = gcpu_get_native_gp_reg(gcpu, IA32_REG_RFLAGS);
         rflags.Bits.RF = 1;
         gcpu_set_native_gp_reg(gcpu, IA32_REG_RFLAGS, rflags.Uint64);
    }
    return inject_allowed;
}

#if 0
// This function is obsolete, it checks VMEnter information for GP, in order to
// identify the situation whether VTLB has injected GPF0 exception, in the scheme
// VTLB doesn't inject anything
/*-----------------------------------------------------------------------------*
*  FUNCTION : gcpu_general_protection_fault_detected
*  PURPOSE  : Check if GPF was detected on given guest CPU.
*             Used for CR write handling: after CR write is handled by addons,
*             if one of them detected GPF, no update to CR is made.
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu - guest CPU
*  RETURNS  : TRUE if GPF was dected, otherwise - false
*-----------------------------------------------------------------------------*/
BOOLEAN gcpu_general_protection_fault_detected(
    GUEST_CPU_HANDLE gcpu)
{
    IA32_VMX_VMCS_VM_ENTER_INTERRUPT_INFO   interrupt_info;
    VMCS_OBJECT                             *vmcs = NULL;

    VMM_ASSERT(gcpu);

    vmcs = gcpu_get_vmcs(gcpu);
    interrupt_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_ENTER_INTERRUPT_INFO);

    return (interrupt_info.Bits.Valid
            && interrupt_info.Bits.Vector == IA32_EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT
            && interrupt_info.Bits.InterruptType == VmEnterInterruptTypeHardwareException
            && interrupt_info.Bits.DeliverCode  == 1);
}
#endif
