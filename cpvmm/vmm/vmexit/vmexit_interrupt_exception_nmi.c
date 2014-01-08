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
//#include "vmcs_object.h"
#include "vmcs_api.h"
#include "guest_cpu.h"
#include "isr.h"
#include "vmexit.h"
#include "emulator_if.h"
#include "hw_utils.h"
#include "ipc.h"
#include "guest_cpu_vmenter_event.h"
#include "em64t_defs.h"
#include "vmm_events_data.h"
#include "vmdb.h"
#include "vmx_ctrl_msrs.h"
#include "vmx_nmi.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_INTERRUPT_EXCEPTION_NMI_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_INTERRUPT_EXCEPTION_NMI_C, __condition)

VMEXIT_HANDLING_STATUS vmexit_nmi_window(GUEST_CPU_HANDLE gcpu);
static VMEXIT_HANDLING_STATUS vmexit_software_interrupt_exception_nmi(GUEST_CPU_HANDLE gcpu);

static
BOOLEAN page_fault( GUEST_CPU_HANDLE gcpu, VMCS_OBJECT* vmcs )
{
    IA32_VMX_EXIT_QUALIFICATION qualification;
    EVENT_GCPU_PAGE_FAULT_DATA  data;

    qualification.Uint64 = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    vmm_memset(&data, 0, sizeof(data));
    data.pf_address = qualification.PageFault.Address;
    data.pf_error_code = vmcs_read(vmcs, VMCS_EXIT_INFO_EXCEPTION_ERROR_CODE);
    data.pf_processed = FALSE;

    event_raise( EVENT_GCPU_PAGE_FAULT, gcpu, &data );

    // TODO: move resolution to common handler
    if (data.pf_processed) {
        gcpu_vmexit_exception_resolve(gcpu);
    }

    // Return FALSE in case when VTLB recognized as NATIVE and in case there is no event hander registered
    return data.pf_processed;
}


void vmexit_nmi_exception_handlers_install(GUEST_ID guest_id)
{
    vmexit_install_handler(
        guest_id,
        vmexit_software_interrupt_exception_nmi,
        Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi);


    vmexit_install_handler(
        guest_id,
        nmi_window_vmexit_handler,
        Ia32VmxExitNmiWindow);
}

void check_and_set_nmi_blocking(VMCS_OBJECT *vmcs)
{
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO   vmexit_exception_info;
    IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY guest_interruptibility;

    idt_vectoring_info.Uint32 = (UINT32)vmcs_read(vmcs,VMCS_EXIT_INFO_IDT_VECTORING);
    vmexit_exception_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO);
		
    if(idt_vectoring_info.Bits.Valid || !vmexit_exception_info.Bits.Valid
            || !vmexit_exception_info.Bits.NmiUnblockingDueToIret )
            return;

    if( (vmexit_exception_info.Bits.InterruptType == VmExitInterruptTypeException) &&
            (vmexit_exception_info.Bits.Vector == IA32_EXCEPTION_VECTOR_DOUBLE_FAULT) )
            return;

    guest_interruptibility.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_GUEST_INTERRUPTIBILITY);
    guest_interruptibility.Bits.BlockNmi = 1;
    vmcs_write(vmcs,VMCS_GUEST_INTERRUPTIBILITY,(UINT64)guest_interruptibility.Uint32);
}

VMEXIT_HANDLING_STATUS vmexit_software_interrupt_exception_nmi(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT                              *vmcs = gcpu_get_vmcs(gcpu);
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO vmexit_exception_info;
    BOOLEAN unsupported_exception = FALSE;
    BOOLEAN handled_exception = TRUE;

    vmexit_exception_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO);

    // no exceptions allowed under emulator
    VMM_ASSERT( (VmExitInterruptTypeException != vmexit_exception_info.Bits.InterruptType) ||
                (TRUE == gcpu_is_native_execution( gcpu )));

    check_and_set_nmi_blocking(vmcs);

    switch (vmexit_exception_info.Bits.InterruptType)
    {
    case VmExitInterruptTypeException:
        switch (vmexit_exception_info.Bits.Vector)
        {
        case IA32_EXCEPTION_VECTOR_MACHINE_CHECK:
            // VmmHandleMachineCheckException(gcpu);    // TBD
            unsupported_exception = TRUE;
            break;

        case IA32_EXCEPTION_VECTOR_DEBUG_BREAKPOINT:
            handled_exception = vmdb_exception_handler(gcpu);
            break;

        case IA32_EXCEPTION_VECTOR_PAGE_FAULT:
            // flat page tables support
            {
                EM64T_CR0 cr0;
                cr0.Uint64 = gcpu_get_guest_visible_control_reg( gcpu, IA32_CTRL_CR0 );

#ifdef ENABLE_EMULATOR
                if (cr0.Bits.PG == 0)
                {
                    // page fault without paging in guest ? it's our
                    gcpu_perform_single_step( gcpu );
                    handled_exception = TRUE;
                }
                else
#endif
                {
                    handled_exception = page_fault(gcpu, vmcs);
                    //unsupported_exception = (FALSE == page_fault(gcpu, vmcs));
                }
            }
            break;

        default: // unsupported exception
            //unsupported_exception = TRUE;
            handled_exception = FALSE;
            break;
        }
        break;

    case VmExitInterruptTypeNmi:
        // call NMI handler
        handled_exception = nmi_vmexit_handler(gcpu);
        break;

    default:
        unsupported_exception = TRUE;
        break;
    }


    if (TRUE == unsupported_exception)
    {
        VMM_LOG(mask_anonymous, level_trace,"Unsupported interrupt/exception (%d) in ", vmexit_exception_info.Bits.Vector);
        PRINT_GCPU_IDENTITY(gcpu);
        VMM_LOG(mask_anonymous, level_trace," Running %s emulator\n", emulator_is_running_as_guest() ? "inside" : "outside");
        VMM_DEADLOOP();
    }

    return handled_exception ? VMEXIT_HANDLED : VMEXIT_NOT_HANDLED;
}

static
void vmexit_change_exit_reason_from_nmi_window_to_nmi(GUEST_CPU_HANDLE gcpu) {
    VMCS_HIERARCHY* hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_MERGED);
    IA32_VMX_EXIT_REASON reason;
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO vmexit_exception_info;

    // Change reason
    reason.Uint32 = (UINT32)vmcs_read(merged_vmcs, VMCS_EXIT_INFO_REASON);
    reason.Bits.BasicReason = Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi;
    VMM_LOG(mask_anonymous, level_trace,"%s: Updaing VMExit reason to %d\n", __FUNCTION__, reason.Bits.BasicReason);
    vmcs_write_nocheck(merged_vmcs, VMCS_EXIT_INFO_REASON, reason.Uint32);
    VMM_ASSERT((UINT32)vmcs_read(merged_vmcs, VMCS_EXIT_INFO_REASON) == reason.Uint32);

    // Change exception info
    vmexit_exception_info.Uint32 = 0;
    vmexit_exception_info.Bits.Vector = IA32_EXCEPTION_VECTOR_NMI;
    vmexit_exception_info.Bits.InterruptType = VmExitInterruptTypeNmi;
    vmexit_exception_info.Bits.Valid = 1;
    vmcs_write_nocheck(merged_vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO, vmexit_exception_info.Uint32);
}

VMEXIT_HANDLING_STATUS vmexit_nmi_window(GUEST_CPU_HANDLE gcpu)
{
    BOOLEAN handled = ipc_nmi_window_vmexit_handler(gcpu);

    if (handled) {
        return VMEXIT_HANDLED;
    }

    VMM_DEADLOOP();


    // Check the case when level-1 vmm requested NMI-Window exiting
    if (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_2) {
        VMCS_HIERARCHY* hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
        VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_1);
        PROCESSOR_BASED_VM_EXECUTION_CONTROLS ctrls;

        ctrls.Uint32 = (UINT32)vmcs_read(level1_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
        if (ctrls.Bits.NmiWindow) {
            // Level1 requested NMI Window vmexit, don't change anything in vmexit information.
            return VMEXIT_NOT_HANDLED;
        }
    }

    // In all other cases, change event to NMI
    vmexit_change_exit_reason_from_nmi_window_to_nmi(gcpu);

    return VMEXIT_NOT_HANDLED;
}

