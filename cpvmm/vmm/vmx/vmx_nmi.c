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

#include "file_codes.h"
// need these defines for guest.h -> array_iterators.h
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMX_NMI_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMX_NMI_C, __condition)
#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "common_libc.h"
#include "memory_allocator.h"
#include "hw_utils.h"
#include "isr.h"
#include "vmm_objects.h"
#include "guest.h"
#include "guest_cpu.h"
#include "guest_cpu_vmenter_event.h"
#include "ipc.h"
#include "vmexit.h"
#include "vmx_ctrl_msrs.h"
#include "vmx_nmi.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


/*
+---------+---------+---------+---------+---------------+-----------+
|  input  |  input  |  input  |output   |     output    |  output   |
+---------+---------+---------+---------+---------------+-----------+
|         |         | X-lated |X-lated  |               |           |
| Reason  | Platform| Reason  |reason   | Local Action  |Deliver to |
|         |   NMI   |         |requested|               | upper VMM |
|         |         |         |by Lvl-1 |               |           |
+---------+---------+---------+---------+---------------+-----------+
|   NMI   |   No    |No reason|   N/A   |    Dismiss    |     No    |
+---------+---------+---------+---------+---------------+-----------+
|   NMI   |   Yes   |   NMI   |   No    |Inject to guest|     No    |
+---------+---------+---------+---------+---------------+-----------+
|   NMI   |   Yes   |   NMI   |   Yes   |Emulate x-lated|     Yes   |
|         |         |         |         |vmexit to lvl-1|           |
+---------+---------+---------+---------+---------------+-----------+
| NMI-Win |   No    | NMI-Win |   No    |    Dismiss    |     No    |
+---------+---------+---------+---------+---------------+-----------+
| NMI-Win |   No    | NMI-Win |   Yes   |Emulate x-lated|     Yes   |
|         |         |         |         |vmexit to lvl-1|           |
+---------+---------+---------+---------+---------------+-----------+
| NMI-Win |   Yes   |   NMI   |   No    |Inject to guest|     Yes   |
+---------+---------+---------+---------+---------------+-----------+
| NMI-Win |   Yes   |   NMI   |   Yes   |Emulate x-lated|     Yes   |
|         |         |         |         |vmexit to lvl-1|           |
+---------+---------+---------+---------+---------------+-----------+
*/



#define XLAT_NMI_VMEXIT_REASON(__nmi_exists) (__nmi_exists) ?                  \
    Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi :                      \
    Ia32VmxExitBasicReasonCount

#define XLAT_NMI_WINDOW_VMEXIT_REASON(__nmi_exists) (__nmi_exists) ?           \
    Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi :                      \
    Ia32VmxExitNmiWindow

#define NMI_EXISTS_ON_GCPU(__gcpu)                                             \
    nmi_is_pending_this() && guest_is_nmi_owner(gcpu_guest_handle(__gcpu))


#ifdef LEGACY_LAYERING
#define COPY_VMCS1_HOST_TO_MERGE_GUEST()    // TODO:
#else
#define COPY_VMCS1_HOST_TO_MERGE_GUEST()    //
#endif


static BOOLEAN *nmi_array;

VMEXIT_HANDLING_STATUS nmi_process_translated_reason(GUEST_CPU_HANDLE gcpu,
                                            IA32_VMX_EXIT_BASIC_REASON xlat_reason);
static VMEXIT_HANDLING_STATUS nmi_propagate_nmi(GUEST_CPU_HANDLE gcpu);
static VMEXIT_HANDLING_STATUS nmi_propagate_nmi_window(GUEST_CPU_HANDLE gcpu);
static void nmi_emulate_nmi_vmexit(GUEST_CPU_HANDLE gcpu);
static void nmi_emulate_nmi_window_vmexit(GUEST_CPU_HANDLE gcpu);
static CPU_ID nmi_num_of_cores;


BOOLEAN nmi_manager_initialize(CPU_ID num_of_cores)
{
    BOOLEAN success = FALSE;

    do {
        nmi_array = vmm_malloc(num_of_cores * sizeof(BOOLEAN));
        nmi_num_of_cores=num_of_cores;
        if (NULL == nmi_array) {
            break;
        }
        vmm_memset(nmi_array, 0, num_of_cores * sizeof(BOOLEAN));
        success = ipc_initialize(num_of_cores);
    } while (0);
    // no need to release memory in case of failure, because it is Fatal
    return success;
}


//static void nmi_raise(CPU_ID cpu_id)
void nmi_raise(CPU_ID cpu_id)
{
    VMM_LOG(mask_anonymous, level_trace,"[nmi] Platform NMI on CPU%d\n", cpu_id);
    nmi_array[cpu_id] = TRUE;
}

//static void nmi_clear(CPU_ID cpu_id)
void nmi_clear(CPU_ID cpu_id)
{
    nmi_array[cpu_id] = FALSE;
}

//static BOOLEAN nmi_is_pending(CPU_ID cpu_id)
BOOLEAN nmi_is_pending(CPU_ID cpu_id)
{
    return nmi_array[cpu_id];
}

void nmi_raise_this(void)
{
	CPU_ID cpu_id=hw_cpu_id();
	if(cpu_id>=nmi_num_of_cores) {
		VMM_LOG(mask_anonymous, level_error, "Error: invalid cpu_id.\n");
		return;
	}
    nmi_raise(cpu_id);
}

void nmi_clear_this(void)
{
    CPU_ID cpu_id=hw_cpu_id();

    if(cpu_id>=nmi_num_of_cores) {
        VMM_LOG(mask_anonymous, level_error, "Error: invalid cpu_id.\n");
        return;
    }
    nmi_clear(cpu_id);
}

BOOLEAN nmi_is_pending_this(void)
{
    CPU_ID cpu_id=hw_cpu_id();
    if(cpu_id>=nmi_num_of_cores) {
        VMM_LOG(mask_anonymous, level_error, "Error: invalid cpu_id.\n");
        return FALSE;
    }
    return nmi_is_pending(cpu_id);
}


// FUNCTION : nmi_resume_handler()
// PURPOSE  : If current CPU is platform NMI owner and unhandled platform NMI
//          : exists on current CPU, sets NMI-Window to get VMEXIT asap.
// ARGUMENTS: GUEST_CPU_HANDLE gcpu
void nmi_resume_handler(GUEST_CPU_HANDLE gcpu)
{
    if (NMI_EXISTS_ON_GCPU(gcpu)) {
        gcpu_set_pending_nmi(gcpu, TRUE);
    }
}


// FUNCTION : nmi_vmexit_handler()
// PURPOSE  : Process NMI VMEXIT
// ARGUMENTS: GUEST_CPU_HANDLE gcpu
// RETURNS  : Status which says if VMEXIT was finally handled or
//          : it should be processed by upper layer
// CALLED   : called as bottom-up local handler
VMEXIT_HANDLING_STATUS nmi_vmexit_handler(GUEST_CPU_HANDLE gcpu)
{
    ipc_nmi_vmexit_handler(gcpu);
    return nmi_process_translated_reason(gcpu, XLAT_NMI_VMEXIT_REASON(NMI_EXISTS_ON_GCPU(gcpu)));
}

// FUNCTION : nmi_window_vmexit_handler()
// PURPOSE  : Process NMI Window VMEXIT
// ARGUMENTS: GUEST_CPU_HANDLE gcpu
// RETURNS  : Status which says if VMEXIT was finally handled or
//          : it should be processed by upper layer
// CALLED   : called as bottom-up local handler
VMEXIT_HANDLING_STATUS nmi_window_vmexit_handler(GUEST_CPU_HANDLE gcpu)
{
    ipc_nmi_window_vmexit_handler(gcpu);
    gcpu_set_pending_nmi(gcpu, FALSE);  // TODO: substitute with new NMI-Window registration service
    return nmi_process_translated_reason(gcpu, XLAT_NMI_WINDOW_VMEXIT_REASON(NMI_EXISTS_ON_GCPU(gcpu)));
}

VMEXIT_HANDLING_STATUS nmi_process_translated_reason(
    GUEST_CPU_HANDLE           gcpu,
    IA32_VMX_EXIT_BASIC_REASON xlat_reason)
{
    VMEXIT_HANDLING_STATUS status;

    switch (xlat_reason) {
    case Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi:
        status = nmi_propagate_nmi(gcpu);
        break;
    case Ia32VmxExitNmiWindow:
        status = nmi_propagate_nmi_window(gcpu);
        break;
    default:
        status = VMEXIT_HANDLED;    // dismiss
        break;
    }
    return status;
}


// FUNCTION : nmi_propagate_nmi()
// PURPOSE  : If layered and upper VMM requested NMI VMEXIT, emulate it,
//          : else inject it directly to VM
// ARGUMENTS: GUEST_CPU_HANDLE gcpu
// RETURNS  : Status which says if VMEXIT was finally handled or
//          : it should be processed by upper layer
VMEXIT_HANDLING_STATUS nmi_propagate_nmi(GUEST_CPU_HANDLE gcpu)
{
    VMEXIT_HANDLING_STATUS status;

    do {
        if (gcpu_is_vmcs_layered(gcpu)) {
            // if upper layer requested NMI VMEXIT, emulate NMI VMEXIT into it
            VMCS_OBJECT *vmcs1 = gcpu_get_vmcs_layered(gcpu, VMCS_LEVEL_1);
            PIN_BASED_VM_EXECUTION_CONTROLS pin_based_vmexit_ctrls;
            pin_based_vmexit_ctrls.Uint32 = (UINT32) vmcs_read(vmcs1, VMCS_CONTROL_VECTOR_PIN_EVENTS);
            if (pin_based_vmexit_ctrls.Bits.Nmi) {
                nmi_emulate_nmi_vmexit(gcpu);
                nmi_clear_this();
                status = VMEXIT_NOT_HANDLED;
                break;
            }
        }
        // here is non-layered case, or level.1 did not request NMI VMEXIT
        if (gcpu_inject_nmi(gcpu)) {
            nmi_clear_this();
        }
        // do not deliver to upper level even if NMI was not really injected
        status = VMEXIT_HANDLED;
    } while (0);
    return status;
}


// FUNCTION : nmi_propagate_nmi_window()
// PURPOSE  : If layered and upper VMM requested NMI-Window VMEXIT, emulate it,
//          : else dismiss it.
// ARGUMENTS: GUEST_CPU_HANDLE gcpu
// RETURNS  : Status which says if VMEXIT was finally handled or
//          : it should be processed by upper layer
VMEXIT_HANDLING_STATUS nmi_propagate_nmi_window(GUEST_CPU_HANDLE gcpu)
{
    VMEXIT_HANDLING_STATUS status;

    do {
        if (gcpu_is_vmcs_layered(gcpu)) {
            // if upper layer requested NMI VMEXIT, emulate NMI VMEXIT into it
            VMCS_OBJECT *vmcs1 = gcpu_get_vmcs_layered(gcpu, VMCS_LEVEL_1);
            PROCESSOR_BASED_VM_EXECUTION_CONTROLS ctrls;

            ctrls.Uint32 = (UINT32)vmcs_read(vmcs1, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
            if (ctrls.Bits.NmiWindow) {
                nmi_emulate_nmi_window_vmexit(gcpu);
                status = VMEXIT_NOT_HANDLED;
                break;
            }
        }

        // here is non-layered case, or level.1 did not request NMI Window VMEXIT
        // do not deliver NMI Window to upper level
        status = VMEXIT_HANDLED;
    } while (0);

    return status;
}


// FUNCTION : nmi_emulate_nmi_vmexit()
// PURPOSE  : Emulates NMI VMEXIT into upper VMM
// ARGUMENTS: GUEST_CPU_HANDLE gcpu
void nmi_emulate_nmi_vmexit(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT *vmcs = gcpu_get_vmcs_layered(gcpu, VMCS_MERGED);
    //UINT32  reason;
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO exception_info;

    VMM_CALLTRACE_ENTER();
    //reason = (UINT32)vmcs_read(vmcs, VMCS_EXIT_INFO_REASON);
    
    // change VMEXIT INFO, which is read-only. It is done in cache only
    // and should not be writeen to hardware VMCS
    vmcs_write_nocheck(vmcs, VMCS_EXIT_INFO_REASON,
        (UINT64)Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi);

    exception_info.Uint32 = 0;
    exception_info.Bits.Vector        = IA32_EXCEPTION_VECTOR_NMI;
    exception_info.Bits.InterruptType = IA32_EXCEPTION_VECTOR_NMI;
    exception_info.Bits.Valid         = 1;
    vmcs_write_nocheck(vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO, (UINT64)exception_info.Uint32);
    COPY_VMCS1_HOST_TO_MERGE_GUEST();
    VMM_CALLTRACE_LEAVE();
}


// FUNCTION : nmi_emulate_nmi_window_vmexit()
// PURPOSE  : Emulates NMI-Window VMEXIT into upper VMM
// ARGUMENTS: GUEST_CPU_HANDLE gcpu
#pragma warning(disable : 4100)
void nmi_emulate_nmi_window_vmexit(GUEST_CPU_HANDLE gcpu UNUSED)
{
    VMM_CALLTRACE_ENTER();
    COPY_VMCS1_HOST_TO_MERGE_GUEST();
    VMM_CALLTRACE_LEAVE();
}
#pragma warning(default : 4100)

