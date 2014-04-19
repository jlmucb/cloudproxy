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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMCALL_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMCALL_C, __condition)
#include "vmm_defs.h"
#include "heap.h"
#include "hw_utils.h"
#include "guest.h"
#include "guest_cpu.h"
#include "gpm_api.h"
#include "vmexit.h"
#include "vmcall.h"
#include "vmm_dbg.h"
#include "list.h"
#include "lock.h"
#include "memory_allocator.h"
#include "../guest/guest_cpu/unrestricted_guest.h"

#ifdef VMCALL_NOT_ALLOWED_FROM_RING_1_TO_3
#include "guest_cpu_vmenter_event.h"

#define DESCRIPTOR_CPL_BIT 0x3
#endif

// MAX_ACTIVE_VMCALLS_PER_GUEST must be power of 2
#define MAX_ACTIVE_VMCALLS_PER_GUEST   64
#define UNALLOCATED_VMCALL             VMCALL_LAST_USED_INTERNAL

#define VMCALL_IS_VALID(__vmcall_id) ((__vmcall_id) != UNALLOCATED_VMCALL)

typedef  struct {
    VMCALL_HANDLER  vmcall_handler;
    BOOLEAN         vmcall_special; // e.g. for emuator termination
    VMCALL_ID       vmcall_id;
} VMCALL_ENTRY;

typedef  struct {
    GUEST_ID guest_id;
    UINT8    padding[2];
    UINT32   filled_entries_count;
    VMCALL_ENTRY vmcall_table[MAX_ACTIVE_VMCALLS_PER_GUEST];
    LIST_ELEMENT list[1];
} GUEST_VMCALL_ENTRIES;

typedef struct {
    LIST_ELEMENT guest_vmcall_entries[1];
} VMCALL_GLOBAL_STATE;

static VMCALL_GLOBAL_STATE         vmcall_global_state;  // for all guests

static VMM_STATUS vmcall_unimplemented(GUEST_CPU_HANDLE gcpu, ADDRESS *arg1, ADDRESS *arg2, ADDRESS *arg3);
VMM_STATUS vmcall_print_string(GUEST_CPU_HANDLE gcpu, ADDRESS * p_string, ADDRESS *is_real_guest, ADDRESS *arg3);

static VMEXIT_HANDLING_STATUS vmcall_common_handler(GUEST_CPU_HANDLE gcpu);

static GUEST_VMCALL_ENTRIES* vmcall_find_guest_vmcalls(GUEST_ID guest_id);

static VMCALL_ENTRY* vmcall_get_vmcall_entry(GUEST_ID     guest_id,
                                             VMCALL_ID    vmcall_id);
#ifdef ENABLE_INT15_VIRTUALIZATION
BOOLEAN handle_int15_vmcall(GUEST_CPU_HANDLE gcpu);
#endif
void vmcall_intialize( void )
{
    vmm_memset( &vmcall_global_state, 0, sizeof(vmcall_global_state) );
    list_init(vmcall_global_state.guest_vmcall_entries);
}

void vmcall_guest_intialize(
    GUEST_ID    guest_id)
{
    UINT32       id;
    GUEST_VMCALL_ENTRIES *guest_vmcalls;
    VMCALL_ENTRY *vmcall_entry;

    VMM_LOG(mask_uvmm, level_trace,"vmcall_guest_intialize start\r\n");

    guest_vmcalls = (GUEST_VMCALL_ENTRIES *) vmm_malloc(sizeof(GUEST_VMCALL_ENTRIES));
    // BEFORE_VMLAUNCH. MALLOC should not fail.
    VMM_ASSERT(guest_vmcalls);

    guest_vmcalls->guest_id = guest_id;
    guest_vmcalls->filled_entries_count = 0;

    list_add(vmcall_global_state.guest_vmcall_entries, guest_vmcalls->list);

    vmexit_install_handler(
        guest_id,
        vmcall_common_handler,
        Ia32VmxExitBasicReasonVmcallInstruction);

    for (id = 0; id < MAX_ACTIVE_VMCALLS_PER_GUEST; ++id) {
        vmcall_entry = &guest_vmcalls->vmcall_table[id];
        vmcall_entry->vmcall_handler = vmcall_unimplemented;
        vmcall_entry->vmcall_id = UNALLOCATED_VMCALL;
    }
    VMM_LOG(mask_uvmm, level_trace,"vmcall_guest_intialize end\r\n");

}

void vmcall_register(
    GUEST_ID        guest_id,
    VMCALL_ID       vmcall_id,
    VMCALL_HANDLER  handler,
    BOOLEAN         special_call)
{
    VMCALL_ENTRY *vmcall_entry;

    VMM_ASSERT(NULL != handler);

    // if already exists, check that all params are the same
    vmcall_entry = vmcall_get_vmcall_entry(guest_id, vmcall_id);
    if (NULL != vmcall_entry) {
        if ((vmcall_entry->vmcall_id      == vmcall_id) &&
            (vmcall_entry->vmcall_handler == handler)   &&
            (vmcall_entry->vmcall_special == special_call)) {
            return;
        }

        VMM_LOG(mask_uvmm, level_trace,"VMCALL %d is already registered for the Guest %d with different params\n",
                  vmcall_id, guest_id);
        VMM_ASSERT(FALSE);
    }

    vmcall_entry = vmcall_get_vmcall_entry(guest_id, UNALLOCATED_VMCALL);
    VMM_ASSERT(vmcall_entry);
    VMM_LOG(mask_uvmm, level_trace,"vmcall_register: guest %d vmcall_id %d vmcall_entry %p\r\n",
        guest_id, vmcall_id, vmcall_entry);

    vmcall_entry->vmcall_handler = handler;
    vmcall_entry->vmcall_special = special_call;
    vmcall_entry->vmcall_id      = vmcall_id;
}

#ifdef VMCALL_NOT_ALLOWED_FROM_RING_1_TO_3

// Return TRUE is the DPL of the guest issuing the VMCALL is in ring 0,
// otherwise inject the #UD execption and return FALSE.
BOOLEAN vmcall_check_guest_dpl_is_ring0(GUEST_CPU_HANDLE gcpu){
	VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
	UINT64 guest_cs_selector= vmcs_read(vmcs, VMCS_GUEST_CS_SELECTOR);

    if (BITMAP_GET(guest_cs_selector, DESCRIPTOR_CPL_BIT) == 0) {
        return TRUE;
    }
    VMM_DEBUG_CODE(VMM_LOG(mask_uvmm, level_error,
			"CPU%d: %s: Error: VMCALL is initialized from ring >0. CPL=%d.\n",
		   	hw_cpu_id(), __FUNCTION__,
			BITMAP_GET(guest_cs_selector, DESCRIPTOR_CPL_BIT)));

    gcpu_inject_invalid_opcode_exception(gcpu);
    return FALSE;
}
#endif

VMEXIT_HANDLING_STATUS vmcall_common_handler(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE guest      = gcpu_guest_handle(gcpu);
    GUEST_ID     guest_id   = guest_get_id(guest);
    VMCALL_ID    vmcall_id;
    ADDRESS      arg1, arg2, arg3;
    VMM_STATUS   ret_value;
    VMCALL_HANDLER vmcall_function;
    BOOLEAN      is_vmcall_special = FALSE;
    VMCALL_ENTRY *vmcall_entry = NULL;
    VMEXIT_HANDLING_STATUS handle_status;
#ifdef ENABLE_INT15_VIRTUALIZATION
    if(is_unrestricted_guest_supported())
    	if ( handle_int15_vmcall(gcpu) )
            return VMEXIT_HANDLED;
#endif
#ifdef VMCALL_NOT_ALLOWED_FROM_RING_1_TO_3
    if (!vmcall_check_guest_dpl_is_ring0(gcpu))
        return VMEXIT_HANDLED;
#endif

    vmcall_id = (VMCALL_ID) gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);
    if (VMM_NATIVE_VMCALL_SIGNATURE == gcpu_get_native_gp_reg(gcpu, IA32_REG_RAX)) {
        vmcall_entry = vmcall_get_vmcall_entry(guest_id, vmcall_id);
    }

    if (NULL != vmcall_entry) {
        VMM_ASSERT( vmcall_entry->vmcall_id == vmcall_id );

        vmcall_function = vmcall_entry->vmcall_handler;
        is_vmcall_special = vmcall_entry->vmcall_special;
    }
    else {
        if (GUEST_LEVEL_2 == gcpu_get_guest_level(gcpu)) {
            // VMCALL will be delivered to level#1 VMM for processing
            vmcall_function = NULL;
        }
        else {
            VMM_LOG(mask_uvmm, level_trace,"ERROR: vmcall %d is not implemented\n", vmcall_id);
            vmcall_function = vmcall_unimplemented;
            is_vmcall_special = FALSE;
        }
    }

    if (NULL != vmcall_function) {
        if (TRUE == is_vmcall_special) {
            vmcall_function(gcpu, NULL, NULL, NULL);
        }
        else {
            arg1      = gcpu_get_native_gp_reg(gcpu, IA32_REG_RDX);
            arg2      = gcpu_get_native_gp_reg(gcpu, IA32_REG_RDI);
            arg3      = gcpu_get_native_gp_reg(gcpu, IA32_REG_RSI);

            /* Invoke vmcall_function that is registered for this vmcall_id */
            ret_value = vmcall_function(gcpu, &arg1, &arg2, &arg3);

            if (ret_value == VMM_OK) {
                // return arguments back to Guest, in case they were changed
                gcpu_set_native_gp_reg(gcpu, IA32_REG_RDX, arg1);
                gcpu_set_native_gp_reg(gcpu, IA32_REG_RDI, arg2);
                gcpu_set_native_gp_reg(gcpu, IA32_REG_RSI, arg3);

                /* Skip instruction only if return_value is VMM_OK */
                gcpu_skip_guest_instruction(gcpu);
            }
        }
        handle_status = VMEXIT_HANDLED;
    }
    else {
		VMM_LOG(mask_uvmm, level_error, "CPU%d: %s: Error: VMEXIT_NOT_HANDLED\n",
				hw_cpu_id(), __FUNCTION__);
        handle_status = VMEXIT_NOT_HANDLED;
    }

    return handle_status;
}

#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter
VMM_STATUS vmcall_unimplemented( GUEST_CPU_HANDLE gcpu USED_IN_DEBUG_ONLY,
    ADDRESS *arg1 UNUSED, ADDRESS *arg2 UNUSED, ADDRESS *arg3 UNUSED)
{
    VMM_LOG(mask_uvmm, level_error,
    		"CPU%d: %s: Error: Unimplemented VMCALL invoked on Guest ",
    		hw_cpu_id(), __FUNCTION__);
    PRINT_GCPU_IDENTITY(gcpu);
    VMM_LOG(mask_uvmm, level_error,"\n");
#ifdef ENABLE_TMSL_API_PROTECTION
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMM_ERROR;
}
#ifdef INCLUDE_UNUSED_CODE
VMM_STATUS vmcall_print_string( GUEST_CPU_HANDLE gcpu,
    ADDRESS *string_gva, ADDRESS *is_real_guest, ADDRESS *arg3 UNUSED)
{
    if (TRUE == *is_real_guest) {
        GUEST_HANDLE    guest_handle;
        GPM_HANDLE      guest_phy_memory;
        HPA             string_gpa;
        HVA             string_hva;

        string_gpa = *string_gva;   // TODO:: translate GVA to GPA (do guest page walk)

        // translate GPA to HVA
        guest_handle = gcpu_guest_handle(gcpu);
        VMM_ASSERT(guest_handle);

        guest_phy_memory = gcpu_get_current_gpm(guest_handle);
        VMM_ASSERT(guest_phy_memory);

        if (FALSE == gpm_gpa_to_hva(guest_phy_memory, string_gpa, &string_hva)) {
            VMM_LOG(mask_uvmm, level_trace,"Bad VM Print\n");
        }
        else {
            VMM_LOG(mask_uvmm, level_trace,"%s", (char *) string_hva);
        }
    }
    else {
        // it is a Host memory space, so GVA == HVA
        VMM_LOG(mask_uvmm, level_trace,"%s", (char *) *string_gva);
    }

    return VMM_OK;
}
#endif

#pragma warning( pop )

static
GUEST_VMCALL_ENTRIES* vmcall_find_guest_vmcalls(GUEST_ID guest_id) {
    LIST_ELEMENT *iter = NULL;
    GUEST_VMCALL_ENTRIES *guest_vmcalls = NULL;

    LIST_FOR_EACH(vmcall_global_state.guest_vmcall_entries, iter) {
        guest_vmcalls = LIST_ENTRY(iter, GUEST_VMCALL_ENTRIES, list);
        if(guest_vmcalls->guest_id == guest_id) {
            return guest_vmcalls;
        }
    }
    return NULL;
}

static VMCALL_ENTRY* find_guest_vmcall_entry( GUEST_VMCALL_ENTRIES* guest_vmcalls,
                                       VMCALL_ID call_id )
{
    UINT32 idx;

    for (idx = 0; idx < MAX_ACTIVE_VMCALLS_PER_GUEST; ++idx) {
        if (guest_vmcalls->vmcall_table[idx].vmcall_id == call_id) {
            return &(guest_vmcalls->vmcall_table[idx]);
        }
    }
    return NULL;
}

static VMCALL_ENTRY* vmcall_get_vmcall_entry(GUEST_ID guest_id, VMCALL_ID vmcall_id)
{
    GUEST_VMCALL_ENTRIES *guest_vmcalls;
    VMCALL_ENTRY *vmcall_entry;

    guest_vmcalls = vmcall_find_guest_vmcalls(guest_id);
    if(NULL == guest_vmcalls) {
        VMM_ASSERT(0);
        return NULL;
    }
    vmcall_entry = find_guest_vmcall_entry(guest_vmcalls,vmcall_id);
    return vmcall_entry;
}

