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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(EPT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(EPT_C, __condition)
#include "vmm_callback.h"
#include "vmcs_init.h"
#include "guest_cpu.h"
#include "event_mgr.h"
#include "vmm_events_data.h"
#include "vmcs_api.h"
#include "guest.h"
#include "ept.h"
#include "policy_manager.h"
#include "memory_allocator.h"
#include "memory_address_mapper_api.h"
#include "gpm_api.h"
#include "hw_utils.h"
#include "mtrrs_abstraction.h"
#include "libc.h"
#include "host_memory_manager_api.h"
#include "ept_hw_layer.h"
#include "ipc.h"
#include "guest_cpu_vmenter_event.h"
#include "lock.h"
#include "scheduler.h"
#include "page_walker.h"
#include "guest_cpu_internal.h"
#include "unrestricted_guest.h"
#include "fvs.h"
#include "ve.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

EPT_STATE ept;
HPA redirect_physical_addr = 0;

#pragma warning( disable : 4214 ) // enables UINT64 bitfield
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter

// macro #define's
#define PDPTR_NXE_DISABLED_RESERVED_BITS_MASK        (UINT64) 0xffffff00000001e6
#define PDPTR_NXE_ENABLED_RESERVED_BITS_MASK         (UINT64) 0x7fffff00000001e6
#define PRESENT_BIT                                  (UINT64) 0x1

// static functions
static BOOLEAN ept_guest_cpu_initialize(GUEST_CPU_HANDLE gcpu);
BOOLEAN ept_page_walk(UINT64 first_table, UINT64 addr, UINT32 gaw);
void ept_set_remote_eptp(CPU_ID from, void* arg);


#ifdef INCLUDE_UNUSED_CODE
static
BOOLEAN ept_check_pdpt_reserved_bits(UINT64 pdptr, UINT64 efer)
{
    if((efer & EFER_NXE) == 0) {
        return (pdptr & PDPTR_NXE_DISABLED_RESERVED_BITS_MASK) == 0;
    }
    return (pdptr & PDPTR_NXE_ENABLED_RESERVED_BITS_MASK) == 0;
}
#endif

void ept_set_pdtprs(GUEST_CPU_HANDLE gcpu, UINT64 cr4_value)
{
    UINT64 pdpt[4];
    BOOLEAN status = TRUE;
    BOOLEAN pdptr_required = FALSE;

    if (cr4_value & CR4_PAE) { // PAE mode
        UINT64 efer = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
        if (0 == (efer & EFER_LME)) { // 32-bit mode
            status = gcpu_get_32_bit_pdpt(gcpu, pdpt)
                  && pw_is_pdpt_in_32_bit_pae_mode_valid(gcpu, pdpt);
            if (TRUE == status) {
                pdptr_required = TRUE;
                ept_hw_set_pdtprs(gcpu, pdpt);
            }
        }
    }
    if (FALSE == pdptr_required) {
        vmm_zeromem(pdpt, sizeof(pdpt));
        ept_hw_set_pdtprs(gcpu, pdpt);
    }
}

void ept_acquire_lock(void)
{
    if (ept.lock.owner_cpu_id == hw_cpu_id()) {
        ept.lock_count++;
        return;
    }
    interruptible_lock_acquire(&ept.lock);
    ept.lock_count = 1;
}

void ept_release_lock(void)
{
    ept.lock_count--;
    if (ept.lock_count == 0) {
        lock_release(&ept.lock);
    }
}

BOOLEAN ept_is_cpu_in_non_paged_mode(GUEST_ID guest_id)
{
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    UINT32 i = 0;
    GUEST_CPU_HANDLE gcpu = scheduler_get_current_gcpu_for_guest(guest_id);

    //for UG system, flat page table will never be used, so, this function should always return FALSE.
    if(is_unrestricted_guest_enabled(gcpu))
        return FALSE;
    ept_guest = ept_find_guest_state(guest_id);
    VMM_ASSERT(ept_guest);
    for (i = 0; i < ept.num_of_cpus; i++) {
        ept_guest_cpu = ept_guest->gcpu_state[i];
        VMM_ASSERT(ept_guest_cpu);
        if (ept_guest_cpu->is_initialized && (ept_guest_cpu->cr0 & CR0_PG) == 0) {
            // cannot change perms - another gcpu not paged and uses flat page tables
            return TRUE;
        }
    }
    return FALSE;
}


#ifdef INCLUDE_UNUSED_CODE
void dbg_print_ept_violation(GUEST_CPU_HANDLE gcpu, EPTP eptp, EVENT_GCPU_EPT_VIOLATION_DATA *data)
{
    EPT_PRINTERROR("\r\n****EPT violation:****\n");
    EPT_PRINTERROR("R=%d W=%d X=%d EptR=%d EptW=%d EptX=%d\n",
        data->qualification.EptViolation.R, data->qualification.EptViolation.W, data->qualification.EptViolation.X,
        data->qualification.EptViolation.EptR, data->qualification.EptViolation.EptW, data->qualification.EptViolation.EptX);
    EPT_PRINTERROR("GawViolation=%d GlaValidity=%d NMIunblocking=%d\n", 
        data->qualification.EptViolation.GawViolation, data->qualification.EptViolation.GlaValidity,data->qualification.EptViolation.NMIunblocking);
    EPT_PRINTERROR("GPA: %p\n", data->guest_physical_address);
    if(data->qualification.EptViolation.GlaValidity)
    {
        EPT_PRINTERROR("GVA: %p\n", data->guest_linear_address);
    }
    EPT_PRINTERROR("EPTP.ETMT: 0x%X EPTP.GAW: 0x%X EPTP.ASR: 0x%X\n", eptp.Bits.ETMT, eptp.Bits.GAW, eptp.Uint64 & ~PAGE_4KB_MASK);
    EPT_PRINTERROR("Is native %p\r\n", gcpu_is_native_execution(gcpu));
    ept_page_walk((UINT64) eptp.Uint64 & ~PAGE_4KB_MASK, data->guest_physical_address, ept_hw_get_guest_address_width_from_encoding((UINT32)eptp.Bits.GAW));
}
#endif

// EPT vmexits
/*
 *  Function name: ept_violation_vmexit
 *  Parameters: Function does not validate gcpu. Assumes valid.
 */
BOOLEAN ept_violation_vmexit(GUEST_CPU_HANDLE gcpu, void *pv)
{
    REPORT_EPT_VIOLATION_DATA violation_data;
    EVENT_GCPU_EPT_VIOLATION_DATA *data = (EVENT_GCPU_EPT_VIOLATION_DATA *) pv;
    const VIRTUAL_CPU_ID *vcpu_id=NULL;
    IA32_VMX_EXIT_QUALIFICATION ept_violation_qualification;

    vcpu_id= guest_vcpu(gcpu);
    VMM_ASSERT(vcpu_id);
    // Report EPT violation to the VIEW module
    violation_data.qualification = data->qualification.Uint64;
    violation_data.guest_linear_address = data->guest_linear_address;
    violation_data.guest_physical_address = data->guest_physical_address;

    ept_violation_qualification.Uint64 = violation_data.qualification;
    if( ept_violation_qualification.EptViolation.NMIunblocking ) {
        VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);
        IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;

        idt_vectoring_info.Uint32 = (UINT32)vmcs_read(vmcs,VMCS_EXIT_INFO_IDT_VECTORING);

        if(!idt_vectoring_info.Bits.Valid) {
            IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY guest_interruptibility;

            guest_interruptibility.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_GUEST_INTERRUPTIBILITY);
            guest_interruptibility.Bits.BlockNmi = 1;
            vmcs_write(vmcs,VMCS_GUEST_INTERRUPTIBILITY,(UINT64)guest_interruptibility.Uint32);
        }
    }

    if (!report_uvmm_event(UVMM_EVENT_EPT_VIOLATION, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)vcpu_id, (void *)&violation_data)) {
        VMM_LOG(mask_anonymous, level_trace, "report_ept_violation failed\n");
    }

    data->processed = TRUE;
    return TRUE;
}

#pragma warning (disable:4189)
#pragma warning (disable:4101)

BOOLEAN ept_misconfiguration_vmexit(GUEST_CPU_HANDLE gcpu UNUSED, void *pv)
{
    EPTP eptp;
    EVENT_GCPU_EPT_MISCONFIGURATION_DATA *data = (EVENT_GCPU_EPT_MISCONFIGURATION_DATA *) pv;

    EPT_PRINTERROR("\r\n****EPT Misconfiguration:****\n");
    EPT_PRINTERROR("GPA=%p\n", data->guest_physical_address);

    eptp.Uint64 = ept_get_eptp(gcpu);
    VMM_LOG(mask_anonymous, level_trace,"EPTP.ETMT: 0x%X EPTP.GAW: 0x%X EPTP.ASR: 0x%X\n", eptp.Bits.ETMT, eptp.Bits.GAW, eptp.Uint64 & ~PAGE_4KB_MASK);
    VMM_LOG(mask_anonymous, level_trace,"Is native %p\r\n", gcpu_is_native_execution(gcpu));
    ept_page_walk((UINT64) eptp.Uint64 & ~PAGE_4KB_MASK, data->guest_physical_address, ept_hw_get_guest_address_width_from_encoding((UINT32)eptp.Bits.GAW));
    VMM_DEADLOOP();
    data->processed = TRUE;
    return TRUE;
}

MAM_EPT_SUPER_PAGE_SUPPORT ept_get_mam_super_page_support(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    IA32_VMX_EPT_VPID_CAP ept_cap = hw_constraints->ept_vpid_capabilities;
    MAM_EPT_SUPER_PAGE_SUPPORT sp_support = MAM_EPT_NO_SUPER_PAGE_SUPPORT;

//Currently we support 2MB pages in implementation
    if(ept_cap.Bits.SP_21_bit) {
        sp_support |= MAM_EPT_SUPPORT_2MB_PAGE;
    }
#if 0
    if(ept_cap.Bits.SP_30_bit) {
        sp_support |= MAM_EPT_SUPPORT_1GB_PAGE;
    }
    if(ept_cap.Bits.SP_39_bit)
    {
        sp_support |= MAM_EPT_SUPPORT_512_GB_PAGE;
    }
#endif
    return sp_support;
}

void ept_get_current_ept(GUEST_CPU_HANDLE gcpu, UINT64 *ept_root_table_hpa, UINT32 *ept_gaw)
{
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    VMM_ASSERT(gcpu);
    vcpu_id = guest_vcpu(gcpu);
    //paranoid check. If assertion fails, possible memory corruption.
    VMM_ASSERT(vcpu_id);
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];
    VMM_ASSERT(ept_guest_cpu);
    *ept_root_table_hpa = ept_guest_cpu->active_ept_root_table_hpa;
    *ept_gaw = ept_guest_cpu->active_ept_gaw;
}

void ept_set_current_ept(GUEST_CPU_HANDLE gcpu, UINT64 ept_root_table_hpa, UINT32 ept_gaw)
{
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;

    VMM_ASSERT(gcpu);
    vcpu_id = guest_vcpu(gcpu);
    //paranoid check. If assertion fails, possible memory corruption.
    VMM_ASSERT(vcpu_id);
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];
    VMM_ASSERT(ept_guest_cpu);
    ept_guest_cpu->active_ept_root_table_hpa = ept_root_table_hpa;
    ept_guest_cpu->active_ept_gaw = ept_gaw;
}

void ept_get_default_ept(GUEST_HANDLE guest, UINT64 *ept_root_table_hpa, UINT32 *ept_gaw)
{
    EPT_GUEST_STATE *ept_guest = NULL;

    VMM_ASSERT(guest);

    ept_guest = ept_find_guest_state(guest_get_id(guest));
    VMM_ASSERT(ept_guest);

    *ept_root_table_hpa = ept_guest->ept_root_table_hpa;
    *ept_gaw = ept_guest->gaw;
}

void ept_create_default_ept(GUEST_HANDLE guest, GPM_HANDLE gpm)
{
    EPT_GUEST_STATE *ept_guest = NULL;

    VMM_ASSERT(guest);
    VMM_ASSERT(gpm);
    ept_guest = ept_find_guest_state(guest_get_id(guest));
    VMM_ASSERT(ept_guest);

    if (ept_guest->address_space != MAM_INVALID_HANDLE) {
        mam_destroy_mapping(ept_guest->address_space);
        ept_guest->address_space = MAM_INVALID_HANDLE;
    }
    ept_guest->gaw = ept_hw_get_guest_address_width(ept_get_guest_address_width(gpm));
    VMM_ASSERT(ept_guest->gaw != (UINT32) -1);
    ept_guest->address_space = ept_create_guest_address_space(gpm, TRUE);
    VMM_ASSERT(mam_convert_to_ept(ept_guest->address_space, ept_get_mam_super_page_support(),
                                  ept_get_mam_supported_gaw(ept_guest->gaw), ve_is_hw_supported(),
                                  &(ept_guest->ept_root_table_hpa)));
}

MAM_EPT_SUPPORTED_GAW ept_get_mam_supported_gaw(UINT32 gaw)
{
    return (MAM_EPT_SUPPORTED_GAW)ept_hw_get_guest_address_width_encoding(gaw);
}

static
BOOLEAN ept_begin_gpm_modification_before_cpus_stop( GUEST_CPU_HANDLE gcpu UNUSED,
                                                     void* pv UNUSED )
{
    ept_acquire_lock();
    return TRUE;
}

static
BOOLEAN ept_end_gpm_modification_before_cpus_resume( GUEST_CPU_HANDLE gcpu, void* pv )
{
    GUEST_HANDLE guest = NULL;
    EPT_SET_EPTP_CMD set_eptp_cmd;
    EPT_INVEPT_CMD invept_cmd;
    IPC_DESTINATION ipc_dest;
    EVENT_GPM_MODIFICATION_DATA *gpm_modification_data = (EVENT_GPM_MODIFICATION_DATA *) pv;
    UINT64 default_ept_root_table_hpa;
    UINT32 default_ept_gaw;
    VMM_ASSERT(pv);

    guest = guest_handle(gpm_modification_data->guest_id);
    if (gpm_modification_data->operation == VMM_MEM_OP_UPDATE)
    {
        ept_get_default_ept(guest, &default_ept_root_table_hpa, &default_ept_gaw);
        invept_cmd.host_cpu_id = ANY_CPU_ID;
        invept_cmd.cmd = INVEPT_CONTEXT_WIDE;
        invept_cmd.eptp = ept_compute_eptp(guest, default_ept_root_table_hpa, default_ept_gaw);

        ept_invalidate_ept(ANY_CPU_ID, &invept_cmd);

        ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        ipc_execute_handler_sync(ipc_dest, ept_invalidate_ept, (void *) &invept_cmd);
    } else if (gpm_modification_data->operation == VMM_MEM_OP_RECREATE) {
        // Recreate Default EPT
        ept_create_default_ept(guest, guest_get_startup_gpm(guest));
        ept_get_default_ept(guest, &default_ept_root_table_hpa, &default_ept_gaw);

        // Reset the Default EPT on current CPU
        ept_set_eptp(gcpu, default_ept_root_table_hpa, default_ept_gaw);

        invept_cmd.host_cpu_id = ANY_CPU_ID;
        invept_cmd.cmd = INVEPT_CONTEXT_WIDE;
        invept_cmd.eptp = ept_compute_eptp(guest, default_ept_root_table_hpa, default_ept_gaw);
        ept_invalidate_ept(ANY_CPU_ID, &invept_cmd);

        set_eptp_cmd.guest_id = gpm_modification_data->guest_id;
        set_eptp_cmd.ept_root_table_hpa = default_ept_root_table_hpa;
        set_eptp_cmd.gaw = default_ept_gaw;
        set_eptp_cmd.invept_cmd = &invept_cmd;

        ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        ipc_execute_handler_sync(ipc_dest, ept_set_remote_eptp, (void *) &set_eptp_cmd);
    } else { // switch
        VMM_ASSERT(gpm_modification_data->operation == VMM_MEM_OP_SWITCH);
        //only switch ept if the active view is not the same as switchto handle
//        if (ept_guest_get_active_view(gcpu) != gpm_modification_data->handle) {
//            VMM_ASSERT(ept_set_eptp(gcpu, gpm_modification_data->handle));
//        }
    }

    return TRUE;
}


static BOOLEAN ept_end_gpm_modification_after_cpus_resume(GUEST_CPU_HANDLE gcpu UNUSED, void* pv UNUSED)
{
    ept_release_lock();
    return TRUE;
}


static BOOLEAN ept_cr0_update(GUEST_CPU_HANDLE gcpu, void* pv)
{
#ifdef JLMDEBUG
    bprint("ept_cr0_update\n");
#endif
    UINT64 value = ((EVENT_GCPU_GUEST_CR_WRITE_DATA*) pv)->new_guest_visible_value;
    BOOLEAN pg;
    BOOLEAN prev_pg = 0;
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    UINT64 cr4;
    IA32_EFER_S efer;
    VM_ENTRY_CONTROLS entry_ctrl_mask;
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);

    ept_acquire_lock();
    vcpu_id = guest_vcpu(gcpu);
    VMM_ASSERT(vcpu_id);
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];
    prev_pg = (ept_guest_cpu->cr0 & CR0_PG) != 0;
    ept_guest_cpu->cr0 = value;
    pg = (ept_guest_cpu->cr0 & CR0_PG) != 0;
    if(is_unrestricted_guest_supported()) {
        /* IA Manual 3B: 27.9.4: IA32_EFER.LMA is always set by the processor
         * to equal IA32_EFER.LME & CR0.PG
         * Update LMA and IA32e bits based on LME and PG bit on systems with UG
         * Set VMCS.GUEST.EFER_MSR.LMA = (GUEST.CR0.PG & GUEST.EFER.LME)
         * Set VMCS.ENTRY_CONTROL.IA32e = (GUEST.CR0.PG & GUEST.EFER.LME)
         *
         * On systems w/o UG, LMA and IA32e are updated when EFER.LME is updated,
         * since PG is always 1
         */
        efer.Uint64 = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
        efer.Bits.LMA = (pg & efer.Bits.LME);
        gcpu_set_msr_reg(gcpu, IA32_VMM_MSR_EFER, efer.Uint64);
        entry_ctrl_mask.Uint32 = 0;
        entry_ctrl_mask.Bits.Ia32eModeGuest = 1;
        vmcs_update(vmcs, VMCS_ENTER_CONTROL_VECTOR,
                (efer.Bits.LMA) ? UINT64_ALL_ONES : 0,
                (UINT64) entry_ctrl_mask.Uint32);
    }
    if(pg != prev_pg) {
        /* INVVPID for this guest */
        ept_hw_invvpid_single_context(1 + gcpu->vcpu.guest_id);
    }
    if((pg) && (pg != prev_pg)) {
        // Enable EPT on systems w/o UG, when PG is turned on
        if(!is_unrestricted_guest_supported() && !ept_is_ept_enabled(gcpu))
            ept_enable(gcpu);
        cr4 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
        ept_set_pdtprs(gcpu, cr4);
    }
    // Disable EPT on systems without UG, when PG is turned off
    if(!pg && !is_unrestricted_guest_supported() && ept_is_ept_enabled(gcpu))
        ept_disable(gcpu);
    ept_release_lock();
    return TRUE;
}

static BOOLEAN ept_cr3_update( GUEST_CPU_HANDLE gcpu, void* pv UNUSED )
{
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;

#ifdef JLMDEBUG
    bprint("ept_cr3_update\n");
#endif
    ept_acquire_lock();
    vcpu_id = guest_vcpu( gcpu );
    VMM_ASSERT(vcpu_id);
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];
    if ((ept_guest_cpu->cr0 & CR0_PG) &&    // if paging is enabled
        (ept_guest_cpu->cr4 & CR4_PAE)) {    // and PAE mode is active
        ept_set_pdtprs(gcpu, ept_guest_cpu->cr4);
    }
    // Flush TLB
    ept_hw_invvpid_single_context(1 + gcpu->vcpu.guest_id);
    ept_release_lock();
    //    EPT_LOG("EPT CPU#%d: %s\n", hw_cpu_id(), __FUNCTION__);
    return TRUE;
}


static BOOLEAN ept_cr4_update(GUEST_CPU_HANDLE gcpu, void* pv)
{
    UINT64 new_cr4 = ((EVENT_GCPU_GUEST_CR_WRITE_DATA*) pv)->new_guest_visible_value;
    BOOLEAN pg;
    BOOLEAN pae = 0;
    BOOLEAN prev_pae = 0;
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    UINT64 cr4;

    (void)pg;
#ifdef JLMDEBUG
    bprint("ept_cr4_update\n");
#endif
    ept_acquire_lock();
    vcpu_id = guest_vcpu(gcpu);
    VMM_ASSERT(vcpu_id);
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];
    prev_pae = (ept_guest_cpu->cr4 & CR4_PAE) != 0;
    ept_guest_cpu->cr4 = new_cr4;
    pg = (ept_guest_cpu->cr0 & CR0_PG) != 0;
    pae = (ept_guest_cpu->cr4 & CR4_PAE) != 0;
    if(ept_is_ept_enabled(gcpu) && pae != prev_pae) {
        cr4 = ept_guest_cpu->cr4;
        ept_set_pdtprs(gcpu, cr4);
    }
    // Flush TLB
#ifdef JLMDEBUG
    bprint("ept_cr4_update position 1\n");
#endif
    ept_hw_invvpid_single_context(1 + gcpu->vcpu.guest_id);
    ept_release_lock();
#ifdef JLMDEBUG
    bprint("ept_cr4_update returning true\n");
#endif
    return TRUE;
}

static BOOLEAN ept_emulator_enter(GUEST_CPU_HANDLE gcpu, void* pv UNUSED)
{
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    EPT_GUEST_STATE *ept_guest_state = NULL;

    vcpu_id = guest_vcpu( gcpu );
    VMM_ASSERT(vcpu_id);
    ept_guest_state = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest_state);
    ept_guest_cpu = ept_guest_state->gcpu_state[vcpu_id->guest_cpu_id];

    ept_guest_cpu->cr0 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);
    ept_guest_cpu->cr4 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
    ept_guest_cpu->ept_enabled_save = FALSE;
    if(ept_is_ept_enabled(gcpu)) {
        ept_guest_cpu->ept_enabled_save = TRUE;
        ept_disable(gcpu);
    }
    return TRUE;
}

static BOOLEAN ept_emulator_exit(GUEST_CPU_HANDLE gcpu, void* pv UNUSED)
{
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    EVENT_GCPU_GUEST_CR_WRITE_DATA write_data = {0};
    UINT64 cr0, cr4;

#ifdef JLMDEBUG
    bprint("ept_emulator exit\n");
#endif
    ept_acquire_lock();
    vcpu_id = guest_vcpu(gcpu);
    VMM_ASSERT(vcpu_id);
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];
    if(ept_guest_cpu->ept_enabled_save) {
        ept_enable(gcpu);
    }
    cr0 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);
    cr4 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
    // Do not assume that the CR0 must be changed when emulator exits.
    // comment out this line to fix the issue "ETP disabled after S3 in ThinkCentre desktop". 
    if(cr0 != ept_guest_cpu->cr0) {
        write_data.new_guest_visible_value = cr0;
        ept_cr0_update(gcpu, &write_data);
    }
    if(cr4 != ept_guest_cpu->cr4) {
        write_data.new_guest_visible_value = cr4;
        ept_cr4_update(gcpu, &write_data);
    }
    ept_release_lock();
    return TRUE;
}

static void ept_register_events(GUEST_CPU_HANDLE gcpu)
{
    event_gcpu_register(EVENT_GCPU_AFTER_GUEST_CR0_WRITE, gcpu, ept_cr0_update);
    event_gcpu_register(EVENT_GCPU_AFTER_GUEST_CR3_WRITE, gcpu, ept_cr3_update);
    event_gcpu_register(EVENT_GCPU_AFTER_GUEST_CR4_WRITE, gcpu, ept_cr4_update);
    event_gcpu_register(EVENT_EMULATOR_AS_GUEST_ENTER, gcpu, ept_emulator_enter);
    event_gcpu_register(EVENT_EMULATOR_AS_GUEST_LEAVE, gcpu, ept_emulator_exit);
    event_gcpu_register(EVENT_GCPU_EPT_MISCONFIGURATION, gcpu, 
                        ept_misconfiguration_vmexit);
    event_gcpu_register(EVENT_GCPU_EPT_VIOLATION, gcpu, ept_violation_vmexit);
}

INLINE BOOLEAN ept_is_gcpu_active(IA32_VMX_VMCS_GUEST_SLEEP_STATE activity_state)
{
    return ((Ia32VmxVmcsGuestSleepStateWaitForSipi != activity_state) &&
            ((Ia32VmxVmcsGuestSleepStateTripleFaultShutdown != activity_state)));
}

static void ept_gcpu_activity_state_change(GUEST_CPU_HANDLE gcpu, 
                    EVENT_GCPU_ACTIVITY_STATE_CHANGE_DATA* pv)
{
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;

#ifdef JLMDEBUG
    bprint("ept_gcpu_activity_state_change\n");
#endif
    VMM_ASSERT( gcpu );
    VMM_ASSERT( pv );
    EPT_LOG("ept CPU#%d: activity state change: new state %d\r\n", 
            hw_cpu_id(), pv->new_state);
    vcpu_id = guest_vcpu( gcpu );
    VMM_ASSERT(vcpu_id);
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    if (ept_is_gcpu_active(pv->new_state)) {
        ept_guest_cpu_initialize(gcpu);
    }
}

UINT32 ept_get_guest_address_width(GPM_HANDLE gpm)
{
    GPM_RANGES_ITERATOR gpm_iter = 0;
    GPA guest_range_addr = 0;
    UINT64 guest_range_size = 0;
    GPA guest_highest_range_addr = 0;
    UINT64 guest_highest_range_size = 0;
    UINT64 guest_address_limit = 0;
    UINT32 guest_address_limit_msb_index = 0;

    VMM_ASSERT(gpm);
    gpm_iter = gpm_get_ranges_iterator(gpm);
    while(GPM_INVALID_RANGES_ITERATOR != gpm_iter) { // for each range in GPM
        gpm_iter = gpm_get_range_details_from_iterator(gpm, gpm_iter,
                                              &guest_range_addr, &guest_range_size);
        if(guest_range_addr > guest_highest_range_addr) {
            guest_highest_range_addr = guest_range_addr;
            guest_highest_range_size = guest_range_size;
        }
    }
    guest_address_limit = guest_highest_range_addr + guest_highest_range_size;
    hw_scan_bit_backward64(&guest_address_limit_msb_index, guest_address_limit);
    return guest_address_limit_msb_index + 1;
}

MAM_HANDLE ept_create_guest_address_space(GPM_HANDLE gpm, BOOLEAN original_perms)
{
    MAM_HANDLE address_space = NULL;
    MAM_ATTRIBUTES attributes = {0}, hpa_attrs;
    GPM_RANGES_ITERATOR gpm_iter = 0;
    GPA guest_range_addr = 0;
    UINT64 guest_range_size = 0;
    HPA host_range_addr = 0;
    BOOLEAN status = FALSE;
    UINT64 same_memory_type_range_size = 0, covered_guest_range_size = 0;
    VMM_PHYS_MEM_TYPE mem_type;

    VMM_ASSERT(gpm);

    // if (original_perms == FALSE) then permissions = RWX (default)
    attributes.ept_attr.readable = 1;
    attributes.ept_attr.writable = 1;
    attributes.ept_attr.executable = 1;

    address_space = mam_create_mapping(attributes);
    VMM_ASSERT(address_space);
    gpm_iter = gpm_get_ranges_iterator(gpm);
    while(GPM_INVALID_RANGES_ITERATOR != gpm_iter) { // for each range in GPM
        gpm_iter = gpm_get_range_details_from_iterator(gpm, gpm_iter, 
                                    &guest_range_addr, &guest_range_size);
        status = gpm_gpa_to_hpa(gpm, guest_range_addr, &host_range_addr, &hpa_attrs);
        if (original_perms) {
            attributes.ept_attr.readable = hpa_attrs.ept_attr.readable;
            attributes.ept_attr.writable = hpa_attrs.ept_attr.writable;
            attributes.ept_attr.executable = hpa_attrs.ept_attr.executable;
        }
        if(status) {
            covered_guest_range_size = 0;
            do { // add separate mapping per memory type
                mem_type = mtrrs_abstraction_get_range_memory_type(
                                host_range_addr + covered_guest_range_size, 
                                &same_memory_type_range_size,
                                guest_range_size - covered_guest_range_size);
                if (VMM_PHYS_MEM_UNDEFINED == mem_type) {
                    EPT_LOG("  EPT %s:  Undefined mem-type for region %P. Use Uncached\n",
                    guest_range_addr + covered_guest_range_size);
                    mem_type = VMM_PHYS_MEM_UNCACHED;
                }
                attributes.ept_attr.emt = mem_type;
                if(covered_guest_range_size + same_memory_type_range_size > guest_range_size) {
                    same_memory_type_range_size = guest_range_size - covered_guest_range_size;
                }
                mam_insert_range(address_space, guest_range_addr + covered_guest_range_size,
                                 host_range_addr + covered_guest_range_size, same_memory_type_range_size,
                                 attributes);
                covered_guest_range_size += same_memory_type_range_size;
            } while(covered_guest_range_size < guest_range_size);
        }
    }
    return address_space;
}

void ept_invalidate_ept(CPU_ID from UNUSED, void* arg)
{
    EPT_INVEPT_CMD *invept_cmd = (EPT_INVEPT_CMD *) arg;

#ifdef JLMDEBUG
    bprint("ept_invalidate_ept\n");
#endif
    if (invept_cmd->host_cpu_id != ANY_CPU_ID &&
        invept_cmd->host_cpu_id != hw_cpu_id()) {
        // not for this CPU -- ignore command
        return;
    }
    switch(invept_cmd->cmd) {
      case INVEPT_ALL_CONTEXTS: // Not being used currently
        ept_hw_invept_all_contexts();
        break;
      case INVEPT_CONTEXT_WIDE:
        ept_hw_invept_context(invept_cmd->eptp);
        break;
      case INVEPT_INDIVIDUAL_ADDRESS: // Not being used currently
        ept_hw_invept_individual_address(invept_cmd->eptp, invept_cmd->gpa);
        break;
      default:
        VMM_ASSERT(0);
    }
}

BOOLEAN ept_is_ept_supported(void)
{
    return ept_hw_is_ept_supported();
}

BOOLEAN ept_is_ept_enabled(GUEST_CPU_HANDLE gcpu)
{
    return ept_hw_is_ept_enabled(gcpu);
}

UINT64 ept_compute_eptp(GUEST_HANDLE guest, UINT64 ept_root_table_hpa, UINT32 gaw)
{
    EPTP eptp;

    VMM_ASSERT(guest);
    VMM_ASSERT(ept_root_table_hpa);
    VMM_ASSERT(gaw);
    eptp.Uint64 = ept_root_table_hpa;
    eptp.Bits.GAW = ept_hw_get_guest_address_width_encoding(gaw);
    eptp.Bits.ETMT = ept_hw_get_ept_memory_type();
    eptp.Bits.Reserved = 0;
    return eptp.Uint64;
}

//NOTE: This function is expected to be always called with the lock acquired
BOOLEAN ept_enable(GUEST_CPU_HANDLE gcpu)
{
    UINT64 ept_root_table_hpa = 0;
    UINT32 gaw = 0;

    VMM_ASSERT(gcpu);
    ept_get_current_ept(gcpu, &ept_root_table_hpa, &gaw);
    if (!ept_set_eptp(gcpu, ept_root_table_hpa, gaw)) {
        EPT_PRINTERROR("EPT: failed to set eptp\r\n");
        goto failure;
    }
    if (!ept_hw_enable_ept(gcpu)) {
        EPT_PRINTERROR("EPT: failed to enable ept\r\n");
        goto failure;
    }
    return TRUE;

failure:
    return FALSE;
}

//NOTE: This function is expected to be always called with the lock acquired
void ept_disable(GUEST_CPU_HANDLE gcpu)
{
    //ept_acquire_lock();
    ept_hw_disable_ept(gcpu);
    //ept_release_lock();
}

UINT64 ept_get_eptp(GUEST_CPU_HANDLE gcpu)
{
    VMM_ASSERT(gcpu);
    return ept_hw_get_eptp(gcpu);
}

BOOLEAN ept_set_eptp(GUEST_CPU_HANDLE gcpu, UINT64 ept_root_table_hpa, UINT32 gaw)
{
    VMM_ASSERT(gcpu);
    return ept_hw_set_eptp(gcpu, ept_root_table_hpa, gaw);
}

void ept_set_remote_eptp(CPU_ID from, void* arg)
{
    EPT_SET_EPTP_CMD *set_eptp_cmd = arg;
    GUEST_CPU_HANDLE gcpu;
    (void)from;
    gcpu = scheduler_get_current_gcpu_for_guest(set_eptp_cmd->guest_id);
    if(gcpu == NULL || !ept_is_ept_enabled(gcpu)) {
        return;
    }
    ept_set_eptp(gcpu, set_eptp_cmd->ept_root_table_hpa, set_eptp_cmd->gaw);
    ept_invalidate_ept(ANY_CPU_ID, set_eptp_cmd->invept_cmd);
}

EPT_GUEST_STATE *ept_find_guest_state(GUEST_ID guest_id)
{
    EPT_GUEST_STATE *ept_guest_state = NULL;
    LIST_ELEMENT *iter = NULL;
    BOOLEAN found = FALSE;

    LIST_FOR_EACH(ept.guest_state, iter) {
        ept_guest_state = LIST_ENTRY(iter, EPT_GUEST_STATE, list);
        if(ept_guest_state->guest_id == guest_id) {
            found = TRUE;
            break;
        }
    }
    if(found) {
        return ept_guest_state;
    }
    return NULL;
}

static BOOLEAN ept_guest_initialize(GUEST_HANDLE guest)
{
    UINT32 i;
    EPT_GUEST_STATE *ept_guest = NULL;

#ifdef JLMDEBUG
    bprint("ept_guest_initialize\n");
#endif
    ept_guest = (EPT_GUEST_STATE *) vmm_malloc(sizeof(EPT_GUEST_STATE));
    VMM_ASSERT(ept_guest);
    ept_guest->guest_id = guest_get_id(guest);
    list_add(ept.guest_state, ept_guest->list);
    ept_guest->gcpu_state = (EPT_GUEST_CPU_STATE **) vmm_malloc(ept.num_of_cpus * sizeof(EPT_GUEST_CPU_STATE*));
    VMM_ASSERT(ept_guest->gcpu_state);
    for (i = 0; i < ept.num_of_cpus; i++) {
        ept_guest->gcpu_state[i] = (EPT_GUEST_CPU_STATE *) vmm_malloc(sizeof(EPT_GUEST_CPU_STATE));
        VMM_ASSERT(ept_guest->gcpu_state[i]);
    }
    event_global_register( EVENT_BEGIN_GPM_MODIFICATION_BEFORE_CPUS_STOPPED,
                            ept_begin_gpm_modification_before_cpus_stop);
    event_global_register( EVENT_END_GPM_MODIFICATION_BEFORE_CPUS_RESUMED,
                            ept_end_gpm_modification_before_cpus_resume);
    event_global_register( EVENT_END_GPM_MODIFICATION_AFTER_CPUS_RESUMED,
                            ept_end_gpm_modification_after_cpus_resume);

    return TRUE;
}

static BOOLEAN ept_guest_cpu_initialize(GUEST_CPU_HANDLE gcpu)
{
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    EPT_GUEST_STATE *ept_guest_state = NULL;

    EPT_LOG("EPT: CPU#%d ept_guest_cpu_initialize\r\n", hw_cpu_id());
    vcpu_id = guest_vcpu( gcpu );
    VMM_ASSERT(vcpu_id);
    ept_guest_state = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest_state);
    ept_guest_cpu = ept_guest_state->gcpu_state[vcpu_id->guest_cpu_id];
    //During S3 resume, these values need to be updated
    ept_guest_cpu->cr0 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);
    ept_guest_cpu->cr4 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
    if (!ept_guest_cpu->is_initialized) {
        ept_register_events(gcpu);
        ept_guest_cpu->is_initialized = TRUE;
    }
    return TRUE;
}

static void ept_fill_vmexit_request(VMEXIT_CONTROL *vmexit_request)
{
#ifdef JLMDEBUG
    bprint("ept_fill_vmexit_request\n");
#endif
    vmm_zeromem(vmexit_request, sizeof(VMEXIT_CONTROL));
    if(!is_unrestricted_guest_supported()) {
        vmexit_request->cr0.bit_request = CR0_PG;
        vmexit_request->cr0.bit_mask    = CR0_PG;
        vmexit_request->cr4.bit_request = CR4_PAE;
        vmexit_request->cr4.bit_mask    = CR4_PAE;
    }
}

static BOOLEAN ept_add_gcpu(GUEST_CPU_HANDLE gcpu, void *pv UNUSED)
{
    EVENT_GCPU_ACTIVITY_STATE_CHANGE_DATA activity_state;
    VMEXIT_CONTROL vmexit_request;

#ifdef JLMDEBUG
    bprint("ept_add_gcpu\n");
#endif
    vmm_zeromem(&activity_state, sizeof(activity_state));
    vmm_zeromem(&vmexit_request, sizeof(vmexit_request));
    event_gcpu_register(EVENT_GCPU_ACTIVITY_STATE_CHANGE, gcpu, 
                        (event_callback) ept_gcpu_activity_state_change);
    activity_state.new_state = gcpu_get_activity_state(gcpu);
    if(ept_is_gcpu_active(activity_state.new_state))
    {// if gcpu already active, fire manually
        ept_gcpu_activity_state_change(gcpu, &activity_state);
    }
    // setup control only if gcpu is added on this host CPU
    if(hw_cpu_id() == scheduler_get_host_cpu_id(gcpu))
    {
        ept_fill_vmexit_request(&vmexit_request);
        gcpu_control_setup(gcpu, &vmexit_request);
    }
    return TRUE;
}

static void ept_add_static_guest(GUEST_HANDLE guest)
{
    GUEST_CPU_HANDLE gcpu;
    GUEST_GCPU_ECONTEXT gcpu_context;
    VMEXIT_CONTROL vmexit_request;
    UINT64 ept_root_table_hpa = 0;
    UINT32 ept_gaw = 0;

#ifdef JLMDEBUG
    bprint("ept_add_static_guest\n");
#endif
    EPT_LOG("ept CPU#%d: activate ept\r\n", hw_cpu_id());
    ept_fill_vmexit_request(&vmexit_request);
    // request needed vmexits
    guest_control_setup(guest, &vmexit_request);
    ept_guest_initialize(guest);
    // Initialize default EPT
    ept_create_default_ept(guest, guest_get_startup_gpm(guest));
    // Get default EPT
    ept_get_default_ept(guest, &ept_root_table_hpa, &ept_gaw);
    for(gcpu = guest_gcpu_first(guest, &gcpu_context); gcpu; gcpu = guest_gcpu_next(&gcpu_context)) {
        ept_add_gcpu(gcpu, NULL);
        // Set EPT pointer (of each GCPU) to default EPT
        ept_set_current_ept(gcpu, ept_root_table_hpa, ept_gaw);
    }
}

static BOOLEAN ept_add_dynamic_guest(GUEST_CPU_HANDLE gcpu UNUSED, void *pv)
{
    EVENT_GUEST_CREATE_DATA *guest_create_event_data = (EVENT_GUEST_CREATE_DATA *) pv;
    GUEST_HANDLE            guest = guest_handle(guest_create_event_data->guest_id);
    VMM_PAGING_POLICY       pg_policy;
    POL_RETVAL              policy_status;

#ifdef JLMDEBUG
    bprint("ept_add_dynamic_guest\n");
#endif
    policy_status = get_paging_policy(guest_policy(guest), &pg_policy);
    VMM_ASSERT(POL_RETVAL_SUCCESS == policy_status);
    if (POL_PG_EPT == pg_policy) {
        ept_guest_initialize(guest_handle(guest_create_event_data->guest_id));
    }
    return TRUE;
}

void init_ept_addon(UINT32 num_of_cpus)
{
    GUEST_HANDLE   guest;
    GUEST_ECONTEXT guest_ctx;

    if (!global_policy_uses_ept()) {
        return;
    }
    vmm_zeromem(&ept, sizeof(ept));
    ept.num_of_cpus = num_of_cpus;
    EPT_LOG("init_ept_addon: Initialize EPT num_cpus %d\n", num_of_cpus);
    list_init(ept.guest_state);
    lock_initialize(&ept.lock);
    event_global_register(EVENT_GUEST_CREATE, ept_add_dynamic_guest);
    event_global_register(EVENT_GCPU_ADD, (event_callback) ept_add_gcpu);
    for(guest = guest_first(&guest_ctx); guest; guest = guest_next(&guest_ctx)) {
        ept_add_static_guest(guest);
    }
}

BOOLEAN ept_page_walk(UINT64 first_table, UINT64 addr, UINT32 gaw)
{
    UINT64 *table = (UINT64 *) first_table;
    UINT64 *entry = NULL;

    EPT_LOG("EPT page walk addr %p\r\n", addr);
    if(gaw > 39) {
        entry = &table[(addr & 0xFF8000000000) >> 39];
        EPT_LOG("Level 4: table %p entry %p\r\n", table, *entry);
        table = (UINT64 *) ((*entry) & ~0xfff);
        if(((*entry) & 0x1) == 0) {
            EPT_LOG("Entry not present\r\n");
            return FALSE;
        }
    }
    entry = &table[(addr & 0x7fc0000000) >> 30];
    EPT_LOG("Level 3: table %p entry %p\r\n", table, *entry);
    if(((*entry) & 0x1) == 0) {
        EPT_LOG("Entry not present\r\n");
        return FALSE;
    }
    table = (UINT64 *) ((*entry) & ~0xfff);
    entry = &table[(addr & 0x3FE00000) >> 21];
    EPT_LOG("Level 2: table %p entry %p\r\n", table, *entry);
    table = (UINT64 *) ((*entry) & ~0xfff);
    if(((*entry) & 0x1) == 0) {
        EPT_LOG("Entry not present\r\n");
        return FALSE;
    }
    entry = &table[(addr & 0x1ff000) >> 12];
    EPT_LOG("Level 1: table %p entry %p\r\n", table, *entry);
    return TRUE;
}

#ifdef DEBUG
void ept_print(IN GUEST_HANDLE guest, IN MAM_HANDLE address_space)
{
    MAM_MEMORY_RANGES_ITERATOR iter;
    MAM_MAPPING_RESULT res;

    iter = mam_get_memory_ranges_iterator(address_space);

    while (iter != MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        GPA curr_gpa;
        UINT64 curr_size;
        HPA curr_hpa;
        MAM_ATTRIBUTES attrs;
        iter = mam_get_range_details_from_iterator(address_space, iter,
                                                   (UINT64*)&curr_gpa, &curr_size);
        VMM_ASSERT(curr_size != 0);

        res = mam_get_mapping(address_space, curr_gpa, &curr_hpa, &attrs);
        if (res == MAM_MAPPING_SUCCESSFUL) {
            EPT_LOG("EPT guest#%d: GPA %p -> HPA %p\r\n", curr_gpa, curr_hpa);
        }
    }
}
#endif

#ifdef INCLUDE_UNUSED_CODE
static
void ept_reset_initiate(GUEST_HANDLE guest)
{
    GUEST_CPU_HANDLE gcpu;

    VMM_ASSERT(guest);
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));

    if(gcpu != NULL && ept_is_ept_enabled(gcpu)) {
        ept_disable(gcpu);
        ept_enable(gcpu);
    }
}

void ept_single_cpu_update(GUEST_HANDLE guest, TMSL_MEM_VIEW_HANDLE handle)
{
    EPT_INVEPT_CMD invept_cmd;

#ifdef JLMDEBUG
    bprint("ept_single_cpu_update\n");
#endif
    invept_cmd.host_cpu_id = ANY_CPU_ID;
    invept_cmd.cmd = INVEPT_CONTEXT_WIDE;
    invept_cmd.eptp = ept_compute_eptp(guest, handle);
    ept_invalidate_ept(ANY_CPU_ID, &invept_cmd);
}

static void ept_reset_local(CPU_ID from UNUSED, void* arg)
{
    GUEST_HANDLE guest = (GUEST_HANDLE) arg;
    GUEST_CPU_HANDLE gcpu;

    VMM_ASSERT(guest);
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    if(gcpu != NULL && ept_is_ept_enabled(gcpu)) {
        ept_disable(gcpu);
        ept_enable(gcpu);
    }
}

#endif

#ifdef INCLUDE_UNUSED_CODE
static void ept_exec_invept(CPU_ID dest, INVEPT_CMD_TYPE cmd,
                     UINT64 eptp, UINT64 gpa)
{
    IPC_DESTINATION ipc_dest;
    EPT_INVEPT_CMD invept_cmd;

    vmm_zeromem(&ipc_dest, sizeof(ipc_dest));
    vmm_zeromem(&invept_cmd, sizeof(invept_cmd));

    invept_cmd.host_cpu_id = dest;
    invept_cmd.cmd = cmd;
    invept_cmd.eptp = eptp;
    invept_cmd.gpa = gpa;
    ipc_dest.addr_shorthand = LOCAL_APIC_BROADCAST_MODE_ALL_EXCLUDING_SELF;
    ipc_execute_handler_sync(ipc_dest, ept_invalidate_ept, (void *) &invept_cmd);
}

void ept_invalidate_guest_ept_on_all_cpus(IN GUEST_HANDLE guest)
{
    UINT64 eptp = 0;

    ept_acquire_lock();
    eptp = ept_compute_eptp(guest);
    ept_exec_invept(ANY_CPU_ID, INVEPT_CONTEXT_WIDE, eptp, 0);
    EPT_LOG("Invalidate eptp %p on CPU#%d\r\n", eptp, hw_cpu_id());
    ept_hw_invept_context(eptp);
    ept_release_lock();
}

BOOLEAN ept_invept_all_contexts(IN CPU_ID host_cpu_id)
{
    BOOLEAN res = FALSE;

    ept_acquire_lock();
    if(host_cpu_id == hw_cpu_id()) {
        res = ept_hw_invept_all_contexts();
    }
    else {
        ept_exec_invept(ANY_CPU_ID, INVEPT_ALL_CONTEXTS, 0, 0);
    }
    ept_release_lock();
    return res;
}

BOOLEAN ept_invept_context(IN CPU_ID host_cpu_id, UINT64 eptp)
{
    BOOLEAN res = FALSE;

    ept_acquire_lock();
    if(host_cpu_id == hw_cpu_id()) {
        res = ept_hw_invept_context(eptp);
    }
    else {
        ept_exec_invept(ANY_CPU_ID, INVEPT_CONTEXT_WIDE, eptp, 0);
    }
    ept_release_lock();
    return res;
}

BOOLEAN ept_invept_individual_address(IN CPU_ID host_cpu_id, UINT64 eptp, ADDRESS gpa)
{
    BOOLEAN res = FALSE;

    ept_acquire_lock();
    if(host_cpu_id == hw_cpu_id()) {
        res = ept_hw_invept_individual_address(eptp, gpa);
    }
    else {
        ept_exec_invept(ANY_CPU_ID, INVEPT_INDIVIDUAL_ADDRESS, eptp, gpa);
    }
    ept_release_lock();
    return res;
}
#endif

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN ept_add_mapping(IN GUEST_HANDLE guest, IN GPA src, IN HPA dest, IN UINT64 size,
                        IN BOOLEAN readable, IN BOOLEAN writable, IN BOOLEAN executable)
{
    EPT_GUEST_STATE *ept_guest = NULL;
    UINT64 eptp = 0;
    GUEST_ID guest_id = guest_get_id(guest);
    MAM_ATTRIBUTES attrs;
    BOOLEAN status = FALSE;
    EPT_INVEPT_CMD invept_cmd;

    VMM_ASSERT( guest );
    vmm_zeromem(&invept_cmd, sizeof(invept_cmd));
    ept_guest = ept_find_guest_state(guest_id);
    VMM_ASSERT(ept_guest);
    ept_acquire_lock();
    stop_all_cpus();
    attrs.uint32 = 0;
    attrs.ept_attr.readable = readable;
    attrs.ept_attr.writable = writable;
    attrs.ept_attr.executable = executable;
    status = mam_insert_range(ept_guest->address_space, src, dest, size, attrs);
    eptp = ept_compute_eptp(guest);
    invept_cmd.host_cpu_id = ANY_CPU_ID;
    invept_cmd.cmd = INVEPT_CONTEXT_WIDE;
    invept_cmd.eptp = eptp;
    start_all_cpus(ept_invalidate_ept, (void *) &invept_cmd);
    ept_hw_invept_context(eptp);
    ept_release_lock();
    return status;
}

BOOLEAN ept_remove_mapping(IN GUEST_HANDLE guest, IN GPA src,
                           IN UINT64 size, IN MAM_MAPPING_RESULT reason)
{
    EPT_GUEST_STATE *ept_guest = NULL;
    UINT64 eptp = 0;
    GUEST_ID guest_id = guest_get_id(guest);
    BOOLEAN status = FALSE;
    EPT_INVEPT_CMD invept_cmd;

    VMM_ASSERT( guest );
    ept_guest = ept_find_guest_state(guest_id);
    VMM_ASSERT(ept_guest);
    ept_acquire_lock();
    stop_all_cpus();
    status = mam_insert_not_existing_range(ept_guest->address_space, src, size, reason);
    eptp = ept_compute_eptp(guest);
    vmm_zeromem(&invept_cmd, sizeof(invept_cmd));
    invept_cmd.host_cpu_id = ANY_CPU_ID;
    invept_cmd.cmd = INVEPT_CONTEXT_WIDE;
    invept_cmd.eptp = eptp;
    start_all_cpus(ept_invalidate_ept, (void *) &invept_cmd);
    ept_hw_invept_context(eptp);
    ept_release_lock();
    return status;
}

MAM_MAPPING_RESULT ept_get_mapping(IN GUEST_HANDLE guest, IN GPA src,
                                   OUT HPA *dest, OUT MAM_ATTRIBUTES *attrs)
{
    EPT_GUEST_STATE *ept_guest = NULL;
    GUEST_ID guest_id = guest_get_id(guest);
    MAM_MAPPING_RESULT res;

    ept_guest = ept_find_guest_state(guest_id);
    VMM_ASSERT(ept_guest);
    ept_acquire_lock();
    res = mam_get_mapping(ept_guest, src, dest, attrs);
    ept_release_lock();
    return res;
}

static BOOLEAN ept_allow_uvmm_heap_access(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE guest = NULL;
    HVA heap_base_hva = 0;
    HPA heap_base_hpa = 0;
    UINT32 heap_size = 0;
    VMM_PHYS_MEM_TYPE mem_type;
    BOOLEAN status = FALSE;
    UINT64 same_memory_type_range_size = 0, covered_heap_range_size = 0;
    MAM_ATTRIBUTES attributes = {0};
    EPT_GUEST_STATE *ept_guest = NULL;

    guest = gcpu_guest_handle(gcpu);
    ept_guest = ept_find_guest_state(guest_get_id(guest));
    VMM_ASSERT(ept_guest);
    vmm_heap_get_details(&heap_base_hva, &heap_size);
    status = hmm_hva_to_hpa(heap_base_hva, &heap_base_hpa);
    VMM_ASSERT(status);
    attributes.ept_attr.readable = 1;
    attributes.ept_attr.writable = 1;
    while(covered_heap_range_size < heap_size) {
        mem_type = mtrrs_abstraction_get_range_memory_type(
                               heap_base_hpa + covered_heap_range_size,
                               &same_memory_type_range_size);
        attributes.ept_attr.emt = mem_type;
        EPT_LOG("  EPT add uvmm heap range: gpa %p -> hpa %p; size %p; mem_type %d\r\n",
            heap_base_hpa, heap_base_hpa, same_memory_type_range_size, mem_type);

        if(covered_heap_range_size + same_memory_type_range_size > heap_size) { // normalize
            same_memory_type_range_size = heap_size - covered_heap_range_size;
        }
        ept_add_mapping(guest, heap_base_hpa + covered_heap_range_size,
            heap_base_hpa + covered_heap_range_size, same_memory_type_range_size,
            TRUE, // readable
            TRUE, // writable
            FALSE // executable
            );
        covered_heap_range_size += same_memory_type_range_size;
        if(covered_heap_range_size > heap_size) { // normalize
            covered_heap_range_size = heap_size;
        }
    }
    return TRUE;
}

static BOOLEAN ept_deny_uvmm_heap_access(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE guest = NULL;
    HVA heap_base_hva = 0;
    HPA heap_base_hpa = 0;
    UINT32 heap_size = 0;
    BOOLEAN status = FALSE;
    UINT32 i = 0;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    const VIRTUAL_CPU_ID* vcpu_id = NULL;

    VMM_ASSERT( gcpu );
    vcpu_id = guest_vcpu( gcpu );
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);

    for(i = 0; i < ept.num_of_cpus; i++) {
        ept_guest_cpu = ept_guest->gcpu_state[i];
        if(ept_guest_cpu->is_initialized
           && (ept_guest_cpu->cr0 & CR0_PG) == 0) { // cannot deny access - another gcpu not paged and uses flat page tables
            return FALSE;
        }
    }
    guest = gcpu_guest_handle(gcpu);
    vmm_heap_get_details(&heap_base_hva, &heap_size);
    status = hmm_hva_to_hpa(heap_base_hva, &heap_base_hpa);
    VMM_ASSERT(status);
    EPT_LOG("  EPT remove uvmm heap range: gpa %p -> hpa %p; size %p;\r\n",
        heap_base_hpa, heap_base_hpa, heap_size);
    ept_remove_mapping(guest, heap_base_hpa, heap_size, 0);
    return TRUE;
}
#endif
