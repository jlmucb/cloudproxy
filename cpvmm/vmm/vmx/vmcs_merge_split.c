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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMCS_MERGE_SPLIT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMCS_MERGE_SPLIT_C, __condition)
#include <vmm_defs.h>
#include <vmm_dbg.h>
#include <vmcs_api.h>
#include <vmx_ctrl_msrs.h>
#include <vmx_vmcs.h>
#include <pfec.h>
#include <host_memory_manager_api.h>
#include <guest.h>
#include <guest_cpu.h>
#include <em64t_defs.h>
#include <gpm_api.h>
#include <ia32_defs.h>
#include "vmcs_internal.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

// do not report warning on unused params
#pragma warning( disable: 4100 )

typedef UINT32 MSR_LIST_COPY_MODE; // mitmask
#define MSR_LIST_COPY_NO_CHANGE 0x0
#define MSR_LIST_COPY_WITH_EFER_CHANGE 0x1
#define MSR_LIST_COPY_AND_SET_32_BIT_MODE_IN_EFER (0x00 | MSR_LIST_COPY_WITH_EFER_CHANGE)
#define MSR_LIST_COPY_AND_SET_64_BIT_MODE_IN_EFER (0x10 | MSR_LIST_COPY_WITH_EFER_CHANGE)
#define MSR_LIST_COPY_UPDATE_GCPU 0x100

typedef enum {
    MS_HVA,
    MS_GPA,
    MS_HPA
} MS_MEM_ADDRESS_TYPE;


static void ms_merge_timer_to_level2(VMCS_OBJECT *vmcs_0, VMCS_OBJECT *vmcs_1, VMCS_OBJECT *vmcs_m);
static void ms_split_timer_from_level2(VMCS_OBJECT *vmcs_0, VMCS_OBJECT *vmcs_1, VMCS_OBJECT *vmcs_m);

static void ms_copy_guest_state_to_level1_vmcs(IN GUEST_CPU_HANDLE gcpu, IN BOOLEAN copy_crs) {
    IN VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy(gcpu), VMCS_LEVEL_1);
    IN VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy(gcpu), VMCS_MERGED);
    UINT64 value;
    UINT16 selector;
    UINT64 base;
    UINT32 limit;
    UINT32 ar;
    UINT64 vmentry_control;

    if (copy_crs) {
        value = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR0, VMCS_MERGED);
        gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR0, value, VMCS_LEVEL_1);

        value = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR3, VMCS_MERGED);
        gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR3, value, VMCS_LEVEL_1);

        value = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR4, VMCS_MERGED);
        gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR4, value, VMCS_LEVEL_1);
    }

    value = gcpu_get_debug_reg_layered(gcpu, IA32_REG_DR7, VMCS_MERGED);
    gcpu_set_debug_reg_layered(gcpu, IA32_REG_DR7, value, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_ES, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_ES, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_CS, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_CS, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_SS, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_SS, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_DS, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_DS, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_FS, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_FS, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_GS, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_GS, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_LDTR, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_LDTR, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_TR, &selector, &base, &limit, &ar, VMCS_MERGED);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_TR, selector, base, limit, ar, VMCS_LEVEL_1);

    gcpu_get_gdt_reg_layered(gcpu, &base, &limit, VMCS_MERGED);
    gcpu_set_gdt_reg_layered(gcpu, base, limit, VMCS_LEVEL_1);

    gcpu_get_idt_reg_layered(gcpu, &base, &limit, VMCS_MERGED);
    gcpu_set_idt_reg_layered(gcpu, base, limit, VMCS_LEVEL_1);

    value = gcpu_get_gp_reg_layered(gcpu, IA32_REG_RSP, VMCS_MERGED);
    gcpu_set_gp_reg_layered(gcpu, IA32_REG_RSP, value, VMCS_LEVEL_1);

    value = gcpu_get_gp_reg_layered(gcpu, IA32_REG_RIP, VMCS_MERGED);
    gcpu_set_gp_reg_layered(gcpu, IA32_REG_RIP, value, VMCS_LEVEL_1);

    value = gcpu_get_gp_reg_layered(gcpu, IA32_REG_RFLAGS, VMCS_MERGED);
    gcpu_set_gp_reg_layered(gcpu, IA32_REG_RFLAGS, value, VMCS_LEVEL_1);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_CS, VMCS_MERGED);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_CS, value, VMCS_LEVEL_1);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_ESP, VMCS_MERGED);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_ESP, value, VMCS_LEVEL_1);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_EIP, VMCS_MERGED);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_EIP, value, VMCS_LEVEL_1);

    value = gcpu_get_pending_debug_exceptions_layered(gcpu, VMCS_MERGED);
    gcpu_set_pending_debug_exceptions_layered(gcpu, value, VMCS_LEVEL_1);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SMBASE, VMCS_MERGED);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SMBASE, value, VMCS_LEVEL_1);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_DEBUGCTL, VMCS_MERGED);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_DEBUGCTL, value, VMCS_LEVEL_1);

    if (vmcs_field_is_supported(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL))
    {
        value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_PERF_GLOBAL_CTRL, VMCS_MERGED);
        gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_PERF_GLOBAL_CTRL, value, VMCS_LEVEL_1);
    }

    value = vmcs_read(merged_vmcs, VMCS_GUEST_WORKING_VMCS_PTR);
    vmcs_write(level1_vmcs, VMCS_GUEST_WORKING_VMCS_PTR, value);

    value = gcpu_get_interruptibility_state_layered(gcpu, VMCS_MERGED);
    gcpu_set_interruptibility_state_layered(gcpu, (UINT32)value, VMCS_LEVEL_1);

    value = gcpu_get_activity_state_layered(gcpu, VMCS_MERGED);
    gcpu_set_activity_state_layered(gcpu, (IA32_VMX_VMCS_GUEST_SLEEP_STATE)value, VMCS_LEVEL_1);

    // Copy IA32e Guest bit is a part of guest state, so copy it here
#define VMENTER_IA32E_MODE_GUEST 0x200
    vmentry_control = vmcs_read(merged_vmcs, VMCS_ENTER_CONTROL_VECTOR);
    vmcs_update(level1_vmcs, VMCS_ENTER_CONTROL_VECTOR, vmentry_control, VMENTER_IA32E_MODE_GUEST);

    // TODO VMCS v2 fields
}

static void ms_copy_guest_state_flom_level1(IN GUEST_CPU_HANDLE gcpu, IN BOOLEAN copy_crs) {
    IN VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy(gcpu), VMCS_LEVEL_1);
    IN VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy(gcpu), VMCS_MERGED);
    UINT64 value;
    UINT16 selector;
    UINT64 base;
    UINT32 limit;
    UINT32 ar;

    if (copy_crs) {
        value = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR0, VMCS_LEVEL_1);
        gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR0, value, VMCS_MERGED);

        value = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR3, VMCS_LEVEL_1);
        gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR3, value, VMCS_MERGED);

        value = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR4, VMCS_LEVEL_1);
        gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR4, value, VMCS_MERGED);
    }

    value = gcpu_get_debug_reg_layered(gcpu, IA32_REG_DR7, VMCS_LEVEL_1);
    gcpu_set_debug_reg_layered(gcpu, IA32_REG_DR7, value, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_ES, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_ES, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_CS, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_CS, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_SS, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_SS, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_DS, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_DS, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_FS, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_FS, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_GS, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_GS, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_LDTR, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_LDTR, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_segment_reg_layered(gcpu, IA32_SEG_TR, &selector, &base, &limit, &ar, VMCS_LEVEL_1);
    gcpu_set_segment_reg_layered(gcpu, IA32_SEG_TR, selector, base, limit, ar, VMCS_MERGED);

    gcpu_get_gdt_reg_layered(gcpu, &base, &limit, VMCS_LEVEL_1);
    gcpu_set_gdt_reg_layered(gcpu, base, limit, VMCS_MERGED);

    gcpu_get_idt_reg_layered(gcpu, &base, &limit, VMCS_LEVEL_1);
    gcpu_set_idt_reg_layered(gcpu, base, limit, VMCS_MERGED);

    value = gcpu_get_gp_reg_layered(gcpu, IA32_REG_RSP, VMCS_LEVEL_1);
    gcpu_set_gp_reg_layered(gcpu, IA32_REG_RSP, value, VMCS_MERGED);

    value = gcpu_get_gp_reg_layered(gcpu, IA32_REG_RIP, VMCS_LEVEL_1);
    gcpu_set_gp_reg_layered(gcpu, IA32_REG_RIP, value, VMCS_MERGED);

    value = gcpu_get_gp_reg_layered(gcpu, IA32_REG_RFLAGS, VMCS_LEVEL_1);
    gcpu_set_gp_reg_layered(gcpu, IA32_REG_RFLAGS, value, VMCS_MERGED);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_CS, VMCS_LEVEL_1);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_CS, value, VMCS_MERGED);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_ESP, VMCS_LEVEL_1);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_ESP, value, VMCS_MERGED);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_EIP, VMCS_LEVEL_1);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_EIP, value, VMCS_MERGED);

    value = gcpu_get_pending_debug_exceptions_layered(gcpu, VMCS_LEVEL_1);
    gcpu_set_pending_debug_exceptions_layered(gcpu, value, VMCS_MERGED);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_SMBASE, VMCS_LEVEL_1);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SMBASE, value, VMCS_MERGED);

    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_DEBUGCTL, VMCS_LEVEL_1);
    gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_DEBUGCTL, value, VMCS_MERGED);

    if (vmcs_field_is_supported(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL)) {
        value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_PERF_GLOBAL_CTRL, VMCS_LEVEL_1);
        gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_PERF_GLOBAL_CTRL, value, VMCS_MERGED);
    }
    value = vmcs_read(level1_vmcs, VMCS_GUEST_WORKING_VMCS_PTR);
    vmcs_write(merged_vmcs, VMCS_GUEST_WORKING_VMCS_PTR, value);

    value = gcpu_get_interruptibility_state_layered(gcpu, VMCS_LEVEL_1);
    gcpu_set_interruptibility_state_layered(gcpu, (UINT32)value, VMCS_MERGED);

    value = (UINT64)gcpu_get_activity_state_layered(gcpu, VMCS_LEVEL_1);
    gcpu_set_activity_state_layered(gcpu, (IA32_VMX_VMCS_GUEST_SLEEP_STATE)value, VMCS_MERGED);

    // TODO VMCS v2 fields
}

static void ms_copy_data_fields(IN OUT VMCS_OBJECT* vmcs_to, IN VMCS_OBJECT* vmcs_from) {
    UINT64 value;

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_INSTRUCTION_ERROR_CODE);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_INSTRUCTION_ERROR_CODE, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_REASON);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_REASON, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_EXCEPTION_INFO);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_EXCEPTION_INFO, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_EXCEPTION_ERROR_CODE);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_EXCEPTION_ERROR_CODE, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_IDT_VECTORING);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_IDT_VECTORING, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_IDT_VECTORING_ERROR_CODE);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_IDT_VECTORING_ERROR_CODE, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_INSTRUCTION_LENGTH, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_INSTRUCTION_INFO);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_INSTRUCTION_INFO, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_QUALIFICATION);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_QUALIFICATION, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_IO_RCX);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_IO_RCX, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_IO_RSI);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_IO_RSI, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_IO_RDI);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_IO_RDI, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_IO_RIP);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_IO_RIP, value);

    value = vmcs_read(vmcs_from, VMCS_EXIT_INFO_GUEST_LINEAR_ADDRESS);
    vmcs_write_nocheck(vmcs_to, VMCS_EXIT_INFO_GUEST_LINEAR_ADDRESS, value);
    // TODO: Copy VMCS v2 fields
}

static void ms_copy_host_state(IN OUT VMCS_OBJECT* vmcs_to, IN VMCS_OBJECT* vmcs_from) {
    UINT64 value;

    value = vmcs_read(vmcs_from, VMCS_HOST_CR0);
    vmcs_write(vmcs_to, VMCS_HOST_CR0, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_CR3);
    vmcs_write(vmcs_to, VMCS_HOST_CR3, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_CR4);
    vmcs_write(vmcs_to, VMCS_HOST_CR4, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_ES_SELECTOR);
    vmcs_write(vmcs_to, VMCS_HOST_ES_SELECTOR, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_CS_SELECTOR);
    vmcs_write(vmcs_to, VMCS_HOST_CS_SELECTOR, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_SS_SELECTOR);
    vmcs_write(vmcs_to, VMCS_HOST_SS_SELECTOR, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_DS_SELECTOR);
    vmcs_write(vmcs_to, VMCS_HOST_DS_SELECTOR, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_FS_SELECTOR);
    vmcs_write(vmcs_to, VMCS_HOST_FS_SELECTOR, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_FS_BASE);
    vmcs_write(vmcs_to, VMCS_HOST_FS_BASE, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_GS_SELECTOR);
    vmcs_write(vmcs_to, VMCS_HOST_GS_SELECTOR, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_GS_BASE);
    vmcs_write(vmcs_to, VMCS_HOST_GS_BASE, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_TR_SELECTOR);
    vmcs_write(vmcs_to, VMCS_HOST_TR_SELECTOR, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_TR_BASE);
    vmcs_write(vmcs_to, VMCS_HOST_TR_BASE, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_GDTR_BASE);
    vmcs_write(vmcs_to, VMCS_HOST_GDTR_BASE, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_IDTR_BASE);
    vmcs_write(vmcs_to, VMCS_HOST_IDTR_BASE, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_RSP);
    vmcs_write(vmcs_to, VMCS_HOST_RSP, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_RIP);
    vmcs_write(vmcs_to, VMCS_HOST_RIP, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_SYSENTER_CS);
    vmcs_write(vmcs_to, VMCS_HOST_SYSENTER_CS, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_SYSENTER_ESP);
    vmcs_write(vmcs_to, VMCS_HOST_SYSENTER_ESP, value);

    value = vmcs_read(vmcs_from, VMCS_HOST_SYSENTER_EIP);
    vmcs_write(vmcs_to, VMCS_HOST_SYSENTER_EIP, value);

    // TODO VMCS v2 fields
}

static BOOLEAN may_cause_vmexit_on_page_fault(IN GUEST_CPU_HANDLE gcpu, IN VMCS_LEVEL level) {
    UINT32 possible_pfec_mask = (1 << VMM_PFEC_NUM_OF_USED_BITS) - 1;
    UINT32 vmcs_pfec_mask;
    UINT32 vmcs_pfec_match;
    IA32_VMCS_EXCEPTION_BITMAP exception_ctrls;

    gcpu_get_pf_error_code_mask_and_match_layered(gcpu, level, &vmcs_pfec_mask, &vmcs_pfec_match);

    exception_ctrls.Uint32 = (UINT32)gcpu_get_exceptions_map_layered(gcpu, level);

    if (exception_ctrls.Bits.PF == 1) {

        if ((vmcs_pfec_match & possible_pfec_mask) != vmcs_pfec_match) {
            // There are bits which are set in PFEC_MATCH, but will be
            // cleared in actual PFEC
            return FALSE;
        }

        if ((vmcs_pfec_mask & vmcs_pfec_match) != vmcs_pfec_match) {
            // There are bits which are set in PFEC_MATCH, but are
            // cleared in PFEC_MASK
            return FALSE;
        }

        // There still can be values of PFEC_MASK and PFEC_MATCH that will
        // never cause VMExits on PF.
        return TRUE;
    }
    else {
        if ((vmcs_pfec_match == 0x00000000) &&
            ((vmcs_pfec_mask & possible_pfec_mask) == 0)) {
            return FALSE;
        }

        return TRUE;
    }
}

static UINT64 ms_merge_cr_shadow(IN GUEST_CPU_HANDLE gcpu, IN VMM_IA32_CONTROL_REGISTERS reg) {
    UINT64 level1_shadow = gcpu_get_guest_visible_control_reg_layered(gcpu, reg, VMCS_LEVEL_1);
    UINT64 level0_mask;
    UINT64 level1_mask;
    UINT64 level1_reg = gcpu_get_control_reg_layered(gcpu, reg, VMCS_LEVEL_1);
    UINT64 merged_shadow;
    UINT64 mask_tmp;

    if (reg == IA32_CTRL_CR0) {
        level0_mask = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_LEVEL_0);
        level1_mask = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_LEVEL_1);
    }
    else {
        VMM_ASSERT(reg == IA32_CTRL_CR4);
        level0_mask = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_LEVEL_0);
        level1_mask = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_LEVEL_1);
    }

    merged_shadow = level1_shadow;

    // clear all bits that are 0 in mask
    merged_shadow &= level1_mask;

    // Copy bits that are 0 in level1_mask and
    // 1 in level0_mask
    // from level1_reg
    mask_tmp = (level0_mask ^ level1_mask) & level0_mask;
    merged_shadow |= (mask_tmp & level1_reg);

    return merged_shadow;
}

static void* ms_retrieve_ptr_to_additional_memory(IN VMCS_OBJECT* vmcs, IN VMCS_FIELD field,
                                           IN MS_MEM_ADDRESS_TYPE mem_type) {
    UINT64 addr_value = vmcs_read(vmcs, field);
    UINT64 addr_hpa;
    UINT64 addr_hva;
    MAM_ATTRIBUTES attrs;

    if (mem_type == MS_HVA) {
        return (void*)addr_value;
    }

    if (mem_type == MS_GPA) {
        GUEST_CPU_HANDLE gcpu = vmcs_get_owner(vmcs);
        GUEST_HANDLE guest = gcpu_guest_handle(gcpu);
        GPM_HANDLE gpm = gcpu_get_current_gpm(guest);
        if (!gpm_gpa_to_hpa(gpm, addr_value, &addr_hpa, &attrs)) {
            VMM_DEADLOOP();
        }
    }
    else {
        VMM_ASSERT(mem_type == MS_HPA);
        addr_hpa = addr_value;
    }

    if (!hmm_hpa_to_hva(addr_hpa, &addr_hva)) {
        VMM_DEADLOOP();
    }

    return (void*)addr_hva;
}

static void ms_merge_bitmaps(IN void* bitmap0, IN void* bitmap1,
                      IN OUT void* merged_bitmap) {
    UINT64 bitmap0_hva = (UINT64)bitmap0;
    UINT64 bitmap1_hva = (UINT64)bitmap1;
    UINT64 merged_bitmap_hva = (UINT64)merged_bitmap;
    UINT64 merged_bitmap_hva_final = merged_bitmap_hva + PAGE_4KB_SIZE;

    VMM_ASSERT((bitmap0 != NULL) || (bitmap1 != NULL));
    VMM_ASSERT(merged_bitmap);

    while (merged_bitmap_hva < merged_bitmap_hva_final) {
        UINT64 value0 = (bitmap0 == NULL) ? (UINT64)0 : *((UINT64*)bitmap0_hva);
        UINT64 value1 = (bitmap1 == NULL) ? (UINT64)0 : *((UINT64*)bitmap1_hva);
        UINT64 merged_value = value0 | value1;

        *((UINT64*)merged_bitmap_hva) = merged_value;

        bitmap0_hva += sizeof(UINT64);
        bitmap1_hva += sizeof(UINT64);
        merged_bitmap_hva += sizeof(UINT64);
    }
}

#if 0
static BOOLEAN ms_is_msr_in_list(IN IA32_VMX_MSR_ENTRY* list, IN UINT32 msr_index,
                          IN UINT32 count, OUT UINT64* value) {
    UINT32 i;

    for (i = count; i > 0; i--) {
        if (list[i - 1].MsrIndex == msr_index) {
            if (value != NULL) {
                *value = list[i - 1].MsrData;
            }
            return TRUE;
        }
    }
    return FALSE;
}
#endif

static void ms_merge_msr_list(IN GUEST_CPU_HANDLE gcpu, IN VMCS_OBJECT* merged_vmcs,
                       IN IA32_VMX_MSR_ENTRY* first_list, IN IA32_VMX_MSR_ENTRY* second_list,
                       IN UINT32 first_list_count, IN UINT32 second_list_count,
                       IN MSR_LIST_COPY_MODE copy_mode, IN VMCS_ADD_MSR_FUNC add_msr_func,
                       IN VMCS_CLEAR_MSR_LIST_FUNC clear_list_func,
                       IN VMCS_IS_MSR_IN_LIST_FUNC is_msr_in_list_func,
                       IN VMCS_FIELD msr_list_addr_field,
                       IN VMCS_FIELD msr_list_count_field) {
    UINT32 i;

    clear_list_func(merged_vmcs);

    for (i = 0; i < first_list_count; i++) {
        add_msr_func(merged_vmcs, first_list[i].MsrIndex, first_list[i].MsrData);
    }

    for (i = 0; i < second_list_count; i++) {
        if (!is_msr_in_list_func(merged_vmcs, second_list[i].MsrIndex)) {
            add_msr_func(merged_vmcs, second_list[i].MsrIndex, second_list[i].MsrData);
        }
    }

    if (copy_mode != MSR_LIST_COPY_NO_CHANGE) {
        IA32_VMX_MSR_ENTRY* merged_list = ms_retrieve_ptr_to_additional_memory(merged_vmcs, msr_list_addr_field, MS_HPA);
        UINT32 merged_list_count = (UINT32)vmcs_read(merged_vmcs, msr_list_count_field);

        for (i = 0; i < merged_list_count; i++) {
            if ((copy_mode & MSR_LIST_COPY_WITH_EFER_CHANGE) &&
                (merged_list[i].MsrIndex == IA32_MSR_EFER)) {
                IA32_EFER_S* efer = (IA32_EFER_S*)(&(merged_list[i].MsrData));
                efer->Bits.LME = ((copy_mode & MSR_LIST_COPY_AND_SET_64_BIT_MODE_IN_EFER) == MSR_LIST_COPY_AND_SET_64_BIT_MODE_IN_EFER) ? 1 : 0;
                efer->Bits.LMA = efer->Bits.LME;
            }

            if (copy_mode & MSR_LIST_COPY_UPDATE_GCPU) {
                gcpu_set_msr_reg_by_index_layered(gcpu, merged_list[i].MsrIndex, merged_list[i].MsrData, VMCS_MERGED);
            }
        }
    }
}

static
void ms_split_msr_lists(IN GUEST_CPU_HANDLE gcpu, IN IA32_VMX_MSR_ENTRY* merged_list,
                        IN UINT32 merged_list_count) {
    UINT32 i;

    // Copy while there is match
    for (i = 0; i < merged_list_count; i++) {
        gcpu_set_msr_reg_by_index_layered(gcpu, merged_list[i].MsrIndex, merged_list[i].MsrData, VMCS_LEVEL_0);
        gcpu_set_msr_reg_by_index_layered(gcpu, merged_list[i].MsrIndex, merged_list[i].MsrData, VMCS_LEVEL_1);
    }
}

static void ms_perform_cr_split(IN GUEST_CPU_HANDLE gcpu, IN VMM_IA32_CONTROL_REGISTERS reg) {
    UINT64 level1_mask;
    UINT64 merged_mask;
    UINT64 merged_shadow = gcpu_get_guest_visible_control_reg_layered(gcpu, reg, VMCS_MERGED);
    UINT64 level1_reg = gcpu_get_control_reg_layered(gcpu, reg, VMCS_LEVEL_1);
    UINT64 merged_reg = gcpu_get_control_reg_layered(gcpu, reg, VMCS_MERGED);
    UINT64 bits_to_take_from_merged_reg;
    UINT64 bits_to_take_from_merged_shadow;

    if (reg == IA32_CTRL_CR0) {
        level1_mask = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_LEVEL_1);
        merged_mask = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_MERGED);
    }
    else {
        VMM_ASSERT(reg == IA32_CTRL_CR4);
        level1_mask = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_LEVEL_1);
        merged_mask = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_MERGED);
    }

    // There should not be any bit that is set level1_mask and cleared in merged_mask
    VMM_ASSERT(((~merged_mask) & level1_mask) == 0);


    bits_to_take_from_merged_reg = ~merged_mask;
    bits_to_take_from_merged_shadow = (merged_mask ^ level1_mask); // bits that 1 in merged and 0 in level1 masks

    level1_reg = (level1_reg & level1_mask) |
                 (merged_reg & bits_to_take_from_merged_reg) |
                 (merged_shadow & bits_to_take_from_merged_shadow);
    gcpu_set_control_reg_layered(gcpu, reg, level1_reg, VMCS_LEVEL_1);
}

void ms_merge_to_level2(IN GUEST_CPU_HANDLE gcpu, IN BOOLEAN merge_only_dirty) {
    // TODO: merge only dirty
    VMCS_HIERARCHY* hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* level0_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_0);
    VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_1);
    VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_MERGED);
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS controls0;
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS controls1;
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 controls0_2;
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 controls1_2;
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS merged_controls;
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 merged_controls_2;

    VMM_ASSERT(level0_vmcs && level1_vmcs);

    if ((merge_only_dirty) &&
        (!vmcs_is_dirty(level0_vmcs)) &&
        (!vmcs_is_dirty(level1_vmcs))) {
        return;
    }

    // Copy guest state from level-1 vmcs
    ms_copy_guest_state_flom_level1(gcpu, TRUE /* copy CRs */);

    // Merging controls

    controls0.Uint32 = (UINT32)gcpu_get_processor_ctrls_layered(gcpu, VMCS_LEVEL_0);
    controls1.Uint32 = (UINT32)gcpu_get_processor_ctrls_layered(gcpu, VMCS_LEVEL_1);
    controls0_2.Uint32 = (UINT32)gcpu_get_processor_ctrls2_layered(gcpu, VMCS_LEVEL_0);
    controls1_2.Uint32 = (UINT32)gcpu_get_processor_ctrls2_layered(gcpu, VMCS_LEVEL_1);
    merged_controls.Uint32 = (UINT32)gcpu_get_processor_ctrls_layered(gcpu, VMCS_MERGED);
    merged_controls_2.Uint32 = (UINT32)gcpu_get_processor_ctrls2_layered(gcpu, VMCS_MERGED);

    // Pin-based controls
    {
        UINT32 value0 = (UINT32)gcpu_get_pin_ctrls_layered(gcpu, VMCS_LEVEL_0);
        UINT32 value1 = (UINT32)gcpu_get_pin_ctrls_layered(gcpu, VMCS_LEVEL_1);
        UINT32 merged_value = value0 | value1;

        gcpu_set_pin_ctrls_layered(gcpu, VMCS_MERGED, merged_value);
    }

    // Exceptions bitmap
    {
        UINT32 value0 = (UINT32)gcpu_get_exceptions_map_layered(gcpu, VMCS_LEVEL_0);
        UINT32 value1 = (UINT32)gcpu_get_exceptions_map_layered(gcpu, VMCS_LEVEL_1);
        UINT32 merged_value = value0 | value1;

        gcpu_set_exceptions_map_layered(gcpu, VMCS_MERGED, merged_value);
    }

    // Primary and secondary processor-based controls
    {
        BOOLEAN is_ia32e_mode = FALSE;
        VM_ENTRY_CONTROLS entry_ctrls;

        // bit 2
        merged_controls.Bits.SoftwareInterrupt = controls0.Bits.SoftwareInterrupt | controls1.Bits.SoftwareInterrupt;

        // bit 3
        merged_controls.Bits.UseTscOffsetting = controls0.Bits.UseTscOffsetting | controls1.Bits.UseTscOffsetting;

        // bit 7
        merged_controls.Bits.Hlt = controls0.Bits.Hlt | controls1.Bits.Hlt;

        // bit 9
        merged_controls.Bits.Invlpg = controls0.Bits.Invlpg | controls1.Bits.Invlpg;

        // bit 10
        merged_controls.Bits.Mwait = controls0.Bits.Mwait | controls1.Bits.Mwait;

        // bit 11
        merged_controls.Bits.Rdpmc = controls0.Bits.Rdpmc | controls1.Bits.Rdpmc;

        // bit 12
        merged_controls.Bits.Rdtsc = controls0.Bits.Rdtsc | controls1.Bits.Rdtsc;

        // bit 19
        entry_ctrls.Uint32 = (UINT32)gcpu_get_enter_ctrls_layered(gcpu, VMCS_LEVEL_1);
        is_ia32e_mode = entry_ctrls.Bits.Ia32eModeGuest;
        if (is_ia32e_mode) {
            merged_controls.Bits.Cr8Load = controls0.Bits.Cr8Load | controls1.Bits.Cr8Load;
        }

        // bit 20
        if (is_ia32e_mode) {
            merged_controls.Bits.Cr8Store = controls0.Bits.Cr8Store | controls1.Bits.Cr8Store;
        }

        // bit 21
        // TPR shadow is currently not supported
        // TODO: Support for TPR shadow in layering
        VMM_ASSERT(controls0.Bits.TprShadow == 0);
        VMM_ASSERT(controls1.Bits.TprShadow == 0);


        // bit 22
        merged_controls.Bits.NmiWindow = controls0.Bits.NmiWindow | controls1.Bits.NmiWindow;

        // bit 23
        merged_controls.Bits.MovDr = controls0.Bits.MovDr | controls1.Bits.MovDr;

        // bits 24 and 25
        if (((controls0.Bits.UnconditionalIo == 1) && (controls0.Bits.ActivateIoBitmaps == 0)) ||
            ((controls1.Bits.UnconditionalIo == 1) && (controls1.Bits.ActivateIoBitmaps == 0))) {

            merged_controls.Bits.UnconditionalIo = 1;
            merged_controls.Bits.ActivateIoBitmaps = 0;
        }
        else {
            merged_controls.Bits.UnconditionalIo = 0;
            merged_controls.Bits.ActivateIoBitmaps = controls0.Bits.ActivateIoBitmaps | controls1.Bits.ActivateIoBitmaps;
        }

        // bit 28
        merged_controls.Bits.UseMsrBitmaps = controls0.Bits.UseMsrBitmaps & controls1.Bits.UseMsrBitmaps;

        // bit 29
        merged_controls.Bits.Monitor = controls0.Bits.Monitor | controls1.Bits.Monitor;

        // bit 30
        merged_controls.Bits.Pause = controls0.Bits.Pause | controls1.Bits.Pause;

        // bit 31
        merged_controls.Bits.SecondaryControls = controls0.Bits.SecondaryControls | controls1.Bits.SecondaryControls;

        gcpu_set_processor_ctrls_layered(gcpu, VMCS_MERGED, merged_controls.Uint32);


        // Secondary controls
        if (controls0.Bits.SecondaryControls == 0) {
            controls0_2.Uint32 = 0;

        }

        if (controls1.Bits.SecondaryControls == 0) {
            controls1_2.Uint32 = 0;
        }

        merged_controls_2.Uint32 = controls0_2.Uint32 | controls1_2.Uint32;

        gcpu_set_processor_ctrls2_layered(gcpu, VMCS_MERGED, merged_controls_2.Uint32);
    }

    // Executive VMCS pointer
    {
        UINT64 value = vmcs_read(level1_vmcs, VMCS_OSV_CONTROLLING_VMCS_ADDRESS);
        vmcs_write(merged_vmcs, VMCS_OSV_CONTROLLING_VMCS_ADDRESS, value);
    }

    // Entry controls
    {
        UINT32 value = (UINT32)gcpu_get_enter_ctrls_layered(gcpu, VMCS_LEVEL_1);
        gcpu_set_enter_ctrls_layered(gcpu, VMCS_MERGED, value);

#ifdef DEBUG
        {
            VM_ENTRY_CONTROLS ctrls;
            ctrls.Uint32 = value;
            VMM_ASSERT(ctrls.Bits.Load_IA32_PERF_GLOBAL_CTRL == 0);
        }
#endif
    }

    // Interruption-information field
    {
        UINT32 value = (UINT32)vmcs_read(level1_vmcs, VMCS_ENTER_INTERRUPT_INFO);
        vmcs_write(merged_vmcs, VMCS_ENTER_INTERRUPT_INFO, value);
    }

    // Exception error code
    {
        UINT32 value = (UINT32)vmcs_read(level1_vmcs, VMCS_ENTER_EXCEPTION_ERROR_CODE);
        vmcs_write(merged_vmcs, VMCS_ENTER_EXCEPTION_ERROR_CODE, value);
    }

    // Instruction length
    {
        UINT32 value = (UINT32)vmcs_read(level1_vmcs, VMCS_ENTER_INSTRUCTION_LENGTH);
        vmcs_write(merged_vmcs, VMCS_ENTER_INSTRUCTION_LENGTH, value);
    }

    // TSC offset
    {
        if (merged_controls.Bits.UseTscOffsetting) {
            UINT64 final_value = 0;


            if ((controls0.Bits.UseTscOffsetting == 1) &&
                (controls1.Bits.UseTscOffsetting == 0)) {

                final_value = vmcs_read(level0_vmcs, VMCS_TSC_OFFSET);

            }
            else if ((controls0.Bits.UseTscOffsetting == 0) &&
                     (controls1.Bits.UseTscOffsetting == 1)) {

                final_value = vmcs_read(level1_vmcs, VMCS_TSC_OFFSET);

            }
            else {
                UINT64 value0 = vmcs_read(level0_vmcs, VMCS_TSC_OFFSET);
                UINT64 value1 = vmcs_read(level1_vmcs, VMCS_TSC_OFFSET);

                VMM_ASSERT(controls0.Bits.UseTscOffsetting == 1);
                VMM_ASSERT(controls1.Bits.UseTscOffsetting == 1);

                final_value = value0 + value1;
            }

            vmcs_write(merged_vmcs, VMCS_TSC_OFFSET, final_value);
        }
    }

    // APIC-access address
    {
        if ((merged_controls.Bits.SecondaryControls == 1) &&
            (merged_controls_2.Bits.VirtualizeAPIC == 1)) {

            // TODO: Implement APIC-access merge
            VMM_DEADLOOP();
        }
    }

    // TPR shadow address
    {
        if (merged_controls.Bits.TprShadow == 1) {
            // TODO: Implement TPR-shadow merge
            VMM_DEADLOOP();
        }
    }

    // "Page-fault error-code mask" and "Page-fault error-code match"
    {
        IA32_VMCS_EXCEPTION_BITMAP exception_ctrls;

        exception_ctrls.Uint32 = (UINT32)gcpu_get_exceptions_map_layered(gcpu, VMCS_MERGED);

        if (may_cause_vmexit_on_page_fault(gcpu, VMCS_LEVEL_0) ||
            may_cause_vmexit_on_page_fault(gcpu, VMCS_LEVEL_1)) {

            if (exception_ctrls.Bits.PF == 1) {
                gcpu_set_pf_error_code_mask_and_match_layered(gcpu, VMCS_MERGED, 0x00000000, 0x00000000);
            }
            else {
                gcpu_set_pf_error_code_mask_and_match_layered(gcpu, VMCS_MERGED, 0x00000000, 0xffffffff);
            }
        }
        else {
            if (exception_ctrls.Bits.PF == 1) {
                gcpu_set_pf_error_code_mask_and_match_layered(gcpu, VMCS_MERGED, 0x00000000, 0xffffffff);
            }
            else {
                gcpu_set_pf_error_code_mask_and_match_layered(gcpu, VMCS_MERGED, 0x00000000, 0x00000000);
            }
        }
    }

    // CR3 target count
    {
        // Target list is not supported
        vmcs_write(merged_vmcs, VMCS_CR3_TARGET_COUNT, 0);
    }

    // VM-exit controls
    {
        VM_EXIT_CONTROLS merged_exit_controls;

        merged_exit_controls.Uint32 = (UINT32)gcpu_get_exit_ctrls_layered(gcpu, VMCS_LEVEL_0);
        merged_exit_controls.Bits.AcknowledgeInterruptOnExit = 0; // The only difference

        gcpu_set_exit_ctrls_layered(gcpu, VMCS_MERGED, merged_exit_controls.Uint32);

        // VTUNE is not supported
        VMM_ASSERT(merged_exit_controls.Bits.Load_IA32_PERF_GLOBAL_CTRL == 0);
    }

    // Attention !!! ms_merge_timer_to_level2 must be called
    // after all other control fields were already merged
    if (vmcs_field_is_supported(VMCS_PREEMPTION_TIMER))
    {
        ms_merge_timer_to_level2(level0_vmcs, level1_vmcs, merged_vmcs);
    }

    // TPR threshold
    {
        if (merged_controls.Bits.TprShadow == 1) {
            // TODO: Implement TPR-threshold merge
            VMM_DEADLOOP();
        }
    }

    // CR0 guest/host mask
    {
        UINT64 mask0 = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_LEVEL_0);
        UINT64 mask1 = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_LEVEL_1);
        UINT64 merged_mask = mask0 | mask1;

        gcpu_set_cr0_reg_mask_layered(gcpu, VMCS_MERGED, merged_mask);
    }

    // CR4 guest/host mask
    {
        UINT64 mask0 = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_LEVEL_0);
        UINT64 mask1 = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_LEVEL_1);
        UINT64 merged_mask = mask0 | mask1;

        gcpu_set_cr4_reg_mask_layered(gcpu, VMCS_MERGED, merged_mask);
    }

    // CR0 shadow
    {
        UINT64 shadow = ms_merge_cr_shadow(gcpu, IA32_CTRL_CR0);
        gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR0, shadow, VMCS_MERGED);
    }

    // CR3 pseudo shadow
    {
        UINT64 value = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR3, VMCS_LEVEL_1);
        gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR3, value, VMCS_MERGED);
    }

    // CR4 shadow
    {
        UINT64 shadow = ms_merge_cr_shadow(gcpu, IA32_CTRL_CR4);
        gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR4, shadow, VMCS_MERGED);
    }

    // I/O bitmaps A and B
    {
        if (merged_controls.Bits.ActivateIoBitmaps == 1) {
            void* level0_bitmap_A;
            void* level0_bitmap_B;
            void* level1_bitmap_A;
            void* level1_bitmap_B;
            void* merged_bitmap_A;
            void* merged_bitmap_B;

            if (controls0.Bits.ActivateIoBitmaps == 1) {
                level0_bitmap_A = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_IO_BITMAP_ADDRESS_A, MS_HVA);
                level0_bitmap_B = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_IO_BITMAP_ADDRESS_B, MS_HVA);
            }
            else {
                level0_bitmap_A = NULL;
                level0_bitmap_B = NULL;
            }

            if (controls1.Bits.ActivateIoBitmaps == 1) {
                level1_bitmap_A = ms_retrieve_ptr_to_additional_memory(level1_vmcs, VMCS_IO_BITMAP_ADDRESS_A, MS_HVA);
                level1_bitmap_B = ms_retrieve_ptr_to_additional_memory(level1_vmcs, VMCS_IO_BITMAP_ADDRESS_B, MS_HVA);
            }
            else {
                level1_bitmap_A = NULL;
                level1_bitmap_B = NULL;
            }

            merged_bitmap_A = ms_retrieve_ptr_to_additional_memory(merged_vmcs, VMCS_IO_BITMAP_ADDRESS_A, MS_HPA);
            merged_bitmap_B = ms_retrieve_ptr_to_additional_memory(merged_vmcs, VMCS_IO_BITMAP_ADDRESS_B, MS_HPA);

            ms_merge_bitmaps(level0_bitmap_A, level1_bitmap_A, merged_bitmap_A);
            ms_merge_bitmaps(level0_bitmap_B, level1_bitmap_B, merged_bitmap_B);
        }
    }

    // MSR bitmap
    {
        if (merged_controls.Bits.UseMsrBitmaps == 1) {
            void* level0_bitmap;
            void* level1_bitmap;
            void* merged_bitmap;

            level0_bitmap = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_MSR_BITMAP_ADDRESS, MS_HVA);
            level1_bitmap = ms_retrieve_ptr_to_additional_memory(level1_vmcs, VMCS_MSR_BITMAP_ADDRESS, MS_HVA);
            merged_bitmap = ms_retrieve_ptr_to_additional_memory(merged_vmcs, VMCS_MSR_BITMAP_ADDRESS, MS_HPA);

            ms_merge_bitmaps(level0_bitmap, level1_bitmap, merged_bitmap);
        }
    }

    // VMExit MSR-store address and count
    {
        IA32_VMX_MSR_ENTRY* level0_list = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_EXIT_MSR_STORE_ADDRESS, MS_HVA);
        UINT32 level0_list_count = (UINT32)vmcs_read(level0_vmcs, VMCS_EXIT_MSR_STORE_COUNT);
        IA32_VMX_MSR_ENTRY* level1_list = ms_retrieve_ptr_to_additional_memory(level1_vmcs, VMCS_EXIT_MSR_STORE_ADDRESS, MS_HVA);
        UINT32 level1_list_count = (UINT32)vmcs_read(level1_vmcs, VMCS_EXIT_MSR_STORE_COUNT);


        if ((level0_list_count + level1_list_count) > 256) {
            // TODO: proper handling of VMExit MSR-store list when it must be > 512 entries
            VMM_DEADLOOP();
        }

        ms_merge_msr_list(gcpu, merged_vmcs, level1_list, level0_list, level1_list_count,
                          level0_list_count, MSR_LIST_COPY_NO_CHANGE,
                          vmcs_add_msr_to_vmexit_store_list, vmcs_clear_vmexit_store_list,
                          vmcs_is_msr_in_vmexit_store_list, VMCS_EXIT_MSR_STORE_ADDRESS,
                          VMCS_EXIT_MSR_STORE_COUNT);
    }

    // VMExit MSR-load address and count
    {
        IA32_VMX_MSR_ENTRY* level0_list = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_EXIT_MSR_LOAD_ADDRESS, MS_HVA);
        UINT32 level0_list_count = (UINT32)vmcs_read(level0_vmcs, VMCS_EXIT_MSR_LOAD_COUNT);

        if (level0_list_count > 256) {
            // TODO: proper handling of VMExit MSR-load list when it must be > 512 entries
            VMM_DEADLOOP();
        }

        ms_merge_msr_list(gcpu, merged_vmcs, level0_list, NULL, level0_list_count, 0,
                          MSR_LIST_COPY_NO_CHANGE, vmcs_add_msr_to_vmexit_load_list,
                          vmcs_clear_vmexit_load_list, vmcs_is_msr_in_vmexit_load_list,
                          VMCS_EXIT_MSR_LOAD_ADDRESS, VMCS_EXIT_MSR_LOAD_COUNT);
    }

    // VMEnter MSR-load address and count
    {
        IA32_VMX_MSR_ENTRY* level0_list = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_ENTER_MSR_LOAD_ADDRESS, MS_HVA);
        UINT32 level0_list_count = (UINT32)vmcs_read(level0_vmcs, VMCS_ENTER_MSR_LOAD_COUNT);
        IA32_VMX_MSR_ENTRY* level1_list = ms_retrieve_ptr_to_additional_memory(level1_vmcs, VMCS_ENTER_MSR_LOAD_ADDRESS, MS_HVA);
        UINT32 level1_list_count = (UINT32)vmcs_read(level1_vmcs, VMCS_ENTER_MSR_LOAD_COUNT);
        VM_ENTRY_CONTROLS entry_ctrls;
        MSR_LIST_COPY_MODE copy_mode;

        if ((level0_list_count + level1_list_count) > 512) {
            // TODO: proper handling of VMEnter MSR-load list when it must be > 512 entries
            VMM_DEADLOOP();
        }

        entry_ctrls.Uint32 = (UINT32)gcpu_get_enter_ctrls_layered(gcpu, VMCS_MERGED);
        if (entry_ctrls.Bits.Ia32eModeGuest) {
            copy_mode = MSR_LIST_COPY_AND_SET_64_BIT_MODE_IN_EFER | MSR_LIST_COPY_UPDATE_GCPU;
        }
        else {
            copy_mode = MSR_LIST_COPY_AND_SET_32_BIT_MODE_IN_EFER | MSR_LIST_COPY_UPDATE_GCPU;
        }

        ms_merge_msr_list(gcpu,
                          merged_vmcs,
                          level1_list,
                          level0_list,
                          level1_list_count,
                          level0_list_count,
                          copy_mode,
                          vmcs_add_msr_to_vmenter_load_list,
                          vmcs_clear_vmenter_load_list,
                          vmcs_is_msr_in_vmenter_load_list,
                          VMCS_ENTER_MSR_LOAD_ADDRESS,
                          VMCS_ENTER_MSR_LOAD_COUNT);
    }

    // Copy host state from level-0 vmcs
    ms_copy_host_state(merged_vmcs, level0_vmcs);
}

void ms_split_from_level2(IN GUEST_CPU_HANDLE gcpu) {
    VMCS_HIERARCHY* hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_1);
    VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_MERGED);

    // ---UPDATE MSR LISTS IN LEVEL0 and LEVEL1 VMCSs---
    {
        IA32_VMX_MSR_ENTRY* merged_list = ms_retrieve_ptr_to_additional_memory(merged_vmcs, VMCS_EXIT_MSR_STORE_ADDRESS, MS_HPA);
        UINT32 merged_list_count = (UINT32)vmcs_read(merged_vmcs, VMCS_EXIT_MSR_STORE_COUNT);

        ms_split_msr_lists(gcpu, merged_list, merged_list_count);
    }

    // Copy guest state from level-1 vmcs
    ms_copy_guest_state_to_level1_vmcs(gcpu, FALSE /* do not copy CRs */);

    // CR3 - actual CR3 is stored as "visible" CR3
    {
        UINT64 value = gcpu_get_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR3, VMCS_MERGED);
        gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR3, value, VMCS_LEVEL_1);
    }

    // CR0/CR4 update
    ms_perform_cr_split(gcpu, IA32_CTRL_CR0);
    ms_perform_cr_split(gcpu, IA32_CTRL_CR4);

    ms_copy_data_fields(level1_vmcs, merged_vmcs);

    if (vmcs_field_is_supported(VMCS_PREEMPTION_TIMER)) {
        ms_split_timer_from_level2(
            vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_1),
            level1_vmcs, merged_vmcs);
    }
}

void ms_merge_to_level1(IN GUEST_CPU_HANDLE gcpu,
                        IN BOOLEAN was_vmexit_from_level1,
                        IN BOOLEAN merge_only_dirty UNUSED) {
    // TODO: merge only dirty
    VMCS_HIERARCHY* hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* level0_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_0);
    VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_1);
    VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_MERGED);

    if (!was_vmexit_from_level1) {
        // (level-2) --> (level-1) vmexit, copy host area of level-1 vmcs to guest area of merged vmcs
        VM_EXIT_CONTROLS exit_ctrls;

        // merged exit controls will be identical to "level-0" exit controls
        exit_ctrls.Uint32 = (UINT32)gcpu_get_exit_ctrls_layered(gcpu, VMCS_LEVEL_0);

        // ES segment
        {
            IA32_SELECTOR selector;
            IA32_VMX_VMCS_GUEST_AR ar;

            selector.sel16 = (UINT16)vmcs_read(level1_vmcs, VMCS_HOST_ES_SELECTOR);

            ar.Uint32 = 0;
            ar.Bits.SegmentType = 1;
            ar.Bits.DescriptorPrivilegeLevel = 0;
            ar.Bits.SegmentPresent = 1;
            ar.Bits.DefaultOperationSize = exit_ctrls.Bits.Ia32eModeHost ? 0 : 1;
            ar.Bits.Granularity = 1;
            ar.Bits.Null = (selector.bits.index == 0) ? 1 : 0; // unused in case when selector is 0

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_ES, selector.sel16, 0, 0xffffffff, ar.Uint32, VMCS_MERGED);
        }

        // CS segment
        {
            IA32_SELECTOR selector;
            IA32_VMX_VMCS_GUEST_AR ar;

            selector.sel16= (UINT16)vmcs_read(level1_vmcs, VMCS_HOST_CS_SELECTOR);

            ar.Uint32 = 0;
            ar.Bits.SegmentType = 11;
            ar.Bits.DescriptorType = 1;
            ar.Bits.DescriptorPrivilegeLevel = 0;
            ar.Bits.SegmentPresent = 1;
            ar.Bits.Reserved_1 = exit_ctrls.Bits.Ia32eModeHost ? 1 : 0;
            ar.Bits.DefaultOperationSize = exit_ctrls.Bits.Ia32eModeHost ? 0 : 1;
            ar.Bits.Granularity = 1;
            ar.Bits.Null = 0; // usable

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_CS, selector.sel16, 0, 0xffffffff, ar.Uint32, VMCS_MERGED);
        }

        // SS segment
        {
            IA32_SELECTOR selector;
            IA32_VMX_VMCS_GUEST_AR ar;

            selector.sel16 = (UINT16)vmcs_read(level1_vmcs, VMCS_HOST_SS_SELECTOR);

            ar.Uint32 = 0;
            ar.Bits.SegmentType = 1;
            ar.Bits.DescriptorPrivilegeLevel = 0;
            ar.Bits.SegmentPresent = 1;
            ar.Bits.DefaultOperationSize = exit_ctrls.Bits.Ia32eModeHost ? 0 : 1;
            ar.Bits.Null = (selector.bits.index == 0) ? 1 : 0; // unusable in case the index is 0

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_SS, selector.sel16, 0, 0xffffffff, ar.Uint32, VMCS_MERGED);
        }

        // DS segment
        {
            IA32_SELECTOR selector;
            IA32_VMX_VMCS_GUEST_AR ar;

            selector.sel16 = (UINT16)vmcs_read(level1_vmcs, VMCS_HOST_DS_SELECTOR);

            ar.Uint32 = 0;
            ar.Bits.SegmentType = 1;
            ar.Bits.DescriptorPrivilegeLevel = 0;
            ar.Bits.SegmentPresent = 1;
            ar.Bits.DefaultOperationSize = exit_ctrls.Bits.Ia32eModeHost ? 0 : 1;
            ar.Bits.Granularity = 1;
            ar.Bits.Null = (selector.bits.index == 0) ? 1 : 0; // unusable in case the index is 0

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_DS, selector.sel16, 0, 0xffffffff, ar.Uint32, VMCS_MERGED);
        }

        // FS segment
        {
            IA32_SELECTOR selector;
            UINT64 base = vmcs_read(level1_vmcs, VMCS_HOST_FS_BASE);
            IA32_VMX_VMCS_GUEST_AR ar;

            selector.sel16 = (UINT16)vmcs_read(level1_vmcs, VMCS_HOST_FS_SELECTOR);

            ar.Uint32 = 0;
            ar.Bits.SegmentType = 1;
            ar.Bits.DescriptorPrivilegeLevel = 0;
            ar.Bits.SegmentPresent = 1;
            ar.Bits.DefaultOperationSize = exit_ctrls.Bits.Ia32eModeHost ? 0 : 1;
            ar.Bits.Granularity = 1;
            ar.Bits.Null = (selector.bits.index == 0) ? 1 : 0; // unusable in case the index is 0

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_FS, selector.sel16, base, 0xffffffff, ar.Uint32, VMCS_MERGED);
        }

        // GS segment
        {
            IA32_SELECTOR selector;
            UINT64 base = vmcs_read(level1_vmcs, VMCS_HOST_GS_BASE);
            IA32_VMX_VMCS_GUEST_AR ar;

            selector.sel16 = (UINT16)vmcs_read(level1_vmcs, VMCS_HOST_GS_SELECTOR);

            ar.Uint32 = 0;
            ar.Bits.SegmentType = 1;
            ar.Bits.DescriptorPrivilegeLevel = 0;
            ar.Bits.SegmentPresent = 1;
            ar.Bits.DefaultOperationSize = exit_ctrls.Bits.Ia32eModeHost ? 0 : 1;
            ar.Bits.Granularity = 1;
            ar.Bits.Null = (selector.bits.index == 0) ? 1 : 0; // unusable in case the index is 0

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_GS, selector.sel16, base, 0xffffffff, ar.Uint32, VMCS_MERGED);
        }

        // TR segment
        {
            IA32_SELECTOR selector;
            UINT64 base = vmcs_read(level1_vmcs, VMCS_HOST_TR_BASE);
            IA32_VMX_VMCS_GUEST_AR ar;

            selector.sel16 = (UINT16)vmcs_read(level1_vmcs, VMCS_HOST_TR_SELECTOR);

            ar.Uint32 = 0;
            ar.Bits.SegmentType = 11;
            ar.Bits.DescriptorType = 0;
            ar.Bits.DescriptorPrivilegeLevel = 0;
            ar.Bits.SegmentPresent = 1;
            ar.Bits.DefaultOperationSize = 0;
            ar.Bits.Granularity = 0;
            ar.Bits.Null = 0; // usable

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_TR, selector.sel16, base, 0x67, ar.Uint32, VMCS_MERGED);
        }

        // LDTR
        {
            IA32_VMX_VMCS_GUEST_AR ar;
            ar.Uint32 = 0;
            ar.Bits.Null = 1; // unusable

            gcpu_set_segment_reg_layered(gcpu, IA32_SEG_LDTR, 0, 0, 0, ar.Uint32, VMCS_MERGED);
        }


        // GDTR IDTR
        {
            UINT64 base;

            base = vmcs_read(level1_vmcs, VMCS_HOST_GDTR_BASE);
            gcpu_set_gdt_reg_layered(gcpu, base, 0xffff, VMCS_MERGED);

            base = vmcs_read(level1_vmcs, VMCS_HOST_IDTR_BASE);
            gcpu_set_idt_reg_layered(gcpu, base, 0xffff, VMCS_MERGED);
        }

        // RFLAGS
        {
            gcpu_set_native_gp_reg_layered(gcpu, IA32_REG_RFLAGS, 0x2, VMCS_MERGED);
        }

        // RSP, RIP
        {
            UINT64 value;

            value = vmcs_read(level1_vmcs, VMCS_HOST_RIP);
            gcpu_set_native_gp_reg_layered(gcpu, IA32_REG_RIP, value, VMCS_MERGED);

            value = vmcs_read(level1_vmcs, VMCS_HOST_RSP);
            gcpu_set_native_gp_reg_layered(gcpu, IA32_REG_RSP, value, VMCS_MERGED);
        }

        // SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
        {
            UINT64 value;

            value = vmcs_read(level1_vmcs, VMCS_HOST_SYSENTER_CS);
            gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_CS, value, VMCS_MERGED);

            value = vmcs_read(level1_vmcs, VMCS_HOST_SYSENTER_ESP);
            gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_ESP, value, VMCS_MERGED);

            value = vmcs_read(level1_vmcs, VMCS_HOST_SYSENTER_EIP);
            gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SYSENTER_EIP, value, VMCS_MERGED);
        }

        // DR7
        {
            gcpu_set_debug_reg_layered(gcpu, IA32_REG_DR7, 0x400, VMCS_MERGED);
        }

        // IA32_PERF_GLOBAL_CTRL
        if (vmcs_field_is_supported(VMCS_HOST_IA32_PERF_GLOBAL_CTRL) &&
            vmcs_field_is_supported(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL))
        {
            UINT64 value;

            value = vmcs_read(level1_vmcs, VMCS_HOST_IA32_PERF_GLOBAL_CTRL);
            vmcs_write(merged_vmcs, VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, value);
        }

        // SMBASE
        {
            gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_SMBASE, 0, VMCS_MERGED);
        }

        // VMCS link pointer
        {
            vmcs_write(merged_vmcs, VMCS_OSV_CONTROLLING_VMCS_ADDRESS, ~((UINT64)0));
        }

        // CR0, CR3, CR4
        {
            UINT64 value;

            value = vmcs_read(level1_vmcs, VMCS_HOST_CR0);
            gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR0, value, VMCS_MERGED);
            gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR0, value, VMCS_MERGED);

            value = vmcs_read(level1_vmcs, VMCS_HOST_CR3);
            gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR3, value, VMCS_MERGED);
            gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR3, value, VMCS_MERGED);

            value = vmcs_read(level1_vmcs, VMCS_HOST_CR4);
            gcpu_set_control_reg_layered(gcpu, IA32_CTRL_CR4, value, VMCS_MERGED);
            gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR4, value, VMCS_MERGED);
        }

        // Interruptibility state
        {
            IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY interruptibility;
            IA32_VMX_EXIT_REASON reason;


            interruptibility.Uint32 = 0;
            reason.Uint32 = (UINT32)vmcs_read(level1_vmcs, VMCS_EXIT_INFO_REASON);
            if (reason.Bits.BasicReason == Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi) {
                IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING vectoring_info;

                vectoring_info.Uint32 = (UINT32)vmcs_read(level1_vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO);
                if (vectoring_info.Bits.InterruptType == 2) {
                    // NMI
                    interruptibility.Bits.BlockNmi = 1;
                }
            }
            gcpu_set_interruptibility_state_layered(gcpu, interruptibility.Uint32, VMCS_MERGED);
        }

        // Activity state
        {
            gcpu_set_activity_state_layered(gcpu, Ia32VmxVmcsGuestSleepStateActive, VMCS_MERGED);
        }

        // IA32_DEBUGCTL
        {
            gcpu_set_msr_reg_layered(gcpu, IA32_VMM_MSR_DEBUGCTL, 0, VMCS_MERGED);
        }

        // Pending debug exceptions
        {
            gcpu_set_pending_debug_exceptions_layered(gcpu, 0, VMCS_MERGED);
        }

        // Preemption Timer
        vmcs_write(merged_vmcs,
                   VMCS_PREEMPTION_TIMER,
                   vmcs_read(level0_vmcs, VMCS_PREEMPTION_TIMER));

    }

    // Most is copied from level-0
    {
        UINT64 value;
        UINT32 pf_mask;
        UINT32 pf_match;

        value = gcpu_get_pin_ctrls_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_pin_ctrls_layered(gcpu, VMCS_MERGED, value);

        value = gcpu_get_exceptions_map_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_exceptions_map_layered(gcpu, VMCS_MERGED, value);

        value = gcpu_get_processor_ctrls_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_processor_ctrls_layered(gcpu, VMCS_MERGED, value);

        value = gcpu_get_processor_ctrls2_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_processor_ctrls2_layered(gcpu, VMCS_MERGED, value);


        value = gcpu_get_enter_ctrls_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_enter_ctrls_layered(gcpu, VMCS_MERGED, (UINT32)value);
#ifdef DEBUG
        {
            VM_ENTRY_CONTROLS controls;
            controls.Uint32 = (UINT32)value;

            // VTUNE is not supported
            VMM_ASSERT(controls.Bits.Load_IA32_PERF_GLOBAL_CTRL == 0);
        }
#endif

        value = gcpu_get_exit_ctrls_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_exit_ctrls_layered(gcpu, VMCS_MERGED, (UINT32)value);
#ifdef DEBUG
        {
            VM_EXIT_CONTROLS controls;
            controls.Uint32 = (UINT32)value;

            // VTUNE is not supported
            VMM_ASSERT(controls.Bits.Load_IA32_PERF_GLOBAL_CTRL == 0);
        }
#endif

        value = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_cr0_reg_mask_layered(gcpu, VMCS_MERGED, value);

        value = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_LEVEL_0);
        gcpu_set_cr4_reg_mask_layered(gcpu, VMCS_MERGED, value);

        value = vmcs_read(level0_vmcs, VMCS_OSV_CONTROLLING_VMCS_ADDRESS);
        vmcs_write(merged_vmcs, VMCS_OSV_CONTROLLING_VMCS_ADDRESS, value);

        value = vmcs_read(level0_vmcs, VMCS_ENTER_INTERRUPT_INFO);
        vmcs_write(merged_vmcs, VMCS_ENTER_INTERRUPT_INFO, value);

        value = vmcs_read(level0_vmcs, VMCS_ENTER_EXCEPTION_ERROR_CODE);
        vmcs_write(merged_vmcs, VMCS_ENTER_EXCEPTION_ERROR_CODE, value);

        value = vmcs_read(level0_vmcs, VMCS_ENTER_INSTRUCTION_LENGTH);
        vmcs_write(merged_vmcs, VMCS_ENTER_INSTRUCTION_LENGTH, value);

        value = vmcs_read(level0_vmcs, VMCS_TSC_OFFSET);
        vmcs_write(merged_vmcs, VMCS_TSC_OFFSET, value);

        value = vmcs_read(level0_vmcs, VMCS_APIC_ACCESS_ADDRESS);
        vmcs_write(merged_vmcs, VMCS_APIC_ACCESS_ADDRESS, value);

        value = vmcs_read(level0_vmcs, VMCS_VIRTUAL_APIC_ADDRESS);
        vmcs_write(merged_vmcs, VMCS_VIRTUAL_APIC_ADDRESS, value);

        gcpu_get_pf_error_code_mask_and_match_layered(gcpu, VMCS_LEVEL_0, &pf_mask, &pf_match);
        gcpu_set_pf_error_code_mask_and_match_layered(gcpu, VMCS_MERGED, pf_mask, pf_match);

        value = vmcs_read(level0_vmcs, VMCS_CR3_TARGET_COUNT);
        vmcs_write(merged_vmcs, VMCS_CR3_TARGET_COUNT, value);

        value = vmcs_read(level0_vmcs, VMCS_CR3_TARGET_VALUE_0);
        vmcs_write(merged_vmcs, VMCS_CR3_TARGET_VALUE_0, value);

        value = vmcs_read(level0_vmcs, VMCS_CR3_TARGET_VALUE_1);
        vmcs_write(merged_vmcs, VMCS_CR3_TARGET_VALUE_1, value);

        value = vmcs_read(level0_vmcs, VMCS_CR3_TARGET_VALUE_2);
        vmcs_write(merged_vmcs, VMCS_CR3_TARGET_VALUE_2, value);

        value = vmcs_read(level0_vmcs, VMCS_CR3_TARGET_VALUE_3);
        vmcs_write(merged_vmcs, VMCS_CR3_TARGET_VALUE_3, value);

        value = vmcs_read(level0_vmcs, VMCS_EXIT_TPR_THRESHOLD);
        vmcs_write(merged_vmcs, VMCS_EXIT_TPR_THRESHOLD, value);

        value = gcpu_get_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR0, VMCS_LEVEL_0);
        gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR0, value, VMCS_MERGED);

        value = gcpu_get_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR4, VMCS_LEVEL_0);
        gcpu_set_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR4, value, VMCS_MERGED);

    }

    // I/O bitmaps A and B
    {
        PROCESSOR_BASED_VM_EXECUTION_CONTROLS merged_controls;

        merged_controls.Uint32 = (UINT32)gcpu_get_processor_ctrls_layered(gcpu, VMCS_LEVEL_0);
        if (merged_controls.Bits.ActivateIoBitmaps == 1) {
            void* level0_bitmap_A;
            void* level0_bitmap_B;
            void* merged_bitmap_A;
            void* merged_bitmap_B;

            level0_bitmap_A = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_IO_BITMAP_ADDRESS_A, MS_HVA);
            level0_bitmap_B = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_IO_BITMAP_ADDRESS_B, MS_HVA);

            VMM_ASSERT(level0_bitmap_A != NULL);
            VMM_ASSERT(level0_bitmap_B != NULL);

            merged_bitmap_A = ms_retrieve_ptr_to_additional_memory(merged_vmcs, VMCS_IO_BITMAP_ADDRESS_A, MS_HPA);
            merged_bitmap_B = ms_retrieve_ptr_to_additional_memory(merged_vmcs, VMCS_IO_BITMAP_ADDRESS_B, MS_HPA);

            VMM_ASSERT(merged_bitmap_A != NULL);
            VMM_ASSERT(merged_bitmap_B != NULL);

            ms_merge_bitmaps(level0_bitmap_A, NULL, merged_bitmap_A);
            ms_merge_bitmaps(level0_bitmap_B, NULL, merged_bitmap_B);

        }
    }

    // MSR bitmap
    {
        PROCESSOR_BASED_VM_EXECUTION_CONTROLS merged_controls;

        merged_controls.Uint32 = (UINT32)gcpu_get_processor_ctrls_layered(gcpu, VMCS_LEVEL_0);

        if (merged_controls.Bits.UseMsrBitmaps == 1) {
            void* level0_bitmap;
            void* merged_bitmap;

            level0_bitmap = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_MSR_BITMAP_ADDRESS, MS_HVA);
            merged_bitmap = ms_retrieve_ptr_to_additional_memory(merged_vmcs, VMCS_MSR_BITMAP_ADDRESS, MS_HPA);

            ms_merge_bitmaps(level0_bitmap, NULL, merged_bitmap);
        }
    }

    // VMExit MSR-store address and count
    {
        IA32_VMX_MSR_ENTRY* level0_list = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_EXIT_MSR_STORE_ADDRESS, MS_HVA);
        UINT32 level0_list_count = (UINT32)vmcs_read(level0_vmcs, VMCS_EXIT_MSR_STORE_COUNT);

        if (level0_list_count > 256) {
            // TODO: proper handling
            VMM_DEADLOOP();
        }

        ms_merge_msr_list(gcpu, merged_vmcs, level0_list, NULL, level0_list_count,
                          0, MSR_LIST_COPY_NO_CHANGE, vmcs_add_msr_to_vmexit_store_list,
                          vmcs_clear_vmexit_store_list, vmcs_is_msr_in_vmexit_store_list,
                          VMCS_EXIT_MSR_STORE_ADDRESS, VMCS_EXIT_MSR_STORE_COUNT);
    }

    // VMExit MSR-load address and count
    {
        IA32_VMX_MSR_ENTRY* level0_list = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_EXIT_MSR_LOAD_ADDRESS, MS_HVA);
        UINT32 level0_list_count = (UINT32)vmcs_read(level0_vmcs, VMCS_EXIT_MSR_LOAD_COUNT);

        if (level0_list_count > 256) {
            // TODO: proper handling
            VMM_DEADLOOP();
        }

        ms_merge_msr_list(gcpu, merged_vmcs, level0_list, NULL, level0_list_count, 0,
                          MSR_LIST_COPY_NO_CHANGE, vmcs_add_msr_to_vmexit_load_list,
                          vmcs_clear_vmexit_load_list, vmcs_is_msr_in_vmexit_load_list,
                          VMCS_EXIT_MSR_LOAD_ADDRESS, VMCS_EXIT_MSR_LOAD_COUNT);
    }

    // VMEnter MSR-load address and count
    {
        IA32_VMX_MSR_ENTRY* level0_list = ms_retrieve_ptr_to_additional_memory(level0_vmcs, VMCS_ENTER_MSR_LOAD_ADDRESS, MS_HVA);
        UINT32 level0_list_count = (UINT32)vmcs_read(level0_vmcs, VMCS_ENTER_MSR_LOAD_COUNT);
        IA32_VMX_MSR_ENTRY* level1_list = ms_retrieve_ptr_to_additional_memory(level1_vmcs, VMCS_EXIT_MSR_LOAD_ADDRESS, MS_HVA);
        UINT32 level1_list_count = (UINT32)vmcs_read(level1_vmcs, VMCS_EXIT_MSR_LOAD_COUNT);
        VM_ENTRY_CONTROLS entry_ctrls;
        MSR_LIST_COPY_MODE copy_mode;

        if ((level0_list_count + level1_list_count) > 256) {
            // TODO: proper handling
            VMM_DEADLOOP();
        }

        entry_ctrls.Uint32 = (UINT32)gcpu_get_enter_ctrls_layered(gcpu, VMCS_MERGED);
        if (entry_ctrls.Bits.Ia32eModeGuest) {
            copy_mode = MSR_LIST_COPY_AND_SET_64_BIT_MODE_IN_EFER | MSR_LIST_COPY_UPDATE_GCPU;
        }
        else {
            copy_mode = MSR_LIST_COPY_AND_SET_32_BIT_MODE_IN_EFER | MSR_LIST_COPY_UPDATE_GCPU;
        }

        ms_merge_msr_list(gcpu, merged_vmcs, level1_list, level0_list, level1_list_count,
                          level0_list_count, copy_mode, vmcs_add_msr_to_vmenter_load_list,
                          vmcs_clear_vmenter_load_list, vmcs_is_msr_in_vmenter_load_list,
                          VMCS_ENTER_MSR_LOAD_ADDRESS, VMCS_ENTER_MSR_LOAD_COUNT);
    }

    // Copy host state from level-0 vmcs
    ms_copy_host_state(merged_vmcs, level0_vmcs);
}


/*
    Merge Algorithm:
    ---------------
        If VMCS#1.Timer-Enabled == FALSE ==> copy from VMCS#0
        else if VMCS#0.Timer-Enabled == FALSE ==> copy from VMCS#1
        else do real-merge:
            Save-Value = 1
            Enable=1
            Counter = Minimum of 2

    Split Algorithm:
    ---------------
        Control information is not split
        if Save-Value = 0 Counter not changed
        else
            if (Counter[i] < Counter[1-i]) Counter[i] = Counter[m]
            else Counter[i] = Counter[m] + Counter[i] - Counter[1-i]

    VMEXIT-request Analysis Algorithm: (implemented in other file)
    ---------------------------------
    if Save-Value == 0              VMEXIT-requested = TRUE;
    else if (counter#0 == counter#1)VMEXIT-requested = TRUE;
    else                            VMEXIT-requested = FALSE;
*/
void ms_merge_timer_to_level2(VMCS_OBJECT *vmcs_0, VMCS_OBJECT *vmcs_1, VMCS_OBJECT *vmcs_m)
{
    PIN_BASED_VM_EXECUTION_CONTROLS merged_pin_exec;
    VM_EXIT_CONTROLS                merged_vmexit_ctrls;
    UINT32                          merged_counter_value;
    PIN_BASED_VM_EXECUTION_CONTROLS pin_exec[2];
    UINT32                          counter_value[2];

    pin_exec[0].Uint32 = (UINT32)vmcs_read(vmcs_0, VMCS_CONTROL_VECTOR_PIN_EVENTS);
    pin_exec[1].Uint32 = (UINT32)vmcs_read(vmcs_1, VMCS_CONTROL_VECTOR_PIN_EVENTS);
    merged_pin_exec.Uint32 = (UINT32)vmcs_read(vmcs_m, VMCS_CONTROL_VECTOR_PIN_EVENTS);
    merged_vmexit_ctrls.Uint32 = (UINT32)vmcs_read(vmcs_m, VMCS_EXIT_CONTROL_VECTOR);

    merged_pin_exec.Bits.VmxTimer = pin_exec[0].Bits.VmxTimer || pin_exec[1].Bits.VmxTimer;

    if (0 == merged_pin_exec.Bits.VmxTimer) {
        // VMX Timer disabled
        merged_vmexit_ctrls.Bits.SaveVmxTimer = 0;
        merged_counter_value = 0;
    }
    else {
        VM_EXIT_CONTROLS vmexit_ctrls;

        // VMX Timer enabled at least in one VMCS
        if (0 == pin_exec[1].Bits.VmxTimer) {
            // copy from vmcs#0
            vmexit_ctrls.Uint32 = (UINT32) vmcs_read(vmcs_0, VMCS_EXIT_CONTROL_VECTOR);
            merged_vmexit_ctrls.Bits.SaveVmxTimer = vmexit_ctrls.Bits.SaveVmxTimer;
            merged_counter_value = (UINT32) vmcs_read(vmcs_0, VMCS_PREEMPTION_TIMER);
        }
        else if (0 == pin_exec[0].Bits.VmxTimer) {
            // copy from vmcs#1
            vmexit_ctrls.Uint32 = (UINT32) vmcs_read(vmcs_1, VMCS_EXIT_CONTROL_VECTOR);
            merged_vmexit_ctrls.Bits.SaveVmxTimer = vmexit_ctrls.Bits.SaveVmxTimer;
            merged_counter_value = (UINT32) vmcs_read(vmcs_1, VMCS_PREEMPTION_TIMER);
        }
        else {
            // VMX Timer enabled at least in one VMCS
            // so doing real merge here
            merged_vmexit_ctrls.Bits.SaveVmxTimer = 1;
            counter_value[0] = (UINT32) vmcs_read(vmcs_0, VMCS_PREEMPTION_TIMER);
            counter_value[1] = (UINT32) vmcs_read(vmcs_1, VMCS_PREEMPTION_TIMER);
            merged_counter_value = MIN(counter_value[0], counter_value[1]);
        }
    }
    vmcs_write(vmcs_m, VMCS_CONTROL_VECTOR_PIN_EVENTS, (UINT64) merged_pin_exec.Uint32);
    vmcs_write(vmcs_m, VMCS_EXIT_CONTROL_VECTOR, (UINT64) merged_vmexit_ctrls.Uint32);
    vmcs_write(vmcs_m, VMCS_PREEMPTION_TIMER, (UINT64) merged_counter_value);
}

void ms_split_timer_from_level2(VMCS_OBJECT *vmcs_0, VMCS_OBJECT *vmcs_1, VMCS_OBJECT *vmcs_m)
{
    PIN_BASED_VM_EXECUTION_CONTROLS pin_exec[2];
    VM_EXIT_CONTROLS                vmexit_ctrls[2];
    UINT32                          old_counter[2];
    UINT32                          new_counter;
    int i;

    pin_exec[0].Uint32     = (UINT32) vmcs_read(vmcs_0, VMCS_CONTROL_VECTOR_PIN_EVENTS);
    pin_exec[1].Uint32     = (UINT32) vmcs_read(vmcs_1, VMCS_CONTROL_VECTOR_PIN_EVENTS);
    vmexit_ctrls[0].Uint32 = (UINT32) vmcs_read(vmcs_0, VMCS_EXIT_CONTROL_VECTOR);
    vmexit_ctrls[1].Uint32 = (UINT32) vmcs_read(vmcs_1, VMCS_EXIT_CONTROL_VECTOR);
    old_counter[0]         = (UINT32) vmcs_read(vmcs_0, VMCS_PREEMPTION_TIMER);
    old_counter[1]         = (UINT32) vmcs_read(vmcs_1, VMCS_PREEMPTION_TIMER);

    for (i = 0; i < 2; ++i) {
        if (1 == pin_exec[i].Bits.VmxTimer && 1 == vmexit_ctrls[i].Bits.SaveVmxTimer) {
            if (0 == pin_exec[1 - i].Bits.VmxTimer) {
                new_counter = old_counter[i];
            }
            else {
                if (old_counter[i] <= old_counter[1 - i]) {
                    new_counter = (UINT32) vmcs_read(vmcs_m, VMCS_PREEMPTION_TIMER);
                }
                else {
                    new_counter = (UINT32) vmcs_read(vmcs_m, VMCS_PREEMPTION_TIMER)
                        + (old_counter[i] - old_counter[1 - i]);
                }
            }
            vmcs_write(vmcs_0, VMCS_PREEMPTION_TIMER, (UINT64) new_counter);
        }
    }

}
