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

#include "vmm_defs.h"
#include "vmcs_init.h"
#include "ept_hw_layer.h"
#include "hw_utils.h"
#include "guest_cpu.h"
#include "vmcs_api.h"
#include "vmm_phys_mem_types.h"
#include "libc.h"
#include "scheduler.h"
#include "guest_cpu_internal.h"
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(EPT_HW_LAYER_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(EPT_HW_LAYER_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define ENABLE_VPID

BOOLEAN ept_hw_is_ept_supported(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();

    return (hw_constraints->may1_processor_based_exec_ctrl.Bits.SecondaryControls
            && hw_constraints->may1_processor_based_exec_ctrl2.Bits.EnableEPT);
}

void ept_hw_set_pdtprs(GUEST_CPU_HANDLE gcpu, UINT64 pdptr[])
{
    VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);

    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    vmcs_write(vmcs, VMCS_GUEST_PDPTR0, pdptr[0]);
    vmcs_write(vmcs, VMCS_GUEST_PDPTR1, pdptr[1]);
    vmcs_write(vmcs, VMCS_GUEST_PDPTR2, pdptr[2]);
    vmcs_write(vmcs, VMCS_GUEST_PDPTR3, pdptr[3]);
}
#ifdef INCLUDE_UNUSED_CODE
void ept_hw_get_pdtprs(GUEST_CPU_HANDLE gcpu, UINT64 pdptr[])
{
    VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);

    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    pdptr[0] = vmcs_read(vmcs, VMCS_GUEST_PDPTR0);
    pdptr[1] = vmcs_read(vmcs, VMCS_GUEST_PDPTR1);
    pdptr[2] = vmcs_read(vmcs, VMCS_GUEST_PDPTR2);
    pdptr[3] = vmcs_read(vmcs, VMCS_GUEST_PDPTR3);
}
#endif

UINT32 ept_hw_get_guest_address_width(UINT32 actual_gaw)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    if(actual_gaw <= 21 && hw_constraints->ept_vpid_capabilities.Bits.GAW_21_bit) {
        return 21;
    }
    if(actual_gaw <= 30 && hw_constraints->ept_vpid_capabilities.Bits.GAW_30_bit) {
        return 30;
    }
    if(actual_gaw <= 39 && hw_constraints->ept_vpid_capabilities.Bits.GAW_39_bit) {
        return 39;
    }
    if(actual_gaw <= 48 && hw_constraints->ept_vpid_capabilities.Bits.GAW_48_bit) {
        return 48;
    }
    if(actual_gaw <= 57 && hw_constraints->ept_vpid_capabilities.Bits.GAW_57_bit) {
        return 57;
    }
    VMM_ASSERT(0);
    return (UINT32) -1;
}

UINT32 ept_hw_get_guest_address_width_encoding(UINT32 width)
{
    UINT32 gaw_encoding = (UINT32) -1;

    VMM_ASSERT(width == 21 || width == 30 || width == 39 || width == 48 || width == 57);
    gaw_encoding = (width - 21) / 9;
    return gaw_encoding;
}

UINT32 ept_hw_get_guest_address_width_from_encoding(UINT32 gaw_encoding)
{
    VMM_ASSERT(gaw_encoding <= 4);
    return 21 + (gaw_encoding * 9);
}

VMM_PHYS_MEM_TYPE ept_hw_get_ept_memory_type(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();

    if(hw_constraints->ept_vpid_capabilities.Bits.WB) {
        return VMM_PHYS_MEM_WRITE_BACK;
    }
    if(hw_constraints->ept_vpid_capabilities.Bits.WP) {
        return VMM_PHYS_MEM_WRITE_PROTECTED;
    }
    if(hw_constraints->ept_vpid_capabilities.Bits.WT) {
        return VMM_PHYS_MEM_WRITE_THROUGH;
    }
    if(hw_constraints->ept_vpid_capabilities.Bits.WC) {
        return VMM_PHYS_MEM_WRITE_COMBINING;
    }
    if(hw_constraints->ept_vpid_capabilities.Bits.UC) {
        return VMM_PHYS_MEM_UNCACHABLE;
    }
    VMM_ASSERT(0);
    return VMM_PHYS_MEM_UNDEFINED;
}

UINT64 ept_hw_get_eptp(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    UINT64 eptp = 0;

    VMM_ASSERT(gcpu);
    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    if(! ept_hw_is_ept_supported()) {
        return eptp;
    }
    eptp = vmcs_read( vmcs, VMCS_EPTP_ADDRESS);
    return eptp;
}

BOOLEAN ept_hw_set_eptp(GUEST_CPU_HANDLE gcpu, HPA ept_root_hpa, UINT32 gaw)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    EPTP eptp;
    UINT32 ept_gaw = 0;

    VMM_ASSERT(gcpu);
    VMM_ASSERT(vmcs);
    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    if(! ept_hw_is_ept_supported() || ept_root_hpa == 0) {
        return FALSE;
    }
    ept_gaw = ept_hw_get_guest_address_width(gaw);
    if(ept_gaw == (UINT32) -1) {
        return FALSE;
    }
    eptp.Uint64 = ept_root_hpa;
    eptp.Bits.ETMT = ept_hw_get_ept_memory_type();
    eptp.Bits.GAW = ept_hw_get_guest_address_width_encoding(ept_gaw);
    eptp.Bits.Reserved = 0;
    vmcs_write( vmcs, VMCS_EPTP_ADDRESS, eptp.Uint64);
    return TRUE;
}

BOOLEAN ept_hw_is_ept_enabled(GUEST_CPU_HANDLE gcpu)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 proc_ctrls2;

    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    proc_ctrls2.Uint32 = (UINT32) vmcs_read(gcpu_get_vmcs(gcpu), VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS);
    return proc_ctrls2.Bits.EnableEPT;
}

// invalidate EPT
BOOLEAN ept_hw_is_invept_supported(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();

    if(ept_hw_is_ept_supported() && hw_constraints->ept_vpid_capabilities.Bits.InveptSupported) {
        return TRUE;
    }
    return FALSE;
}

// invalidate VPID
BOOLEAN ept_hw_is_invvpid_supported(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();

    if(ept_hw_is_ept_supported() && hw_constraints->ept_vpid_capabilities.Bits.InvvpidSupported) {
        return TRUE;
    }
#ifdef JLMDEBUG
    bprint("ept_hw_is_invvpid_supported is returning false\n");
#endif
    return FALSE;
}

BOOLEAN ept_hw_invept_all_contexts(void)
{
    INVEPT_ARG arg;
    UINT64 rflags;
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    BOOLEAN status = FALSE;

    if(! ept_hw_is_invept_supported()) {
        return TRUE;
    }
    vmm_zeromem(&arg, sizeof(arg));
    if(hw_constraints->ept_vpid_capabilities.Bits.InveptAllContexts) {
        vmm_asm_invept(&arg, INVEPT_ALL_CONTEXTS, &rflags);
        status = ((rflags & 0x8d5) == 0);
        if(! status) {
            VMM_LOG(mask_anonymous, level_trace,"ept_hw_invept_all_contexts ERROR: rflags = %p\r\n", rflags);
        }
    }
    return status;
}

BOOLEAN ept_hw_invept_context(UINT64 eptp)
{
    INVEPT_ARG arg;
    UINT64 rflags;
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    BOOLEAN status = FALSE;

    if(! ept_hw_is_invept_supported()) {
        return TRUE;
    }
    vmm_zeromem(&arg, sizeof(arg));
    VMM_ASSERT(eptp != 0);
    arg.eptp = eptp;
    if(hw_constraints->ept_vpid_capabilities.Bits.InveptContextWide) {
        vmm_asm_invept(&arg, INVEPT_CONTEXT_WIDE, &rflags);
        status = ((rflags & 0x8d5) == 0);
        if(! status) {
            VMM_LOG(mask_anonymous, level_trace,"ept_hw_invept_context ERROR: eptp = %p rflags = %p\r\n", eptp, rflags);
        }
    }
    else {
        ept_hw_invept_all_contexts();
    }
    return status;
}

BOOLEAN ept_hw_invept_individual_address(UINT64 eptp, ADDRESS gpa)
{
    INVEPT_ARG arg;
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    UINT64 rflags;
    BOOLEAN status = FALSE;

    if(! ept_hw_is_invept_supported()) {
        return TRUE;
    }
    vmm_zeromem(&arg, sizeof(arg));
    VMM_ASSERT((eptp != 0) && (gpa != 0));
    arg.eptp = eptp;
    arg.gpa = gpa;
    if(hw_constraints->ept_vpid_capabilities.Bits.InveptIndividualAddress) {
        vmm_asm_invept(&arg, INVEPT_INDIVIDUAL_ADDRESS, &rflags);
        status = ((rflags & 0x8d5) == 0);
        if(! status) {
            VMM_LOG(mask_anonymous, level_trace,
                    "ept_hw_invept_individual_address ERROR: eptp = %p gpa = %p rflags = %p\r\n", 
                    eptp, gpa, rflags);
        }
    }
    else {
        ept_hw_invept_context(eptp);
    }
    return status;
}

BOOLEAN ept_hw_invvpid_individual_address(UINT64 vpid, ADDRESS gva)
{
    INVVPID_ARG arg;
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    UINT64 rflags;
    BOOLEAN status = FALSE;

    if(!ept_hw_is_invvpid_supported()) {
        VMM_ASSERT(0);
        return TRUE;
    }
    arg.vpid = vpid;
    arg.gva = gva;
    if(hw_constraints->ept_vpid_capabilities.Bits.InvvpidIndividualAddress) {
        vmm_asm_invvpid(&arg, INVVPID_INDIVIDUAL_ADDRESS, &rflags);
        status = ((rflags & 0x8d5) == 0);
        if(! status) {
            VMM_LOG(mask_anonymous, level_trace,
                    "ept_hw_invvpid_individual_address ERROR: vpid = %d gva = %p rflags = %p\r\n", 
                    vpid, gva, rflags);
                    VMM_ASSERT(0);
        }
    }
    return status;
}

BOOLEAN ept_hw_invvpid_all_contexts(void)
{
    INVVPID_ARG arg;
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    UINT64 rflags;
    BOOLEAN status = FALSE;

    if(! ept_hw_is_invvpid_supported()) {
                VMM_ASSERT(0);
        return TRUE;
    }
    arg.vpid = 0; // vpid;
    //arg.gva = gva;

    if(hw_constraints->ept_vpid_capabilities.Bits.InvvpidAllContexts) {
        vmm_asm_invvpid(&arg, INVVPID_ALL_CONTEXTS, &rflags);
        status = ((rflags & 0x8d5) == 0);
        if(! status) {
            VMM_LOG(mask_anonymous, level_trace,"ept_hw_invvpid_all_contexts ERROR: rflags = %p\r\n", rflags);
                        VMM_ASSERT(0);
        }
    }
    return status;
}


BOOLEAN ept_hw_invvpid_single_context(UINT64 vpid)
{
    INVVPID_ARG arg;
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    UINT64 rflags;
    BOOLEAN status = FALSE;

#ifdef JLMDEBUG
    bprint("ept_hw_invvpid_single_context\n");
#endif
    if(!ept_hw_is_invvpid_supported()) {
        VMM_ASSERT(0);
        return TRUE;
    }
    arg.vpid = vpid;
    if(hw_constraints->ept_vpid_capabilities.Bits.InvvpidContextWide) {
        vmm_asm_invvpid(&arg, INVVPID_SINGLE_CONTEXT, &rflags);
        status = ((rflags & 0x8d5) == 0);
        if(!status) {
#ifdef JLMDEBUG
            bprint("vmm_asm_invvpid failed\n");
#endif
            VMM_LOG(mask_anonymous, level_trace,
            "ept_hw_invvpid_all_contexts ERROR: rflags = %p\r\n", rflags);
            VMM_ASSERT(0);
        }
    }
    return status;
}

BOOLEAN ept_hw_enable_ept(GUEST_CPU_HANDLE gcpu)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 proc_ctrls2;
    VMEXIT_CONTROL vmexit_request;

    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    VMM_ASSERT(gcpu);
    if(! ept_hw_is_ept_supported()) {
        return FALSE;
    }
    proc_ctrls2.Uint32 = 0;
    vmm_zeromem(&vmexit_request, sizeof(vmexit_request));

    proc_ctrls2.Bits.EnableEPT = 1;
#ifdef ENABLE_VPID
    proc_ctrls2.Bits.EnableVPID = 1;
    vmcs_write(gcpu_get_vmcs(gcpu), VMCS_VPID, 1 + gcpu->vcpu.guest_id); 
#endif
    vmexit_request.proc_ctrls2.bit_mask    = proc_ctrls2.Uint32;
    vmexit_request.proc_ctrls2.bit_request = UINT64_ALL_ONES;
    // FIXME
    gcpu_control_setup( gcpu, &vmexit_request );
    return TRUE;
}

void ept_hw_disable_ept(GUEST_CPU_HANDLE gcpu)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 proc_ctrls2;
    VMEXIT_CONTROL vmexit_request;
    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    ept_hw_invvpid_single_context(1 + gcpu->vcpu.guest_id);
    proc_ctrls2.Uint32 = 0;
    vmm_zeromem(&vmexit_request, sizeof(vmexit_request));
    proc_ctrls2.Bits.EnableEPT = 1;
#ifdef ENABLE_VPID
    proc_ctrls2.Bits.EnableVPID = 1;
    vmcs_write(gcpu_get_vmcs(gcpu), VMCS_VPID, 0);
#endif
    vmexit_request.proc_ctrls2.bit_mask    = proc_ctrls2.Uint32;
    vmexit_request.proc_ctrls2.bit_request = 0;
    // FIXME
    gcpu_control_setup( gcpu, &vmexit_request );
}
