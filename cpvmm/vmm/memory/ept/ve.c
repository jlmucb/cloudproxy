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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VE_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VE_C, __condition)
#include "vmcs_init.h"
#include "host_memory_manager_api.h"
#include "guest.h"
#include "..\..\guest\guest_cpu\guest_cpu_internal.h"
#include "isr.h"
#include "guest_cpu_vmenter_event.h"
#include "ve.h"
#include "memory_address_mapper_api.h"
#include "gpm_api.h"

BOOLEAN ve_is_hw_supported(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();

    return (hw_constraints->ve_supported);
}

BOOLEAN ve_is_ve_enabled(GUEST_CPU_HANDLE gcpu)
{
    return (gcpu->ve_desc.ve_enabled);
}

BOOLEAN ve_update_hpa(GUEST_ID guest_id, CPU_ID guest_cpu_id, HPA hpa, UINT32 enable)
{
    GUEST_GCPU_ECONTEXT gcpu_context;
    GUEST_HANDLE guest;
    GUEST_CPU_HANDLE gcpu;
    VIRTUAL_CPU_ID vcpu_id;

    // check if hpa is used by other CPUs in previous enables
    if (enable) {
        guest = guest_handle(guest_id);
        for (gcpu=guest_gcpu_first(guest, &gcpu_context); gcpu; gcpu=guest_gcpu_next(&gcpu_context)) {
            if (!ve_is_ve_enabled(gcpu))
                continue;
            if (gcpu->vcpu.guest_cpu_id == guest_cpu_id)
                continue;
            if (gcpu->ve_desc.ve_info_hpa == hpa)
                return FALSE;
        }
    }

    vcpu_id.guest_id = guest_id;
    vcpu_id.guest_cpu_id = guest_cpu_id;
    gcpu = gcpu_state(&vcpu_id);
    //paranoid check. If assertion fails, possible memory corruption.
    VMM_ASSERT(gcpu);

    gcpu->ve_desc.ve_info_hpa = hpa;
    return TRUE;
}

static
void ve_activate_hw_ve(GUEST_CPU_HANDLE gcpu, BOOLEAN enable)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2  proc_ctrls2;
    VMEXIT_CONTROL                          vmexit_request;

    proc_ctrls2.Uint32 = 0;
    vmm_zeromem(&vmexit_request, sizeof(vmexit_request));

    proc_ctrls2.Bits.VE                    = 1;
    vmexit_request.proc_ctrls2.bit_mask    = proc_ctrls2.Uint32;
    vmexit_request.proc_ctrls2.bit_request = enable ? UINT64_ALL_ONES : 0;

    gcpu_control2_setup(gcpu, &vmexit_request);
}

void ve_enable_ve(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT *vmcs;
    HVA hva;

    if (ve_is_hw_supported()) {
        vmcs = gcpu_get_vmcs(gcpu);
        vmcs_write(vmcs, VMCS_VE_INFO_ADDRESS, (UINT64)gcpu->ve_desc.ve_info_hpa);
        ve_activate_hw_ve(gcpu, TRUE);
    } else {
        if (hmm_hpa_to_hva(gcpu->ve_desc.ve_info_hpa, &hva) == FALSE)
            return;
        gcpu->ve_desc.ve_info_hva = hva;
    }

    gcpu->ve_desc.ve_enabled = TRUE;
}

void ve_disable_ve(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT *vmcs;

    if (ve_is_hw_supported()) {
        ve_activate_hw_ve(gcpu, FALSE);
        vmcs = gcpu_get_vmcs(gcpu);
        vmcs_write(vmcs, VMCS_VE_INFO_ADDRESS, 0);
    }

    gcpu->ve_desc.ve_enabled = FALSE;
}

//
// returns TRUE - SW #VE injected
BOOLEAN ve_handle_sw_ve(GUEST_CPU_HANDLE gcpu, UINT64 qualification, UINT64 gla, UINT64 gpa, UINT64 view)
{
    VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);
    VE_EPT_INFO *hva;
    GUEST_HANDLE guest;
    IA32_VMCS_EXCEPTION_BITMAP exceptions;
    EM64T_CR0 cr0;
    HPA hpa;
    MAM_ATTRIBUTES attrs;
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING idt_vectoring_info;

    if (ve_is_hw_supported())
        return FALSE;

    if (!ve_is_ve_enabled(gcpu))
        return FALSE;

    hva = (VE_EPT_INFO *)gcpu->ve_desc.ve_info_hva;
    VMM_ASSERT(hva);

    // check flag
    if (hva->flag != 0)
        return FALSE;

    // check PE
    cr0.Uint64 = vmcs_read(vmcs, VMCS_GUEST_CR0);
    if (0 == cr0.Bits.PE)
        return FALSE;

    // check the logical processor is not in the process of delivering an
    // event through the IDT
    idt_vectoring_info.Uint32 =
            (UINT32)vmcs_read(vmcs, VMCS_EXIT_INFO_IDT_VECTORING);
    if (idt_vectoring_info.Bits.Valid)
        return FALSE;

    // check exception bitmap bit 20
    exceptions.Uint32 = (UINT32)vmcs_read(vmcs, VMCS_EXCEPTION_BITMAP);
    if (exceptions.Bits.VE)
        return FALSE;

    // check eptp pte bit 63
    guest = gcpu_guest_handle(gcpu);
    if (!gpm_gpa_to_hpa(gcpu_get_current_gpm(guest), gpa, &hpa, &attrs))
        return FALSE;
    if (attrs.ept_attr.suppress_ve) {
        return FALSE;
    }

    hva->exit_reason = Ia32VmxExitBasicReasonEptViolation;
    hva->flag = 0xFFFFFFFF;	// must clear flag in ISR
    hva->exit_qualification = qualification;
    hva->gla = gla;
    hva->gpa = gpa;
    hva->eptp_index = (UINT16)view;

    // inject soft #VE
    return gcpu_inject_fault(gcpu, IA32_EXCEPTION_VECTOR_VIRTUAL_EXCEPTION, 0);
}
