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
#include "guest_cpu.h"
#include "vmm_dbg.h"
#include "vmexit_dtr_tr.h"
#include "ia32_defs.h"
#include "host_memory_manager_api.h"
#include "vmm_callback.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_DTR_TR_ACCESS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_DTR_TR_ACCESS_C, __condition)

#define _MTF_SINGLE_STEP_

//
// Utils
//


#ifdef DEBUG
// Disabling unreferenced formal parameter warnings
#pragma warning ( push )
#pragma warning ( disable : 4100 )
void print_instruction_info(IA32_VMX_VMCS_VM_EXIT_INFO_INSTRUCTION_INFO *instruction_info)
{
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits                      = %08X\n\n", instruction_info->Bits);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.Scaling              = %08X\n", instruction_info->Bits.Scaling);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.Reserved_0           = %08X\n", instruction_info->Bits.Reserved_0);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.Register1            = %08X\n", instruction_info->Bits.Register1);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.AddressSize          = %08X\n", instruction_info->Bits.AddressSize);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.RegisterMemory       = %08X\n", instruction_info->Bits.RegisterMemory);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.OperandSize           = %08X\n", instruction_info->Bits.OperandSize);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.Reserved_2           = %08X\n", instruction_info->Bits.Reserved_2);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.Segment              = %08X\n", instruction_info->Bits.Segment);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.IndexRegister        = %08X\n", instruction_info->Bits.IndexRegister);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.IndexRegisterInvalid = %08X\n", instruction_info->Bits.IndexRegisterInvalid);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.BaseRegister         = %08X\n", instruction_info->Bits.BaseRegister);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.BaseRegisterInvalid  = %08X\n", instruction_info->Bits.BaseRegisterInvalid);
	VMM_LOG(mask_anonymous, level_trace,"instruction_info.Bits.Register2            = %08X\n", instruction_info->Bits.Register2);
}

void print_guest_gprs(GUEST_CPU_HANDLE gcpu)
{
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_RCX = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_RCX));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_RDX = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_RDX));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_RBX = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_RBX));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_RBP = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_RBP));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_RSI = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_RSI));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_RDI = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_RDI));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R8  = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R8));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R9  = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R9));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R10 = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R10));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R11 = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R11));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R12 = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R12));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R13 = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R13));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R14 = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R14));
		VMM_LOG(mask_anonymous, level_trace,"IA32_REG_R15 = %08X\n", gcpu_get_gp_reg(gcpu, IA32_REG_R15));
}
#pragma warning ( pop )
#endif

//
// VMEXIT Handlers
//

VMEXIT_HANDLING_STATUS vmexit_dr_access(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    REPORT_CR_DR_LOAD_ACCESS_DATA dr_load_access_data;

    dr_load_access_data.qualification = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);

    if (!report_uvmm_event(UVMM_EVENT_DR_LOAD_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&dr_load_access_data)) {
        VMM_LOG(mask_anonymous, level_trace, "report_dr_load_access failed\n");
    }
    return VMEXIT_HANDLED;
}

VMEXIT_HANDLING_STATUS vmexit_gdtr_idtr_access(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    REPORT_DTR_ACCESS_DATA gdtr_idtr_access_data;

    gdtr_idtr_access_data.qualification = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    gdtr_idtr_access_data.instruction_info = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_INFO);

    if (!report_uvmm_event(UVMM_EVENT_GDTR_IDTR_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&gdtr_idtr_access_data)) {
        VMM_LOG(mask_anonymous, level_trace, "report_gdtr_idtr_access failed\n");
    }
    return VMEXIT_HANDLED;
}

VMEXIT_HANDLING_STATUS vmexit_ldtr_tr_access(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    REPORT_DTR_ACCESS_DATA ldtr_load_access_data;

    ldtr_load_access_data.qualification= vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    ldtr_load_access_data.instruction_info = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_INFO);

    if (!report_uvmm_event(UVMM_EVENT_LDTR_LOAD_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&ldtr_load_access_data)) {
        VMM_LOG(mask_anonymous, level_trace, "report_ldtr_load_access failed\n");
    }

    return VMEXIT_HANDLED;
}
