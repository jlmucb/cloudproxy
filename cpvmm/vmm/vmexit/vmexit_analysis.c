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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_ANALYSIS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_ANALYSIS_C, __condition)
#include <vmm_defs.h>
#include <vmm_dbg.h>
#include <vmcs_api.h>
#include <vmx_vmcs.h>
#include <vmx_ctrl_msrs.h>
#include <vmm_objects.h>
#include <isr.h>
#include <vmm_arch_defs.h>
#include <vmexit_cr_access.h>
#include <guest_cpu.h>
#include <guest.h>
#include <gpm_api.h>
#include <host_memory_manager_api.h>
#include <vmexit_analysis.h>
#include "vmm_callback.h"

#pragma warning (disable : 4100)

typedef BOOLEAN (*VMEXIT_IS_CONTROL_REQUESTED_FUNC)(GUEST_CPU_HANDLE, VMCS_OBJECT*, VMCS_OBJECT*);

static
BOOLEAN vmexit_analysis_true_func(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs UNUSED) {
    return TRUE;
}

static
BOOLEAN vmexit_analysis_false_func(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs UNUSED) {
    return FALSE;
}

static
BOOLEAN vmexit_analysis_interrupt_window_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.VirtualInterrupt == 1);
}

static
BOOLEAN vmexit_analysis_nmi_window_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.NmiWindow == 1);
}

static
BOOLEAN vmexit_analysis_hlt_inst_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.Hlt == 1);
}

static
BOOLEAN vmexit_analysis_invlpg_inst_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.Invlpg == 1);
}

static
BOOLEAN vmexit_analysis_rdpmc_inst_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.Rdpmc == 1);
}

static
BOOLEAN vmexit_analysis_rdtsc_inst_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.Rdtsc == 1);
}

static
BOOLEAN vmexit_analysis_dr_access_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.MovDr == 1);
}

static
BOOLEAN vmexit_analysis_mwait_inst_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.Mwait == 1);
}

static
BOOLEAN vmexit_analysis_monitor_inst_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.Monitor == 1);
}

static
BOOLEAN vmexit_analysis_pause_inst_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS level1_ctrls;

    level1_ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (level1_ctrls.Bits.Pause == 1);
}

static
BOOLEAN vmexit_analysis_softinterrupt_exception_nmi_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs, VMCS_OBJECT* control_vmcs) {
    IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO interrupt_info;
    UINT32 vector;

    interrupt_info.Uint32 = (UINT32)vmcs_read(vmexit_vmcs, VMCS_EXIT_INFO_EXCEPTION_INFO);
    vector = (UINT32)interrupt_info.Bits.Vector;

    if (vector == IA32_EXCEPTION_VECTOR_PAGE_FAULT) {
        IA32_VMCS_EXCEPTION_BITMAP level1_exceptions;
        UINT32 pfec = (UINT32)vmcs_read(vmexit_vmcs, VMCS_EXIT_INFO_EXCEPTION_ERROR_CODE);
        UINT32 level1_pfec_mask = (UINT32)vmcs_read(vmexit_vmcs, VMCS_PAGE_FAULT_ERROR_CODE_MASK);
        UINT32 level1_pfec_match = (UINT32)vmcs_read(vmexit_vmcs, VMCS_PAGE_FAULT_ERROR_CODE_MATCH);

        VMM_ASSERT(interrupt_info.Bits.InterruptType != VmExitInterruptTypeExternalInterrupt);
        VMM_ASSERT(interrupt_info.Bits.InterruptType != VmExitInterruptTypeNmi);

        level1_exceptions.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_EXCEPTION_BITMAP);
        if (level1_exceptions.Bits.PF == 1) {
            return ((pfec & level1_pfec_mask) == level1_pfec_match);
        }
        else {
            return ((pfec & level1_pfec_mask) != level1_pfec_match);
        }
    }
    else if (interrupt_info.Bits.InterruptType == VmExitInterruptTypeNmi){
        PIN_BASED_VM_EXECUTION_CONTROLS level1_pin_ctrls;

        VMM_ASSERT(vector == IA32_EXCEPTION_VECTOR_NMI);
        level1_pin_ctrls.Uint32 = (UINT32)vmcs_read(vmexit_vmcs, VMCS_CONTROL_VECTOR_PIN_EVENTS);
        return (level1_pin_ctrls.Bits.Nmi == 1);
    }
    else {
        UINT32 level1_exceptions = (UINT32)vmcs_read(control_vmcs, VMCS_EXCEPTION_BITMAP);

        return ((level1_exceptions & (1 << vector)) != 0);
    }

}

static
BOOLEAN vmexit_analysis_hardware_interrupt_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs, VMCS_OBJECT* control_vmcs UNUSED) {
    PIN_BASED_VM_EXECUTION_CONTROLS level1_pin_ctrls;

    level1_pin_ctrls.Uint32 = (UINT32)vmcs_read(vmexit_vmcs, VMCS_CONTROL_VECTOR_PIN_EVENTS);
    return (level1_pin_ctrls.Bits.ExternalInterrupt == 1);
}

static
BOOLEAN vmexit_analysis_is_cr3_in_target_list(VMCS_OBJECT* vmcs, UINT64 cr3_value) {
    UINT32 cr3_target_count = (UINT32)vmcs_read(vmcs, VMCS_CR3_TARGET_COUNT);
    UINT32 i;

    VMM_ASSERT(cr3_target_count <= 4);
    for (i = 0; i < cr3_target_count; i++) {
        UINT64 value = vmcs_read(vmcs, (VMCS_FIELD)(VMCS_CR3_TARGET_VALUE_0 + i));

        if (value == cr3_value) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN vmexit_analysis_is_exit_on_cr_update(VMCS_OBJECT* vmcs, UINT64 new_value, VMCS_FIELD shadow_field, VMCS_FIELD mask_field) {
    UINT64 shadow = vmcs_read(vmcs, shadow_field);
    UINT64 mask = vmcs_read(vmcs, mask_field);
    BOOLEAN result;

    result = ((shadow & mask) != (new_value & mask));

    return result;
}

static
BOOLEAN vmexit_analysis_cr_access_exiting(GUEST_CPU_HANDLE gcpu, VMCS_OBJECT* vmexit_vmcs, VMCS_OBJECT* control_vmcs) {
    IA32_VMX_EXIT_QUALIFICATION qualification;

    qualification.Uint64 = vmcs_read(vmexit_vmcs, VMCS_EXIT_INFO_QUALIFICATION);

    switch (qualification.CrAccess.AccessType)
    {
    case 0: // move to CR
        {
            VMM_IA32_CONTROL_REGISTERS cr_id = vmexit_cr_access_get_cr_from_qualification(qualification.Uint64);
            VMM_IA32_GP_REGISTERS operand = vmexit_cr_access_get_operand_from_qualification(qualification.Uint64);
            UINT64 new_value = gcpu_get_gp_reg(gcpu, operand);

            if (cr_id == IA32_CTRL_CR3) {
                // return TRUE in case the value is not in target list
                return (vmexit_analysis_is_cr3_in_target_list(control_vmcs, new_value) == FALSE);
            }
            else if (cr_id == IA32_CTRL_CR0) {
                return vmexit_analysis_is_exit_on_cr_update(control_vmcs, new_value, VMCS_CR0_READ_SHADOW, VMCS_CR0_MASK);
            }
            else if (cr_id == IA32_CTRL_CR4) {
                return vmexit_analysis_is_exit_on_cr_update(control_vmcs, new_value, VMCS_CR4_READ_SHADOW, VMCS_CR4_MASK);
            }
            else {
                PROCESSOR_BASED_VM_EXECUTION_CONTROLS ctrls;

                VMM_ASSERT(cr_id == IA32_CTRL_CR8);
                ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);

                if (ctrls.Bits.Cr8Load) {
                    return TRUE;
                }

                if (ctrls.Bits.TprShadow) {
                    // TODO: currently TPR shadow is not supported
                    VMM_LOG(mask_anonymous, level_trace,"%s: Currently TPR shadow is not supported\n", __FUNCTION__);
                    VMM_DEADLOOP();
                }

                return FALSE;
            }
            break;
        }
    case 1: // move from CR
        {
            VMM_IA32_CONTROL_REGISTERS cr_id = vmexit_cr_access_get_cr_from_qualification(qualification.Uint64);

            if (cr_id == IA32_CTRL_CR3) {
                return TRUE;
            }
            else {
                PROCESSOR_BASED_VM_EXECUTION_CONTROLS ctrls;

                VMM_ASSERT(cr_id == IA32_CTRL_CR8);

                ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
                if (ctrls.Bits.Cr8Store) {
                    return TRUE;
                }

                if (ctrls.Bits.TprShadow) {
                    // TODO: currently TPR shadow is not supported
                    VMM_LOG(mask_anonymous, level_trace,"%s: Currently TPR shadow is not supported\n");
                    VMM_DEADLOOP();
                }

                return FALSE;
            }

            break;
        }

    case 2: // CLTS
        {
            EM64T_CR0 cr0_shadow;
            EM64T_CR0 cr0_mask;

            VMM_ASSERT(0 == qualification.CrAccess.Number);

            cr0_shadow.Uint64 = vmcs_read(control_vmcs, VMCS_CR0_READ_SHADOW);
            cr0_mask.Uint64 = vmcs_read(control_vmcs, VMCS_CR0_MASK);

            return ((cr0_mask.Bits.TS == 1) && (cr0_shadow.Bits.TS != 0));
            break;
        }

    case 3: // LMSW
        {
            EM64T_CR0 cr0_shadow;
            EM64T_CR0 cr0_mask;
            UINT32 mask_tmp;

            VMM_ASSERT(0 == qualification.CrAccess.Number);

            cr0_shadow.Uint64 = vmcs_read(control_vmcs, VMCS_CR0_READ_SHADOW);
            cr0_mask.Uint64 = vmcs_read(control_vmcs, VMCS_CR0_MASK);
            mask_tmp = (UINT32)(cr0_mask.Uint64 & 0xffff);
            return ((mask_tmp != 0) &&
                    ((cr0_shadow.Uint64 & mask_tmp) != (qualification.CrAccess.LmswData & mask_tmp)));
            break;
        }
    }

    // should not reach here
    VMM_DEADLOOP();
    return FALSE;
}

static
void* vmexit_analysis_retrieve_ptr_to_additional_memory(IN VMCS_OBJECT* vmcs,
                                                                IN VMCS_FIELD field,
                                                                IN BOOLEAN convert_gpa_to_hpa) {
    UINT64 bitmap_pa = vmcs_read(vmcs, field);
    UINT64 bitmap_hpa;
    UINT64 bitmap_hva;
	MAM_ATTRIBUTES attrs;

    if (convert_gpa_to_hpa) {
        GUEST_CPU_HANDLE gcpu = vmcs_get_owner(vmcs);
        GUEST_HANDLE guest = gcpu_guest_handle(gcpu);
        GPM_HANDLE gpm = gcpu_get_current_gpm(guest);
        if (!gpm_gpa_to_hpa(gpm, bitmap_pa, &bitmap_hpa, &attrs)) {
            VMM_DEADLOOP();
        }
    }
    else {
        bitmap_hpa = bitmap_pa;
    }

    if (!hmm_hpa_to_hva(bitmap_hpa, &bitmap_hva)) {
        VMM_DEADLOOP();
    }

    return (void*)bitmap_hva;
}

static
BOOLEAN vmexit_analysis_is_bit_set_in_bitmap(void* bitmap, UINT32 bit_pos) {
    UINT32 byte = bit_pos >> 3;
    UINT32 pos_in_byte = bit_pos & 0x7;
    UINT8* bitmap_tmp = (UINT8*)bitmap;

    return ((bitmap_tmp[byte] & (1 << pos_in_byte)) != 0);
}

static
BOOLEAN vmexit_analysis_io_exiting(GUEST_CPU_HANDLE gcpu UNUSED, VMCS_OBJECT* vmexit_vmcs, VMCS_OBJECT* control_vmcs) {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS ctrls;
    IA32_VMX_EXIT_QUALIFICATION qualification;
    UINT32 port;
    UINT32 size = 0;
    VMCS_LEVEL control_vmcs_level;

    ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);

    if (ctrls.Bits.ActivateIoBitmaps == 0) {
        return (ctrls.Bits.UnconditionalIo == 1);
    }

    qualification.Uint64 = vmcs_read(vmexit_vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    port = qualification.IoInstruction.PortNumber;
    switch (qualification.IoInstruction.Size) {
    case 0:
        size = 1;
        break;
    case 1:
        size = 2;
        break;
    case 3:
        size = 4;
        break;
    default:
        VMM_DEADLOOP();
    }

    if ((port + size) > 0xffff) {
        // wrap around
        return TRUE;
    }

    control_vmcs_level = vmcs_get_level(control_vmcs);
    if (port < 0x7fff) {
        void* bitmap = vmexit_analysis_retrieve_ptr_to_additional_memory(control_vmcs, VMCS_IO_BITMAP_ADDRESS_A, (control_vmcs_level == VMCS_LEVEL_1));
        return vmexit_analysis_is_bit_set_in_bitmap(bitmap, port);
    }
    else {
        void* bitmap = vmexit_analysis_retrieve_ptr_to_additional_memory(control_vmcs, VMCS_IO_BITMAP_ADDRESS_B, (control_vmcs_level == VMCS_LEVEL_1));
        UINT32 bit_pos = port & 0x7fff;
        return vmexit_analysis_is_bit_set_in_bitmap(bitmap, bit_pos);
    }
}

static
BOOLEAN vmexit_analysis_msr_access_exiting(GUEST_CPU_HANDLE gcpu,
                                           VMCS_OBJECT* control_vmcs,
                                           BOOLEAN is_rdmsr) {
    MSR_ID msr_id;
    HVA bitmap_hva;
    UINT32 bitmap_pos;
    void* bitmap;
    VMCS_LEVEL control_vmcs_level;
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS ctrls;

    ctrls.Uint32 = (UINT32)vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);

    if (ctrls.Bits.UseMsrBitmaps == 0) {
        return TRUE;
    }

    msr_id = (MSR_ID) gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);

    if ((msr_id > 0x1fff) &&
        (msr_id < 0xc0000000)) {
        return TRUE;
    }

    if (msr_id > 0xc0001fff) {
        return TRUE;
    }

    control_vmcs_level = vmcs_get_level(control_vmcs);
    bitmap_hva = (HVA)vmexit_analysis_retrieve_ptr_to_additional_memory(control_vmcs, VMCS_MSR_BITMAP_ADDRESS, (control_vmcs_level == VMCS_LEVEL_1));
    bitmap_pos = msr_id & 0x1fff;

    if (is_rdmsr) {
        if (msr_id <= 0x1fff) {
            bitmap = (void*)bitmap_hva;
        }
        else {
            VMM_ASSERT(msr_id >= 0xc0000000);
            VMM_ASSERT(msr_id <= 0xc0001fff);
            bitmap = (void*)(bitmap_hva + (1 KILOBYTE));
        }
    }
    else {
        if (msr_id <= 0x1fff) {
            bitmap = (void*)(bitmap_hva + (2 KILOBYTES));
        }
        else {
            VMM_ASSERT(msr_id >= 0xc0000000);
            VMM_ASSERT(msr_id <= 0xc0001fff);
            bitmap = (void*)(bitmap_hva + (3 KILOBYTES));
        }
    }

    return vmexit_analysis_is_bit_set_in_bitmap(bitmap, bitmap_pos);
}

static
BOOLEAN vmexit_analysis_rdmsr_exiting(GUEST_CPU_HANDLE gcpu, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {

    return vmexit_analysis_msr_access_exiting(gcpu, control_vmcs, TRUE);
}

static
BOOLEAN vmexit_analysis_wrmsr_exiting(GUEST_CPU_HANDLE gcpu, VMCS_OBJECT* vmexit_vmcs UNUSED, VMCS_OBJECT* control_vmcs) {

    return vmexit_analysis_msr_access_exiting(gcpu, control_vmcs, FALSE);
}

static
BOOLEAN vmexit_analysis_timer_exiting(
                GUEST_CPU_HANDLE gcpu,
                VMCS_OBJECT* vmexit_vmcs UNUSED,
                VMCS_OBJECT* control_vmcs)
{
//    VMEXIT-request Analysis Algorithm:
//    ---------------------------------
//    if Save-Value == 0                VMEXIT-requested = TRUE;
//    else if (counter <= other-counter)VMEXIT-requested = TRUE;
//    else                              VMEXIT-requested = FALSE;

    PIN_BASED_VM_EXECUTION_CONTROLS pin_exec;
    PIN_BASED_VM_EXECUTION_CONTROLS peer_pin_exec;
    BOOLEAN                         vmexit_requested = FALSE;
    VMCS_OBJECT                    *peer_control_vmcs;
    VM_EXIT_CONTROLS                vmexit_ctrls;
    UINT32                          counter_value;
    UINT32                          peer_counter_value;

    pin_exec.Uint32 = (UINT32) vmcs_read(control_vmcs, VMCS_CONTROL_VECTOR_PIN_EVENTS);
    if (1 == pin_exec.Bits.VmxTimer)
    {
        // find other VMCS
        if (VMCS_LEVEL_0 == vmcs_get_level(control_vmcs))
            peer_control_vmcs = gcpu_get_vmcs_layered(gcpu, VMCS_LEVEL_1);
        else if (VMCS_LEVEL_1 == vmcs_get_level(control_vmcs))
            peer_control_vmcs = gcpu_get_vmcs_layered(gcpu, VMCS_LEVEL_0);
        else
        {
            VMM_ASSERT(0);
            return TRUE;
        }

        peer_pin_exec.Uint32 = (UINT32) vmcs_read(peer_control_vmcs, VMCS_CONTROL_VECTOR_PIN_EVENTS);
        if (0 == peer_pin_exec.Bits.VmxTimer)
        {
            // if other vmcs did not requested it
            // apparently it did the current level vmcs. don't check further
            vmexit_requested = TRUE;
        }
        else
        {
            // here both layers requested VMEXIT
            vmexit_ctrls.Uint32 = (UINT32) vmcs_read(control_vmcs, VMCS_EXIT_CONTROL_VECTOR);
            if (vmexit_ctrls.Bits.SaveVmxTimer)
            {
                counter_value = (UINT32) vmcs_read(control_vmcs, VMCS_PREEMPTION_TIMER);
                peer_counter_value = (UINT32) vmcs_read(peer_control_vmcs, VMCS_PREEMPTION_TIMER);
                if (counter_value <= peer_counter_value)
                {
                    vmexit_requested = TRUE;
                }
            }
            else
            {
                //:BUGBUG: Dima insists to handle this case in a more precise way
                VMM_ASSERT(0);
                vmexit_requested = TRUE;
            }
        }
    }

    return vmexit_requested;
}


VMEXIT_IS_CONTROL_REQUESTED_FUNC vmexit_is_control_requested_func[Ia32VmxExitBasicReasonCount] = {
/*  0 Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi */ vmexit_analysis_softinterrupt_exception_nmi_exiting,
/*  1 Ia32VmxExitBasicReasonHardwareInterrupt */             vmexit_analysis_hardware_interrupt_exiting,
/*  2 Ia32VmxExitBasicReasonTripleFault */                   vmexit_analysis_true_func,
/*  3 Ia32VmxExitBasicReasonInitEvent */                     vmexit_analysis_true_func,
/*  4 Ia32VmxExitBasicReasonSipiEvent */                     vmexit_analysis_true_func,
/*  5 Ia32VmxExitBasicReasonSmiIoEvent */                    vmexit_analysis_true_func,
/*  6 Ia32VmxExitBasicReasonSmiOtherEvent */                 vmexit_analysis_true_func,
/*  7 Ia32VmxExitBasicReasonPendingInterrupt */              vmexit_analysis_interrupt_window_exiting,
/*  8 Ia32VmxExitNmiWindow */                                vmexit_analysis_nmi_window_exiting,
/*  9 Ia32VmxExitBasicReasonTaskSwitch */                    vmexit_analysis_true_func,
/* 10 Ia32VmxExitBasicReasonCpuidInstruction */              vmexit_analysis_true_func,
/* 11 Ia32VmxExitBasicReasonGetsecInstruction */             vmexit_analysis_true_func,
/* 12 Ia32VmxExitBasicReasonHltInstruction */                vmexit_analysis_hlt_inst_exiting,
/* 13 Ia32VmxExitBasicReasonInvdInstruction */               vmexit_analysis_true_func,
/* 14 Ia32VmxExitBasicReasonInvlpgInstruction */             vmexit_analysis_invlpg_inst_exiting,
/* 15 Ia32VmxExitBasicReasonRdpmcInstruction */              vmexit_analysis_rdpmc_inst_exiting,
/* 16 Ia32VmxExitBasicReasonRdtscInstruction */              vmexit_analysis_rdtsc_inst_exiting,
/* 17 Ia32VmxExitBasicReasonRsmInstruction */                vmexit_analysis_true_func,
/* 18 Ia32VmxExitBasicReasonVmcallInstruction */             vmexit_analysis_true_func,
/* 19 Ia32VmxExitBasicReasonVmclearInstruction */            vmexit_analysis_true_func,
/* 20 Ia32VmxExitBasicReasonVmlaunchInstruction */           vmexit_analysis_true_func,
/* 21 Ia32VmxExitBasicReasonVmptrldInstruction */            vmexit_analysis_true_func,
/* 22 Ia32VmxExitBasicReasonVmptrstInstruction */            vmexit_analysis_true_func,
/* 23 Ia32VmxExitBasicReasonVmreadInstruction */             vmexit_analysis_true_func,
/* 24 Ia32VmxExitBasicReasonVmresumeInstruction */           vmexit_analysis_true_func,
/* 25 Ia32VmxExitBasicReasonVmwriteInstruction */            vmexit_analysis_true_func,
/* 26 Ia32VmxExitBasicReasonVmxoffInstruction */             vmexit_analysis_true_func,
/* 27 Ia32VmxExitBasicReasonVmxonInstruction */              vmexit_analysis_true_func,
/* 28 Ia32VmxExitBasicReasonCrAccess */                      vmexit_analysis_cr_access_exiting,
/* 29 Ia32VmxExitBasicReasonDrAccess */                      vmexit_analysis_dr_access_exiting,
/* 30 Ia32VmxExitBasicReasonIoInstruction */                 vmexit_analysis_io_exiting,
/* 31 Ia32VmxExitBasicReasonMsrRead */                       vmexit_analysis_rdmsr_exiting,
/* 32 Ia32VmxExitBasicReasonMsrWrite */                      vmexit_analysis_wrmsr_exiting,
/* 33 Ia32VmxExitBasicReasonFailedVmEnterGuestState */       vmexit_analysis_true_func,
/* 34 Ia32VmxExitBasicReasonFailedVmEnterMsrLoading */       vmexit_analysis_true_func,
/* 35 Ia32VmxExitBasicReasonFailedVmExit */                  vmexit_analysis_false_func,
/* 36 Ia32VmxExitBasicReasonMwaitInstruction */              vmexit_analysis_mwait_inst_exiting,
/* 37 Ia32VmxExitBasicReasonMonitorTrapFlag */               vmexit_analysis_false_func,
/* 38 Ia32VmxExitBasicReasonInvalidVmexitReason38 */         vmexit_analysis_false_func,
/* 39 Ia32VmxExitBasicReasonMonitor */                       vmexit_analysis_monitor_inst_exiting,
/* 40 Ia32VmxExitBasicReasonPause */                         vmexit_analysis_pause_inst_exiting,
/* 41 Ia32VmxExitBasicReasonFailureDueMachineCheck */        vmexit_analysis_true_func,
/* 42 Ia32VmxExitBasicReasonInvalidVmexitReason42 */         vmexit_analysis_false_func,
/* 43 Ia32VmxExitBasicReasonTprBelowThreshold */             vmexit_analysis_false_func,
/* 44 Ia32VmxExitBasicReasonApicAccess */                    vmexit_analysis_false_func,
/* 45 Ia32VmxExitBasicReasonInvalidVmexitReason45 */         vmexit_analysis_false_func,
/* 46 Ia32VmxExitBasicReasonGdtrIdtrAccess */                vmexit_analysis_false_func,
/* 47 Ia32VmxExitBasicReasonLdtrTrAccess */                  vmexit_analysis_false_func,
/* 48 Ia32VmxExitBasicReasonEptViolation */                  vmexit_analysis_false_func,
/* 48 Ia32VmxExitBasicReasonEptMisconfiguration */           vmexit_analysis_false_func,
/* 50 Ia32VmxExitBasicReasonInveptInstruction */             vmexit_analysis_false_func,
/* 51 Ia32VmxExitBasicReasonRdtscpInstruction */             vmexit_analysis_false_func,
/* 52 Ia32VmxExitBasicReasonPreemptionTimerExpired */        vmexit_analysis_timer_exiting,
/* 53 Ia32VmxExitBasicReasonInvvpidInstruction */            vmexit_analysis_false_func,
/* 54 Ia32VmxExitBasicReasonInvalidVmexitReason54 */         vmexit_analysis_false_func,
/* 55 Ia32VmxExitBasicReasonXsetbvInstruction */             vmexit_analysis_true_func
};

BOOLEAN vmexit_analysis_was_control_requested(GUEST_CPU_HANDLE gcpu,
                                              VMCS_OBJECT* vmexit_vmcs,
                                              VMCS_OBJECT* control_vmcs,
                                              IA32_VMX_EXIT_BASIC_REASON exit_reason) {
    if (exit_reason >= Ia32VmxExitBasicReasonCount) {
        return FALSE;
    }

    VMM_ASSERT(vmexit_vmcs != NULL);
    VMM_ASSERT(control_vmcs != NULL);

    return vmexit_is_control_requested_func[exit_reason](gcpu, vmexit_vmcs, control_vmcs);
}
