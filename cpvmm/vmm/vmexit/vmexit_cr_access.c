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
#include "guest_cpu.h"
#include "vmcs_api.h"
#include "vmm_dbg.h"
#include "em64t_defs.h"
#include "guest_cpu_vmenter_event.h"
#include "policy_manager.h"
#include "vmm_events_data.h"
#include "vmcs_hierarchy.h"
#include "page_walker.h"
#include "ept.h"
#include "unrestricted_guest.h"
#include "vmm_callback.h"
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_CR_ACCESS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_CR_ACCESS_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define CR0_TASK_SWITCH     8
#define GCPU_SET_GUEST_VISIBLE_CONTROL_TO_L0_M(__gcpu, __reg_id, __value) {     \
    if (IA32_CTRL_CR0 == (__reg_id) ||  IA32_CTRL_CR4 == (__reg_id))           \
        gcpu_set_guest_visible_control_reg_layered(__gcpu, __reg_id, __value, VMCS_LEVEL_0);\
    gcpu_set_guest_visible_control_reg_layered(__gcpu, __reg_id, __value, VMCS_MERGED);\
}

extern BOOLEAN is_cr4_osxsave_supported(void);
static UVMM_EVENT lkup_write_event[IA32_CTRL_COUNT] = {
    EVENT_GCPU_AFTER_GUEST_CR0_WRITE,   // IA32_CTRL_CR0,
    EVENTS_COUNT,                       // IA32_CTRL_CR2,
    EVENT_GCPU_AFTER_GUEST_CR3_WRITE,   // IA32_CTRL_CR3,
    EVENT_GCPU_AFTER_GUEST_CR4_WRITE,   // IA32_CTRL_CR4,
    EVENTS_COUNT,                       // IA32_CTRL_CR8,
};

#define IA32_REG_COUNT 0x10

static VMM_IA32_GP_REGISTERS lkup_operand[IA32_REG_COUNT] = {
    IA32_REG_RAX,
    IA32_REG_RCX,
    IA32_REG_RDX,
    IA32_REG_RBX,
    IA32_REG_RSP,
    IA32_REG_RBP,
    IA32_REG_RSI,
    IA32_REG_RDI,
    IA32_REG_R8,
    IA32_REG_R9,
    IA32_REG_R10,
    IA32_REG_R11,
    IA32_REG_R12,
    IA32_REG_R13,
    IA32_REG_R14,
    IA32_REG_R15
};

#define IA32_CR_COUNT   0x9

static VMM_IA32_CONTROL_REGISTERS lkup_cr[IA32_CR_COUNT] = {
    IA32_CTRL_CR0,
    UNSUPPORTED_CR,
    UNSUPPORTED_CR,
    IA32_CTRL_CR3,
    IA32_CTRL_CR4,
    UNSUPPORTED_CR,
    UNSUPPORTED_CR,
    UNSUPPORTED_CR,
    IA32_CTRL_CR8
};

#define CPUID_SMEP_SUPPORTED_BIT 0x7
#define CPUID_M_RAX_7 0x7

/* Method to check if SMEP is supported or not on this processor.
 * Returns 0 if SMEP is not supported.
 *         1 if SMEP is supported.
 */
BOOLEAN is_cr4_smep_supported(void)
{
    CPUID_PARAMS cpuid_params;
    /* Invoke CPUID with RAX = 7 */
    cpuid_params.m_rax = CPUID_M_RAX_7;
    /* Set sub-leaf RCX to 0 */
    cpuid_params.m_rcx = 0;
    /* Execute CPUID */
    hw_cpuid(&cpuid_params);
    /* Return whether SMEP is supported or not */
    return (BOOLEAN) BIT_GET64( cpuid_params.m_rbx, CPUID_SMEP_SUPPORTED_BIT );
}

static BOOLEAN vmexit_cr_access_is_gpf0(GUEST_CPU_HANDLE gcpu) {
    EM64T_CR0 cr0;
    UINT64    cr3;
    EM64T_CR4 cr4;
    IA32_EFER_S efer;

    VMM_ASSERT(gcpu != NULL);
    cr0.Uint64 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);
    if ((cr0.Bits.PG && (!cr0.Bits.PE)) || (cr0.Bits.NW && (!cr0.Bits.CD))) {
        return TRUE;
    }
    cr4.Uint64 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
    if (cr4.Bits.Reserved_0 || cr4.Bits.Reserved_1 ||
        cr4.Bits.Reserved_2 || cr4.Bits.Reserved_3 ||
        cr4.Bits.VMXE || cr4.Bits.SMXE) {
        return TRUE;
    }
    if ( cr4.Bits.OSXSAVE && !is_cr4_osxsave_supported() ) {
        return TRUE;
    }
    if ( cr4.Bits.SMEP && !is_cr4_smep_supported() ) {
        return TRUE;
    }
    if (cr4.Bits.FSGSBASE && !is_fsgsbase_supported() ){
        return TRUE;
    }
    efer.Uint64 = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
    if (efer.Bits.LME && (!cr4.Bits.PAE)) {
        return TRUE;
    }
    // #GP conditions due to PCIDE feature. 
    if (cr4.Bits.PCIDE){
        //If this bit is not supported by h/w .
        if(!is_pcid_supported()){
            return TRUE;
        }
        //PCIDE bit Can be set only in IA-32e mode (if IA32_EFER.LMA = 1).
        if(!efer.Bits.LMA ){
            return TRUE;
        }
        cr3 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR3);
        //software can change CR4.PCIDE from 0 to 1 only if CR3[11:0] = 000H
        if(cr3 & 0x0FFF){
            return TRUE;
        }
        //MOVtoCR0 causes a #GP if it would clear CR0.PG to 0 while CR4.PCIDE=1.
        if(!cr0.Bits.PG){
            return TRUE;
        }        
    }
    if (cr0.Bits.PG && cr4.Bits.PAE && (!efer.Bits.LME)) {
        UINT8 pdpt[PW_NUM_OF_PDPT_ENTRIES_IN_32_BIT_MODE * PW_SIZE_OF_PAE_ENTRY];

        gcpu_get_32_bit_pdpt(gcpu, pdpt);
        if (!pw_is_pdpt_in_32_bit_pae_mode_valid(gcpu, pdpt)) {
            return TRUE;
        }
    }
    return FALSE;
}


static BOOLEAN cr_guest_update(GUEST_CPU_HANDLE gcpu, 
                VMM_IA32_CONTROL_REGISTERS reg_id,
                ADDRESS bits_to_update, IA32_VMX_EXIT_QUALIFICATION qualification);
static BOOLEAN cr_mov(GUEST_CPU_HANDLE gcpu, 
        IA32_VMX_EXIT_QUALIFICATION qualification);


RAISE_EVENT_RETVAL cr_raise_write_events( GUEST_CPU_HANDLE gcpu,
                            VMM_IA32_CONTROL_REGISTERS reg_id, ADDRESS new_value )
{
    EVENT_GCPU_GUEST_CR_WRITE_DATA event_data = {0};
    UVMM_EVENT event;
    RAISE_EVENT_RETVAL result = EVENT_NO_HANDLERS_REGISTERED;

    if(reg_id >= IA32_CTRL_COUNT)
        return result;
    event = lkup_write_event[reg_id];
    if (event != (UVMM_EVENT)EVENTS_COUNT) {
        event_data.new_guest_visible_value = new_value;
        if(TRUE == event_raise( event, gcpu, &event_data )) {
            result = EVENT_HANDLED;
        } else {
            result = EVENT_NOT_HANDLED;
        }
    }
    return result;
}

BOOLEAN cr_guest_update(GUEST_CPU_HANDLE gcpu, VMM_IA32_CONTROL_REGISTERS reg_id,
                ADDRESS bits_to_update, IA32_VMX_EXIT_QUALIFICATION qualification)
{
    UINT64 guest_cr;
    UINT64 old_visible_reg_value;
    UINT64 visible_guest_cr;
    RAISE_EVENT_RETVAL cr_update_event;
    ADDRESS value;
    REPORT_CR_DR_LOAD_ACCESS_DATA cr_access_data;

#ifdef JLMDEBUG
    bprint("cr_guest_update %d\n", reg_id);
#endif
    if(qualification.CrAccess.AccessType == 3)
        value = qualification.CrAccess.LmswData;
    else
        value = 0;
    cr_access_data.qualification = qualification.Uint64;
    if (report_uvmm_event(UVMM_EVENT_CR_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, 
                          (const GUEST_VCPU*)guest_vcpu(gcpu), 
                          (void *)&cr_access_data)) {
        return FALSE;
    }
    old_visible_reg_value = gcpu_get_guest_visible_control_reg_layered(gcpu, 
                                            reg_id, VMCS_MERGED);
    visible_guest_cr = old_visible_reg_value;
    BITMAP_ASSIGN64(visible_guest_cr, bits_to_update, value);

    // update guest visible CR-X
    // gcpu_set_guest_visible_control_reg_layered(gcpu, reg_id, 
    //                  visible_guest_cr, VMCS_MERGED);
    GCPU_SET_GUEST_VISIBLE_CONTROL_TO_L0_M(gcpu, reg_id, visible_guest_cr);
    if (vmexit_cr_access_is_gpf0(gcpu)) {
    // gcpu_set_guest_visible_control_reg_layered(gcpu, reg_id, 
    //          old_visible_reg_value, VMCS_MERGED);
        GCPU_SET_GUEST_VISIBLE_CONTROL_TO_L0_M(gcpu, reg_id, old_visible_reg_value);

        // CR* access vmexit is changed to GPF0 exception.
        VMM_LOG(mask_anonymous, level_trace,"%s: CR* access caused GPF0\n", 
                __FUNCTION__);
        VMM_DEBUG_CODE(VMM_DEADLOOP());
        gcpu_inject_gp0(gcpu);
        return FALSE;
    }
    // update guest CR-X
    guest_cr = gcpu_get_control_reg_layered(gcpu, reg_id, VMCS_MERGED);
    BITMAP_ASSIGN64(guest_cr, bits_to_update, value);
    gcpu_set_control_reg_layered(gcpu, reg_id, guest_cr, VMCS_MERGED);
    cr_update_event = cr_raise_write_events( gcpu, reg_id, visible_guest_cr );
    if(cr_update_event==EVENT_NOT_HANDLED) {
#ifdef JLMDEBUG
        bprint("cr_guest_update event not handled\n");
        LOOP_FOREVER
#endif
    }
#ifdef JLMDEBUG
    bprint("cr_guest_update returning true\n");
#endif
    return TRUE;
}

BOOLEAN cr_guest_write( GUEST_CPU_HANDLE gcpu, VMM_IA32_CONTROL_REGISTERS reg_id,
                        ADDRESS value)
{
    RAISE_EVENT_RETVAL cr_update_event;
    UINT64 old_visible_reg_value;
    const VIRTUAL_CPU_ID* vcpu_id = NULL;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;

#ifdef JLMDEBUG
    bprint("cr_guest_write %d\n", reg_id);
#endif
    old_visible_reg_value = gcpu_get_guest_visible_control_reg_layered(gcpu, 
                                        reg_id, VMCS_MERGED);
    // gcpu_set_guest_visible_control_reg_layered(gcpu, reg_id, value, VMCS_MERGED);
    GCPU_SET_GUEST_VISIBLE_CONTROL_TO_L0_M(gcpu, reg_id, value);
    if (vmexit_cr_access_is_gpf0(gcpu)) {
        //  gcpu_set_guest_visible_control_reg_layered(gcpu, reg_id, 
        //                  old_visible_reg_value, VMCS_MERGED);
        GCPU_SET_GUEST_VISIBLE_CONTROL_TO_L0_M(gcpu, reg_id, old_visible_reg_value);

        // CR* access vmexit is changed to GPF0 exception.
        VMM_LOG(mask_anonymous, level_trace,"%s: CR* access caused GPF0\n", 
                __FUNCTION__);
        VMM_DEBUG_CODE(VMM_DEADLOOP());
        gcpu_inject_gp0(gcpu);
        return FALSE;
    }
    if(is_unrestricted_guest_supported()) {
        vcpu_id = guest_vcpu(gcpu);
        VMM_ASSERT(vcpu_id);        
        ept_guest = ept_find_guest_state(vcpu_id->guest_id);
        VMM_ASSERT(ept_guest);
        ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];
        ept_guest_cpu->cr0 = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR0, 
                                            VMCS_MERGED);
        ept_guest_cpu->cr4 = gcpu_get_control_reg_layered(gcpu, IA32_CTRL_CR4, 
                                            VMCS_MERGED);
    }
    gcpu_set_control_reg_layered(gcpu, reg_id, value, VMCS_MERGED);
    cr_update_event= cr_raise_write_events(gcpu, reg_id, value);
#ifdef JLMDEBUG
    bprint("cr_guest_write, position 8\n");
#endif
    if(cr_update_event==EVENT_NOT_HANDLED) {
#ifdef JLMDEBUG
        bprint("event not handled\n");
        LOOP_FOREVER
#endif
    }
    if((reg_id == IA32_CTRL_CR4) && is_cr4_osxsave_supported()) {
        EM64T_CR4 cr4_mask;
                
        cr4_mask.Uint64 = 0;
        cr4_mask.Bits.OSXSAVE = 1;
        vmcs_write(gcpu_get_vmcs(gcpu), VMCS_HOST_CR4, 
                   (vmcs_read(gcpu_get_vmcs(gcpu),VMCS_HOST_CR4) 
                    & ~cr4_mask.Uint64) | (value & cr4_mask.Uint64) );
    }
#ifdef JLMDEBUG
    bprint("cr_guest_write returning true\n");
#endif
    return TRUE;
}

BOOLEAN cr_mov( GUEST_CPU_HANDLE gcpu, IA32_VMX_EXIT_QUALIFICATION qualification)

{
    VMM_IA32_CONTROL_REGISTERS  cr_id;
    VMM_IA32_GP_REGISTERS operand;
    ADDRESS cr_value;
    BOOLEAN status = TRUE;
    REPORT_CR_DR_LOAD_ACCESS_DATA cr_access_data;

#ifdef JLMDEBUG
    bprint("cr_mov\n");
#endif
    cr_access_data.qualification = qualification.Uint64;
    if (report_uvmm_event(UVMM_EVENT_CR_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, 
                    (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&cr_access_data)) {
        return FALSE;
    }
    VMM_ASSERT(qualification.CrAccess.Number < NELEMENTS(lkup_cr));
    cr_id = lkup_cr[qualification.CrAccess.Number];
    VMM_ASSERT(UNSUPPORTED_CR != cr_id);
    VMM_ASSERT(qualification.CrAccess.MoveGpr < NELEMENTS(lkup_operand));
    operand = lkup_operand[qualification.CrAccess.MoveGpr];

    switch (qualification.CrAccess.AccessType) {
      case 0: // move to CR
        cr_value = gcpu_get_gp_reg(gcpu, operand);
        status = cr_guest_write(gcpu, cr_id, cr_value);
        break;
      case 1: // move from CR
        cr_value = gcpu_get_guest_visible_control_reg(gcpu, cr_id);
                // VMM_LOG(mask_anonymous, level_trace, "move from CR") ;
        gcpu_set_gp_reg(gcpu, operand, cr_value);
        break;
      default:
        VMM_DEADLOOP();
        break;
    }
    return status;
}

VMEXIT_HANDLING_STATUS vmexit_cr_access(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT*                vmcs = gcpu_get_vmcs(gcpu);
    IA32_VMX_EXIT_QUALIFICATION qualification;
    BOOLEAN                     status = TRUE;

    qualification.Uint64 = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    switch (qualification.CrAccess.AccessType) {
      case 0: // move to CR
      case 1: // move from CR
        status = cr_mov(gcpu, qualification);
        break;
      case 2: // CLTS
        VMM_ASSERT(0 == qualification.CrAccess.Number);
        status= cr_guest_update(gcpu, IA32_CTRL_CR0, CR0_TASK_SWITCH, qualification);
        break;
      case 3: // LMSW
        VMM_ASSERT(0 == qualification.CrAccess.Number);
        status = cr_guest_update(gcpu, IA32_CTRL_CR0, 0xFFFF, qualification);
        break;
    }
    if (TRUE == status) {
        gcpu_skip_guest_instruction(gcpu);
    }
    return VMEXIT_HANDLED;
}

VMM_IA32_CONTROL_REGISTERS vmexit_cr_access_get_cr_from_qualification(
                                        UINT64 qualification) {
    IA32_VMX_EXIT_QUALIFICATION qualification_tmp;

    qualification_tmp.Uint64 = qualification;
    if(qualification_tmp.CrAccess.Number >= IA32_CR_COUNT)
        return UNSUPPORTED_CR;
    return lkup_cr[qualification_tmp.CrAccess.Number];
}

VMM_IA32_GP_REGISTERS vmexit_cr_access_get_operand_from_qualification(UINT64 qualification) {
    IA32_VMX_EXIT_QUALIFICATION qualification_tmp;

    qualification_tmp.Uint64 = qualification;
    VMM_ASSERT(qualification_tmp.CrAccess.MoveGpr < IA32_REG_COUNT);

    return lkup_operand[qualification_tmp.CrAccess.MoveGpr];
}
