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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_C, __condition)
#include "vmm_defs.h"
#include "heap.h"
#include "scheduler.h"
#include "vmx_asm.h"
#include "vmm_globals.h"
#include "vmcs_actual.h"
#include "guest.h"
#include "em64t_defs.h"
#include "vmexit_msr.h"
#include "vmexit_io.h"
#include "vmcall.h"
#include "vmexit_cpuid.h"
#include "vmexit.h"
#include "vmm_dbg.h"
#include "list.h"
#include "lock.h"
#include "memory_allocator.h"
#include "vmexit_analysis.h"
#include "guest_cpu_vmenter_event.h"
#include "host_cpu.h"
#include "guest_cpu_internal.h"
#include "vmenter_checks.h"
#include "vmm_callback.h"
#ifdef FAST_VIEW_SWITCH
#include "fvs.h"
#endif
#include "isr.h"
#include "memory_dump.h"
#include "vmexit_dtr_tr.h"
#include "profiling.h"

BOOLEAN legacy_scheduling_enabled = TRUE;

extern BOOLEAN vmcs_sw_shadow_disable[];
extern VMEXIT_HANDLING_STATUS vmexit_cr_access(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_triple_fault(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_undefined_opcode(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_init_event(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_sipi_event(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_task_switch(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_invlpg(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_invd(GUEST_CPU_HANDLE gcpu);
extern void vmexit_check_keystroke(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_ept_violation(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_ept_misconfiguration(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS msr_failed_vmenter_loading_handler(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_mtf(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmxon_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmxoff_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmlaunch_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmresume_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmclear_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmptrld_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmptrst_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmread_instruction(GUEST_CPU_HANDLE gcpu);
extern VMEXIT_HANDLING_STATUS vmexit_vmwrite_instruction(GUEST_CPU_HANDLE gcpu);
VMEXIT_HANDLING_STATUS vmexit_halt_instruction(GUEST_CPU_HANDLE gcpu);
VMEXIT_HANDLING_STATUS vmexit_xsetbv(GUEST_CPU_HANDLE gcpu);
VMEXIT_HANDLING_STATUS vmexit_vmentry_failure_due2_machine_check(GUEST_CPU_HANDLE gcpu);
#ifdef FAST_VIEW_SWITCH
VMEXIT_HANDLING_STATUS vmexit_invalid_vmfunc(GUEST_CPU_HANDLE gcpu);
#endif

UINT32 /* ASM_FUNCTION */ vmexit_check_ept_violation(void);

extern int CLI_active(void);

static void vmexit_bottom_up_common_handler(GUEST_CPU_HANDLE gcpu, UINT32 reason);
static void vmexit_bottom_up_all_vmms_skip_instruction(GUEST_CPU_HANDLE gcpu, UINT32 reason);
static void vmexit_top_down_common_handler(GUEST_CPU_HANDLE gcpu, UINT32 reason);

typedef struct _GUEST_VMEXIT_CONTROL {
    GUEST_ID            guest_id;
    char                padding[6];
    VMEXIT_HANDLER      vmexit_handlers[Ia32VmxExitBasicReasonCount];
    UINT64              vmexit_counter[Ia32VmxExitBasicReasonCount];
    LIST_ELEMENT        list[1];
} GUEST_VMEXIT_CONTROL;

typedef struct {
    LIST_ELEMENT guest_vmexit_controls[1];
} VMEXIT_GLOBAL_STATE;

static VMEXIT_GLOBAL_STATE         vmexit_global_state;  // for all guests

typedef void (*VMEXIT_CLASSIFICATION_FUNC)(GUEST_CPU_HANDLE gcpu, UINT32 reason);

static VMEXIT_CLASSIFICATION_FUNC vmexit_classification_func[Ia32VmxExitBasicReasonCount] = {
/*  0 Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi */ vmexit_bottom_up_common_handler,
/*  1 Ia32VmxExitBasicReasonHardwareInterrupt */             vmexit_bottom_up_common_handler,
/*  2 Ia32VmxExitBasicReasonTripleFault */                   vmexit_top_down_common_handler,
/*  3 Ia32VmxExitBasicReasonInitEvent  */
#ifdef INIT_LAYERED_IS_SUPPORTED
    vmexit_top_down_common_handler, // top-down because we have nothing to do with it, except reboot
#else
    vmexit_bottom_up_common_handler,
#endif
/*  4 Ia32VmxExitBasicReasonSipiEvent */                     vmexit_bottom_up_common_handler,
/*  5 Ia32VmxExitBasicReasonSmiIoEvent */                    vmexit_bottom_up_common_handler,
/*  6 Ia32VmxExitBasicReasonSmiOtherEvent */                 vmexit_bottom_up_common_handler,
/*  7 Ia32VmxExitBasicReasonPendingInterrupt */              vmexit_top_down_common_handler,
/*  8 Ia32VmxExitNmiWindow  */                               vmexit_top_down_common_handler,
/*  9 Ia32VmxExitBasicReasonTaskSwitch */                    vmexit_top_down_common_handler,
/* 10 Ia32VmxExitBasicReasonCpuidInstruction */              vmexit_top_down_common_handler,
/* 11 Ia32VmxExitBasicReasonGetsecInstruction */             vmexit_top_down_common_handler,
/* 12 Ia32VmxExitBasicReasonHltInstruction */                vmexit_top_down_common_handler,
/* 13 Ia32VmxExitBasicReasonInvdInstruction */               vmexit_top_down_common_handler,
/* 14 Ia32VmxExitBasicReasonInvlpgInstruction */             vmexit_bottom_up_all_vmms_skip_instruction,
/* 15 Ia32VmxExitBasicReasonRdpmcInstruction */              vmexit_top_down_common_handler,
/* 16 Ia32VmxExitBasicReasonRdtscInstruction */              vmexit_top_down_common_handler,
/* 17 Ia32VmxExitBasicReasonRsmInstruction */                vmexit_top_down_common_handler,
/* 18 Ia32VmxExitBasicReasonVmcallInstruction */             vmexit_bottom_up_common_handler,
/* 19 Ia32VmxExitBasicReasonVmclearInstruction */            vmexit_top_down_common_handler,
/* 20 Ia32VmxExitBasicReasonVmlaunchInstruction */           vmexit_top_down_common_handler,
/* 21 Ia32VmxExitBasicReasonVmptrldInstruction */            vmexit_top_down_common_handler,
/* 22 Ia32VmxExitBasicReasonVmptrstInstruction */            vmexit_top_down_common_handler,
/* 23 Ia32VmxExitBasicReasonVmreadInstruction */             vmexit_top_down_common_handler,
/* 24 Ia32VmxExitBasicReasonVmresumeInstruction */           vmexit_top_down_common_handler,
/* 25 Ia32VmxExitBasicReasonVmwriteInstruction */            vmexit_top_down_common_handler,
/* 26 Ia32VmxExitBasicReasonVmxoffInstruction */             vmexit_top_down_common_handler,
/* 27 Ia32VmxExitBasicReasonVmxonInstruction */              vmexit_top_down_common_handler,
/* 28 Ia32VmxExitBasicReasonCrAccess */                      vmexit_top_down_common_handler,
/* 29 Ia32VmxExitBasicReasonDrAccess */                      vmexit_top_down_common_handler,
/* 30 Ia32VmxExitBasicReasonIoInstruction */                 vmexit_top_down_common_handler,
/* 31 Ia32VmxExitBasicReasonMsrRead */                       vmexit_top_down_common_handler,
/* 32 Ia32VmxExitBasicReasonMsrWrite */                      vmexit_top_down_common_handler,
/* 33 Ia32VmxExitBasicReasonFailedVmEnterGuestState */       vmexit_bottom_up_common_handler,
/* 34 Ia32VmxExitBasicReasonFailedVmEnterMsrLoading */       vmexit_bottom_up_common_handler,
/* 35 Ia32VmxExitBasicReasonFailedVmExit */                  vmexit_top_down_common_handler,
/* 36 Ia32VmxExitBasicReasonMwaitInstruction */              vmexit_top_down_common_handler,
/* 37 Ia32VmxExitBasicReasonMonitorTrapFlag */               vmexit_top_down_common_handler,
/* 38 Ia32VmxExitBasicReasonInvalidVmexitReason38 */         vmexit_top_down_common_handler,
/* 39 Ia32VmxExitBasicReasonMonitor */                       vmexit_top_down_common_handler,
/* 40 Ia32VmxExitBasicReasonPause */                         vmexit_top_down_common_handler,
/* 41 Ia32VmxExitBasicReasonFailureDueMachineCheck */        vmexit_bottom_up_common_handler,
/* 42 Ia32VmxExitBasicReasonInvalidVmexitReason42 */         vmexit_top_down_common_handler,
/* 43 Ia32VmxExitBasicReasonTprBelowThreshold */             vmexit_top_down_common_handler,
/* 44 Ia32VmxExitBasicReasonApicAccess */                    vmexit_top_down_common_handler,
/* 45 Ia32VmxExitBasicReasonInvalidVmexitReason45 */         vmexit_top_down_common_handler,
/* 46 Ia32VmxExitBasicReasonGdtrIdtrAccess */                vmexit_top_down_common_handler,
/* 47 Ia32VmxExitBasicReasonLdtrTrAccess */                  vmexit_top_down_common_handler,
/* 48 Ia32VmxExitBasicReasonEptViolation */                  vmexit_bottom_up_common_handler,
/* 48 Ia32VmxExitBasicReasonEptMisconfiguration */           vmexit_bottom_up_common_handler,
/* 50 Ia32VmxExitBasicReasonInveptInstruction */             vmexit_bottom_up_common_handler,
/* 51 Ia32VmxExitBasicReasonRdtscpInstruction */             vmexit_top_down_common_handler,
/* 52 Ia32VmxExitBasicReasonPreemptionTimerExpired */        vmexit_bottom_up_common_handler,
/* 53 Ia32VmxExitBasicReasonInvvpidInstruction */            vmexit_top_down_common_handler,
/* 54 Ia32VmxExitBasicReasonInvalidVmexitReason54 */         vmexit_top_down_common_handler,
/* 55 Ia32VmxExitBasicReasonXsetbvInstruction */             vmexit_top_down_common_handler,
#ifdef FAST_VIEW_SWITCH
/* 56 Ia32VmxExitBasicReasonPlaceHolder1 */                  vmexit_top_down_common_handler,
/* 57 Ia32VmxExitBasicReasonPlaceHolder2 */                  vmexit_top_down_common_handler,
/* 58 Ia32VmxExitBasicReasonPlaceHolder3 */                  vmexit_top_down_common_handler,
/* 59 Ia32VmxExitBasicReasonInvalidVmfunc */                 vmexit_top_down_common_handler
#endif
};

////////// T.B.D. ////////////////////
#define NMI_DO_PROCESSING()

extern void vmexit_nmi_exception_handlers_install(GUEST_ID guest_id);
static void vmexit_handler_invoke(GUEST_CPU_HANDLE gcpu, UINT32 reason);
static GUEST_VMEXIT_CONTROL* vmexit_find_guest_vmexit_control(GUEST_ID guest_id);

// FUNCTION : vmexit_setup()
// PURPOSE  : Populate guest table, containing specific VMEXIT handlers with
//          : default handlers
// ARGUMENTS: GUEST_ID num_of_guests
void vmexit_initialize(void)
{
    GUEST_HANDLE   guest;
    GUEST_ECONTEXT guest_ctx;

    vmm_memset( &vmexit_global_state, 0, sizeof(vmexit_global_state) );
    list_init(vmexit_global_state.guest_vmexit_controls);
    io_vmexit_initialize();
    vmcall_intialize();
    for( guest = guest_first( &guest_ctx ); guest; guest = guest_next( &guest_ctx )) {
        vmexit_guest_initialize(guest_get_id(guest));
    }
}

// FUNCTION : vmexit_guest_initialize()
// PURPOSE  : Populate guest table, containing specific VMEXIT handlers with
//          : default handlers
// ARGUMENTS: GUEST_ID guest_id
// RETURNS  : void
void vmexit_guest_initialize(GUEST_ID guest_id)
{
    GUEST_VMEXIT_CONTROL *guest_vmexit_control = NULL;
    UINT32 i;

    VMM_LOG(mask_uvmm, level_trace,"vmexit_guest_initialize start guest_id=#%d\r\n", guest_id);
    guest_vmexit_control = (GUEST_VMEXIT_CONTROL *) vmm_malloc(sizeof(GUEST_VMEXIT_CONTROL));
    // BEFORE_VMLAUNCH
    VMM_ASSERT(guest_vmexit_control);

    guest_vmexit_control->guest_id = guest_id;
    list_add(vmexit_global_state.guest_vmexit_controls, guest_vmexit_control->list);

    // install default handlers
    for (i = 0; i < Ia32VmxExitBasicReasonCount; ++i) {
        guest_vmexit_control->vmexit_handlers[i] = vmexit_handler_default;
    }

    //  commented out handlers installed by means of vmexit_install_handler
    //  guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonMsrRead] = vmexit_msr_read;
    //  guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonMsrWrite] = vmexit_msr_write;
    //  guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmcallInstruction] = vmexit_vmcall;
    //  guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi]= vmexit_software_interrupt_exception_nmi;
    //  guest_vmexit_control->vmexit_handlers[Ia32VmxExitNmiWindow]  = vmexit_nmi_window;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonCrAccess] = vmexit_cr_access;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonSipiEvent] = vmexit_sipi_event;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonInitEvent] = vmexit_init_event;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonTripleFault] = vmexit_triple_fault;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonHltInstruction] = vmexit_halt_instruction;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonTaskSwitch] = vmexit_task_switch;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmclearInstruction] = vmexit_vmclear_instruction; 
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmlaunchInstruction] = vmexit_vmlaunch_instruction;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmptrldInstruction] = vmexit_vmptrld_instruction;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmptrstInstruction] = vmexit_vmptrst_instruction;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmreadInstruction] = vmexit_vmread_instruction; 
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmresumeInstruction] = vmexit_vmresume_instruction;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmwriteInstruction] = vmexit_vmwrite_instruction; 
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmxoffInstruction] = vmexit_vmxoff_instruction;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonVmxonInstruction] = vmexit_vmxon_instruction; 
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonInvdInstruction] = vmexit_invd;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonInvlpgInstruction] = vmexit_invlpg;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonEptViolation] = vmexit_ept_violation;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonEptMisconfiguration] = vmexit_ept_misconfiguration;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonInveptInstruction] = vmexit_undefined_opcode;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonFailedVmEnterMsrLoading] = msr_failed_vmenter_loading_handler;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonInvvpidInstruction] = vmexit_undefined_opcode;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonGdtrIdtrAccess] = vmexit_gdtr_idtr_access;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonLdtrTrAccess] = vmexit_ldtr_tr_access;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonDrAccess] = vmexit_dr_access;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonMonitorTrapFlag] = vmexit_mtf;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonFailureDueMachineCheck] = vmexit_vmentry_failure_due2_machine_check;
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonXsetbvInstruction] = vmexit_xsetbv;
#ifdef FAST_VIEW_SWITCH
    guest_vmexit_control->vmexit_handlers[Ia32VmxExitBasicReasonInvalidVmfunc] = vmexit_invalid_vmfunc;
#endif

    // install IO VMEXITs
    io_vmexit_guest_initialize(guest_id);

#if 0 /* this is commented out for now to work with serial card from Startech
         or the guest OS boot up would be stuck */
    // Handle debug port virtualization
    if ((vmm_debug_port_get_virt_mode() == VMM_DEBUG_PORT_VIRT_HIDE) &&
        (vmm_debug_port_get_io_base() != 0))
    {
        // Block the debug port I/O range

        io_vmexit_block_port(guest_id,
                             vmm_debug_port_get_io_base(),
                             vmm_debug_port_get_io_end());
    }
#endif

    // install NMI and Exceptions VMEXITs
    vmexit_nmi_exception_handlers_install(guest_id);

    // init CPUID instruction vmexit handlers
    vmexit_cpuid_guest_intialize(guest_id);

    // install VMCALL services
    vmcall_guest_intialize(guest_id);
    VMM_LOG(mask_uvmm, level_trace,"vmexit_guest_initialize end guest_id=#%d\r\n", guest_id);
}

static void vmexit_bottom_up_all_vmms_skip_instruction(GUEST_CPU_HANDLE gcpu,
                                                UINT32 reason) {
    GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
    GUEST_ID        guest_id = guest_get_id(guest);
    GUEST_VMEXIT_CONTROL *guest_vmexit_control = NULL;
    VMCS_HIERARCHY* vmcs_hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* level0_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_LEVEL_0);
    VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_MERGED);
    GUEST_LEVEL_ENUM guest_level = gcpu_get_guest_level(gcpu);
    BOOLEAN skip_instruction = TRUE;

    guest_vmexit_control = vmexit_find_guest_vmexit_control(guest_id);
    VMM_ASSERT(guest_vmexit_control);

    VMM_ASSERT(reason < Ia32VmxExitBasicReasonCount);

    VMM_ASSERT(level0_vmcs != NULL);
    hw_interlocked_increment((INT32*)&(guest_vmexit_control->vmexit_counter[reason]));

    if ((guest_level == GUEST_LEVEL_1_SIMPLE) || (guest_level == GUEST_LEVEL_1_VMM) ||
        (vmexit_analysis_was_control_requested(gcpu, merged_vmcs, level0_vmcs, (IA32_VMX_EXIT_BASIC_REASON)reason))) {
#ifdef DEBUG
        // Check that in GUEST_LEVEL_1_SIMPLE and GUEST_LEVEL_1_VMM modes
        // the vmexit was requested in the level-0 controls
        if (guest_level == GUEST_LEVEL_1_VMM) {
            VMM_ASSERT(vmexit_analysis_was_control_requested(gcpu, merged_vmcs, level0_vmcs, (IA32_VMX_EXIT_BASIC_REASON)reason));
        }
#endif
        // return value is not important
        guest_vmexit_control->vmexit_handlers[reason](gcpu);
    }

    if (guest_level == GUEST_LEVEL_2) {
        VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_LEVEL_1);

        VMM_ASSERT(level1_vmcs != NULL);
        // Check if layer2 can accept the event, if not inject event to (level-2) guest
        if (vmexit_analysis_was_control_requested(gcpu, merged_vmcs, level1_vmcs, (IA32_VMX_EXIT_BASIC_REASON)reason)) {
            gcpu_set_next_guest_level(gcpu, GUEST_LEVEL_1_VMM);

            // instruction will be skipped by level-1
            skip_instruction = FALSE;
        }
    }

    if (skip_instruction) {
        gcpu_skip_guest_instruction(gcpu);
    }

}

void vmexit_bottom_up_common_handler(GUEST_CPU_HANDLE gcpu, UINT32 reason) {
    GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
    GUEST_ID        guest_id = guest_get_id(guest);
    GUEST_VMEXIT_CONTROL *guest_vmexit_control = NULL;
    VMEXIT_HANDLING_STATUS vmexit_handling_status = VMEXIT_NOT_HANDLED;
    VMCS_HIERARCHY* vmcs_hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* level0_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_LEVEL_0);
    VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_MERGED);
    GUEST_LEVEL_ENUM guest_level = gcpu_get_guest_level(gcpu);

    guest_vmexit_control = vmexit_find_guest_vmexit_control(guest_id);
    VMM_ASSERT(guest_vmexit_control);

    VMM_ASSERT(reason < Ia32VmxExitBasicReasonCount);

    VMM_ASSERT(level0_vmcs != NULL);
    hw_interlocked_increment((INT32*)&(guest_vmexit_control->vmexit_counter[reason]));

    if ((guest_level == GUEST_LEVEL_1_SIMPLE) ||    // non -layered vmexit
        (guest_level == GUEST_LEVEL_1_VMM)    ||    // or vmexit from level 1
#ifdef ENABLE_EMULATOR
        (FALSE == gcpu_is_mode_native(gcpu))  ||    // or emulated
#endif
        (vmexit_analysis_was_control_requested(gcpu, merged_vmcs, level0_vmcs, (IA32_VMX_EXIT_BASIC_REASON)reason))) {
        IA32_VMX_EXIT_REASON exit_reason;

#ifdef DEBUG
        // Check that in GUEST_LEVEL_1_SIMPLE and GUEST_LEVEL_1_VMM modes
        // the vmexit was requested in the level-0 controls
        if (guest_level == GUEST_LEVEL_1_VMM) {
            VMM_ASSERT(vmexit_analysis_was_control_requested(gcpu, merged_vmcs, level0_vmcs, reason));
        }
#endif

        vmexit_handling_status = guest_vmexit_control->vmexit_handlers[reason](gcpu);

        // reason can be changed after the attempt to handle
        exit_reason.Uint32 = (UINT32)vmcs_read(merged_vmcs, VMCS_EXIT_INFO_REASON);
        reason = exit_reason.Bits.BasicReason;
    }

    if ((vmexit_handling_status != VMEXIT_HANDLED) &&
        (guest_level == GUEST_LEVEL_2)) {
        VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_LEVEL_1);

        VMM_ASSERT(level1_vmcs != NULL);

        // Check if layer2 can accept the event, if not inject event to (level-2) guest
        if (vmexit_analysis_was_control_requested(gcpu, merged_vmcs, level1_vmcs, (IA32_VMX_EXIT_BASIC_REASON)reason)) {
            gcpu_set_next_guest_level(gcpu, GUEST_LEVEL_1_VMM);
            vmexit_handling_status = VMEXIT_HANDLED;
        }
    }

    if (vmexit_handling_status != VMEXIT_HANDLED) {
        // Currently it can happen only for exception
        if (reason != Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi) {
            VMM_LOG(mask_uvmm, level_trace,"%s: reason = %d\n", __FUNCTION__, reason);
        }
        VMM_ASSERT(reason == Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi);
        gcpu_vmexit_exception_reflect(gcpu);
    }
    else {
        // TODO: Here must be call to resolve gcpu_vmexit_exception_resolve
        /*if (reason == Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi) {
            gcpu_vmexit_exception_resolve(gcpu);
        }*/
    }
}

void vmexit_top_down_common_handler(GUEST_CPU_HANDLE gcpu, UINT32 reason) {
    GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
    GUEST_ID        guest_id = guest_get_id(guest);
    GUEST_VMEXIT_CONTROL *guest_vmexit_control = NULL;
    VMEXIT_HANDLING_STATUS vmexit_handling_status = VMEXIT_NOT_HANDLED;
    VMCS_HIERARCHY* vmcs_hierarchy = gcpu_get_vmcs_hierarchy(gcpu);
    VMCS_OBJECT* merged_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_MERGED);
    GUEST_LEVEL_ENUM guest_level = gcpu_get_guest_level(gcpu);

    guest_vmexit_control = vmexit_find_guest_vmexit_control(guest_id);
    VMM_ASSERT(guest_vmexit_control);

    VMM_ASSERT(reason < Ia32VmxExitBasicReasonCount);
    hw_interlocked_increment((INT32*)&(guest_vmexit_control->vmexit_counter[reason]));

    if (guest_level == GUEST_LEVEL_2 && gcpu_is_native_execution(gcpu)) {
        VMCS_OBJECT* level1_vmcs = vmcs_hierarchy_get_vmcs(vmcs_hierarchy, VMCS_LEVEL_1);

        VMM_ASSERT(level1_vmcs != NULL);
        // Check whether it can be handled in Level-1
        if (vmexit_analysis_was_control_requested(gcpu, merged_vmcs, level1_vmcs, (IA32_VMX_EXIT_BASIC_REASON)reason)) {
            gcpu_set_next_guest_level(gcpu, GUEST_LEVEL_1_VMM);
            vmexit_handling_status = VMEXIT_HANDLED;
        }
    }
    if (vmexit_handling_status != VMEXIT_HANDLED) {
        // Handle in Level-0
        vmexit_handling_status = guest_vmexit_control->vmexit_handlers[reason](gcpu);
    }
    if (vmexit_handling_status != VMEXIT_HANDLED) {
        if (vmexit_handling_status == VMEXIT_HANDLED_RESUME_LEVEL2) {
            gcpu_set_next_guest_level(gcpu, GUEST_LEVEL_2);
        }
        else {
            VMM_LOG(mask_uvmm, level_trace,"%s: Top-Down VMExit (%d) which wasn't handled", __FUNCTION__, reason);
            VMM_DEADLOOP(); // Should not get here
        }
    }
}

void vmexit_handler_invoke( GUEST_CPU_HANDLE gcpu, UINT32 reason)
{
    GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
    GUEST_ID        guest_id = guest_get_id(guest);
    GUEST_VMEXIT_CONTROL *guest_vmexit_control = NULL;

    guest_vmexit_control = vmexit_find_guest_vmexit_control(guest_id);
    VMM_ASSERT(guest_vmexit_control);
#ifdef API_NOT_USED
    tmsl_vmexit(gcpu);
#endif
    if (reason < Ia32VmxExitBasicReasonCount) {
        // Call top-down or bottom-up common handler;
        vmexit_classification_func[reason](gcpu, reason);
    }
    else {
        VMM_LOG(mask_uvmm, level_trace,"Warning: Unknown VMEXIT reason(%d)\n", reason);
        vmexit_handler_default(gcpu);
    }
}


// FUNCTION : vmentry_failure_function
// PURPOSE  : Called upon VMENTER failure
// ARGUMENTS: ADDRESS flag - value of processor flags register
// RETURNS  : void
void vmentry_failure_function(ADDRESS flags)
{
    GUEST_CPU_HANDLE gcpu = scheduler_current_gcpu();
    VMCS_OBJECT*     vmcs = gcpu_get_vmcs(gcpu);
    const char*      err = NULL;
    VMCS_INSTRUCTION_ERROR code;
    EM64T_RFLAGS     rflags;
#ifndef DEBUG
    IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY    interruptibility;
#endif

    rflags.Uint64 = flags;
    code = vmcs_last_instruction_error_code( vmcs, &err );

    VMM_LOG(mask_uvmm, level_error,"CPU%d: VMENTRY Failed on ", hw_cpu_id());
    PRINT_GCPU_IDENTITY(gcpu);
    VMM_LOG(mask_uvmm, level_error," FLAGS=0x%X (ZF=%d CF=%d) ErrorCode=0x%X Desc=%s\n",
            flags, rflags.Bits.ZF, rflags.Bits.CF, code, err);
#ifdef CLI_INCLUDE
    vmcs_print_all(vmcs);
#endif

#ifdef DEBUG
    VMM_DEADLOOP();
#else
    vmm_deadloop_internal(VMEXIT_C, __LINE__, gcpu);
    vmcs_restore_initial(gcpu);

    // clear interrupt flag
    rflags.Uint64 = gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);
    rflags.Bits.IFL = 0;
    gcpu_set_gp_reg(gcpu, IA32_REG_RFLAGS, rflags.Uint64);

    interruptibility.Uint32 = gcpu_get_interruptibility_state(gcpu);
    interruptibility.Bits.BlockNextInstruction = 0;
    gcpu_set_interruptibility_state(gcpu, interruptibility.Uint32);

    gcpu_inject_gp0(gcpu);
    gcpu_resume(gcpu);
#endif
}

extern void /* __attribute((_stdcall)) */ vmm_write_xcr(UINT64,UINT64,UINT64);
extern void /* __attribute((_stdcall)) */ vmm_read_xcr(UINT32*,UINT32*,UINT32);
// FUNCTION : vmexit_xsetbv()
// PURPOSE  : Handler for xsetbv instruction
// ARGUMENTS: gcpu
VMEXIT_HANDLING_STATUS vmexit_xsetbv(GUEST_CPU_HANDLE gcpu)
{
    UINT32 XCR0_Mask_low,XCR0_Mask_high;
    CPUID_PARAMS    cpuid_params;

    cpuid_params.m_rax = 0xd;
    cpuid_params.m_rcx = 0;

    hw_cpuid(&cpuid_params);

    vmm_read_xcr(&XCR0_Mask_low,&XCR0_Mask_high,0);
    /*
    let's check three things first before executing the instruction to make 
    sure everything is correct, otherwise, inject GP0 to guest instead of failing 
    in host since guest is responsible for the failure if any
    1. Guest ECX must have a value of zero since only one XCR which is XCR0 is 
        supported by HW currently 
    2. The reserved bits in XCR0 are not being changed
    3. Bit 0 of XCR0 is not being changed to zero since it must be one.
    4. No attempt to write 0 to bit 1 and 1 to bit 2, i.e. XCR0[2:1]=10.
    */
    if (((gcpu->save_area.gp.reg[IA32_REG_RCX] << 32) > 0) ||
        (((~((UINT32)cpuid_params.m_rax)) & XCR0_Mask_low ) !=  (UINT32)(~cpuid_params.m_rax & 
            gcpu->save_area.gp.reg[IA32_REG_RAX])) ||
        (((~((UINT32)cpuid_params.m_rdx)) & XCR0_Mask_high ) !=  (UINT32)(~cpuid_params.m_rdx & 
            gcpu->save_area.gp.reg[IA32_REG_RDX])) ||
        ((gcpu->save_area.gp.reg[IA32_REG_RAX] & 1) == 0) ||
        ((gcpu->save_area.gp.reg[IA32_REG_RAX] & 0x6) == 0x4)) {
        gcpu_inject_gp0(gcpu);
        return VMEXIT_HANDLED;
    }

    vmm_write_xcr(gcpu->save_area.gp.reg[IA32_REG_RCX],gcpu->save_area.gp.reg[IA32_REG_RDX],
        gcpu->save_area.gp.reg[IA32_REG_RAX]);
    gcpu_skip_guest_instruction(gcpu);
    return VMEXIT_HANDLED;

}

// FUNCTION : vmexit_halt_instruction()
// PURPOSE  : Handler for halt instruction
// ARGUMENTS: gcpu
// RETURNS  : vmexit handling status
VMEXIT_HANDLING_STATUS vmexit_halt_instruction(GUEST_CPU_HANDLE gcpu)
{
    if (!report_uvmm_event(UVMM_EVENT_HALT_INSTRUCTION, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), NULL)) {
        VMM_LOG(mask_uvmm, level_trace, "Report HALT Instruction VMExit failed.\n");
        VMM_DEADLOOP();
    }
    return VMEXIT_HANDLED;
}

// FUNCTION : vmexit_vmentry_failure_due2_machine_check()
// PURPOSE  : Handler for vmexit that happens in vmentry due to machine check
// ARGUMENTS: gcpu
// RETURNS  : VMEXIT_HANDLING_STATUS
#pragma warning(push)
#pragma warning(disable : 4100)  // Supress warnings about unreferenced formal parameter
VMEXIT_HANDLING_STATUS vmexit_vmentry_failure_due2_machine_check(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_error,"CPU%d: VMENTRY failed due to machine check\r\n", hw_cpu_id());
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    // IA SDM 15.10.4.1 :Reset system for uncorrected machine check errors
    hw_reset_platform();
#endif
    //never reach here
    return VMEXIT_HANDLED;
}
#pragma warning(pop)


#ifdef FAST_VIEW_SWITCH
// FUNCTION : vmexit_invalid_vmfunc()
// PURPOSE  : Handler for invalid vmfunc instruction
// ARGUMENTS: gcpu
// RETURNS  : VMEXIT_HANDLING_STATUS
VMEXIT_HANDLING_STATUS vmexit_invalid_vmfunc(GUEST_CPU_HANDLE gcpu)
{
    REPORT_FAST_VIEW_SWITCH_DATA fast_view_switch_data;
    UINT64 r_ecx;

    r_ecx = gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);
    /* Invalid vmfunc report to handler */
    VMM_LOG(mask_anonymous, level_trace,
        "%s: view id=%d.Invalid vmfunc vmexit.\n",
            __FUNCTION__,r_ecx);
    fast_view_switch_data.reg = r_ecx;
    report_uvmm_event(UVMM_EVENT_INVALID_FAST_VIEW_SWITCH, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&fast_view_switch_data);
    return VMEXIT_HANDLED;
}
#endif

// FUNCTION : vmexit_handler_default()
// PURPOSE  : Handler for unimplemented/not supported VMEXITs
// ARGUMENTS: IN VMEXIT_EXECUTION_CONTEXT *vmexit - contains guest handles
VMEXIT_HANDLING_STATUS vmexit_handler_default(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT          *vmcs = gcpu_get_vmcs(gcpu);
    IA32_VMX_EXIT_REASON  reason;
#if defined DEBUG || defined ENABLE_RELEASE_VMM_LOG
    const VIRTUAL_CPU_ID *vcpuid = guest_vcpu(gcpu);
#else
    EM64T_RFLAGS rflags;
    IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY    interruptibility;
#endif

    reason.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_REASON);
#if defined DEBUG || defined ENABLE_RELEASE_VMM_LOG
    VMM_ASSERT(vcpuid);
    VMM_LOG(mask_uvmm, level_error,"NOT supported VMEXIT(%d) occurred on CPU(%d) Guest(%d) GuestCPU(%d)\n",
                reason.Bits.BasicReason, hw_cpu_id(), vcpuid->guest_id, vcpuid->guest_cpu_id );
#endif

    VMM_DEBUG_CODE(
        if( reason.Bits.BasicReason == Ia32VmxExitBasicReasonFailedVmEnterGuestState || 
            reason.Bits.BasicReason == Ia32VmxExitBasicReasonFailedVmEnterMsrLoading ) {
            vmenter_failure_check_guest_state();
        }
    )
    
#if defined DEBUG || defined ENABLE_RELEASE_VMM_LOG
    VMM_DEADLOOP(); // VTDBG
#else
    if( reason.Bits.BasicReason == Ia32VmxExitBasicReasonFailedVmEnterGuestState || 
        reason.Bits.BasicReason == Ia32VmxExitBasicReasonFailedVmEnterMsrLoading ) {
        vmm_deadloop_internal(VMEXIT_C, __LINE__, gcpu);
        vmcs_restore_initial(gcpu);

        // clear interrupt flag
        rflags.Uint64 = gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);
        rflags.Bits.IFL = 0;
        gcpu_set_gp_reg(gcpu, IA32_REG_RFLAGS, rflags.Uint64);

        interruptibility.Uint32 = gcpu_get_interruptibility_state(gcpu);
        interruptibility.Bits.BlockNextInstruction = 0;
        gcpu_set_interruptibility_state(gcpu, interruptibility.Uint32);

        gcpu_inject_gp0(gcpu);
        gcpu_resume(gcpu);
    } else {
        VMM_DEADLOOP();
    }
#endif
    return VMEXIT_NOT_HANDLED;
}

// FUNCTION : vmexit_install_handler
// PURPOSE  : Install specific VMEXIT handler
// ARGUMENTS: GUEST_ID        guest_id
//          : VMEXIT_HANDLER  handler
//          : UINT32          reason
// RETURNS  : VMM_STATUS
VMM_STATUS vmexit_install_handler(
    GUEST_ID        guest_id,
    VMEXIT_HANDLER  handler,
    UINT32          reason)
{
    VMM_STATUS status = VMM_OK;
    GUEST_VMEXIT_CONTROL *guest_vmexit_control = NULL;

    guest_vmexit_control = vmexit_find_guest_vmexit_control(guest_id);
    // BEFORE_VMLAUNCH
    VMM_ASSERT(guest_vmexit_control);

    if (reason < Ia32VmxExitBasicReasonCount) {
        guest_vmexit_control->vmexit_handlers[reason] = handler;
    }
    else {
        VMM_LOG(mask_uvmm, level_error,
                "CPU%d: Error: VMEXIT Reason(%d) exceeds supported limit\n",
                hw_cpu_id(), reason);
        status = VMM_ERROR;
        // BEFORE_VMLAUNCH. It could happen due to coding error.
        VMM_ASSERT(reason < Ia32VmxExitBasicReasonCount);
    }

    return status;
}

extern UINT32 /* __attribute((stdcall)) */ vmexit_reason(void);
UINT64 /* __attribute((stdcall)) */ gcpu_read_guestrip(void);


// FUNCTION : vmexit_common_handler()
// PURPOSE  : Called by vmexit_func() upon each VMEXIT
void vmexit_common_handler(void)
{
    GUEST_CPU_HANDLE        gcpu;
    GUEST_CPU_HANDLE        next_gcpu;
    VMCS_OBJECT             *vmcs;
    IA32_VMX_EXIT_REASON    reason;
    REPORT_INITIAL_VMEXIT_CHECK_DATA initial_vmexit_check_data;

    gcpu = scheduler_current_gcpu();
    VMM_ASSERT(gcpu);

    // Disable the VMCS Software Shadow/Cache
    // This is required since GCPU and VMCS cache has not yet been flushed and might have stale values from previous VMExit
    vmcs_sw_shadow_disable[hw_cpu_id()] = TRUE;

    if( gcpu->trigger_log_event && (vmexit_reason() == Ia32VmxExitBasicReasonMonitorTrapFlag) ) {
        REPORT_VMM_LOG_EVENT_DATA vmm_log_event_data;
                
        vmm_log_event_data.vector = gcpu->trigger_log_event - 1;
        gcpu->trigger_log_event = 0;
        report_uvmm_event(UVMM_EVENT_LOG, (VMM_IDENTIFICATION_DATA)gcpu, 
                    (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&vmm_log_event_data);
    }

    // OPTIMIZATION: Check if current VMExit is MTF VMExit after MTF was turned on for EPT violation
    initial_vmexit_check_data.current_cpu_rip = gcpu_read_guestrip();
    initial_vmexit_check_data.vmexit_reason = vmexit_reason();
    if (report_uvmm_event(UVMM_EVENT_INITIAL_VMEXIT_CHECK, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&initial_vmexit_check_data)) {
#ifdef FAST_VIEW_SWITCH
        if (fvs_is_eptp_switching_supported()) {
            fvs_save_resumed_eptp(gcpu);
        }
#endif
        nmi_window_update_before_vmresume(gcpu_get_vmcs(gcpu));
        vmentry_func(FALSE);
    }

    // OPTIMIZATION: This has been placed after the MTF VMExit check since number of MTF VMExits are more compared to Fast View Switch
#ifdef FAST_VIEW_SWITCH
    if (fvs_is_fvs_enabled(gcpu)) {
        fvs_vmexit_handler(gcpu);
    }
#endif

    VMM_ASSERT(hw_cpu_id() < VMM_MAX_CPU_SUPPORTED);

    // OPTIMIZATION: For EPT violation, do not enable the software VMCS cache
    if ((vmexit_check_ept_violation() & 7) == 0)
        vmcs_sw_shadow_disable[hw_cpu_id()] = FALSE;

    // clear guest cpu cache data. in fact it clears all VMCS caches too.
    gcpu_vmexit_start(gcpu);
    //host_cpu_restore_dr7(hw_cpu_id());
    host_cpu_store_vmexit_gcpu(hw_cpu_id(), gcpu);
    if (CLI_active()) {
        // Check keystroke
        vmexit_check_keystroke(gcpu);
    }

#ifdef FAST_VIEW_SWITCH
    if (fvs_is_fvs_enabled(gcpu)) {
        if (fvs_is_eptp_switching_supported())
                report_uvmm_event(UVMM_EVENT_UPDATE_ACTIVE_VIEW, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), NULL);
    }
#endif
    // read VMEXIT reason
    vmcs = gcpu_get_vmcs(gcpu);
    reason.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_REASON);

    // call add-on VMEXIT if installed
    // if add-on is not interesting in this VMEXIT, it retursn NULL
    // if legacy_scheduling_enabled == FALSE, scheduling must be done in gcpu_resume()
    next_gcpu = gcpu_call_vmexit_function(gcpu, reason.Bits.BasicReason);

    if (NULL == next_gcpu) {
        // call reason-specific VMEXIT handler
        vmexit_handler_invoke(gcpu, reason.Bits.BasicReason);
        if (legacy_scheduling_enabled)
            next_gcpu = scheduler_select_next_gcpu();   // select guest for execution
        else
            next_gcpu = gcpu;   // in layered vmresume
    }
    else {
        scheduler_schedule_gcpu(next_gcpu);
    }

    VMM_ASSERT(next_gcpu);

    // finally process NMI injection
    NMI_DO_PROCESSING();
    gcpu_resume(next_gcpu);
}

static GUEST_VMEXIT_CONTROL* vmexit_find_guest_vmexit_control(GUEST_ID guest_id)
{
    LIST_ELEMENT *iter = NULL;
    GUEST_VMEXIT_CONTROL *guest_vmexit_control = NULL;

    LIST_FOR_EACH(vmexit_global_state.guest_vmexit_controls, iter) {
        guest_vmexit_control = LIST_ENTRY(iter, GUEST_VMEXIT_CONTROL, list);
        if(guest_vmexit_control->guest_id == guest_id) {
            return guest_vmexit_control;
        }
    }

    return NULL;
}


#ifdef INCLUDE_UNUSED_CODE

// This function is tuned for XuPro only!!!!!
void vmexit_direct_call_handler(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT             *vmcs  = gcpu_get_vmcs(gcpu);
    IA32_VMX_EXIT_REASON    reason;
    UINT32                  vmexit_id;

    reason.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_REASON);
    vmexit_id = reason.Bits.BasicReason;

    if (vmexit_id < Ia32VmxExitBasicReasonCount) {
        GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
        GUEST_ID        guest_id = guest_get_id(guest);
        GUEST_VMEXIT_CONTROL *guest_vmexit_control = vmexit_find_guest_vmexit_control(guest_id);

        VMM_ASSERT(guest_vmexit_control);

        // Call top-down common handler
        if (vmexit_classification_func[vmexit_id] == vmexit_top_down_common_handler) {
            guest_vmexit_control->vmexit_handlers[vmexit_id](gcpu);
        }
        else {
            // XuModel didn't handle bottom up vmexit
            VMM_ASSERT(Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi == vmexit_id);
            gcpu_vmexit_exception_reflect(gcpu);
        }
    }
}
#endif


#define vmexit_hardware_interrupt           vmexit_handler_default
#define vmexit_pending_interrupt            vmexit_handler_default
//#define vmexit_halt_instruction             vmexit_handler_default
#define vmexit_invalid_instruction          vmexit_handler_default
#define vmexit_dr_access                    vmexit_handler_default
#define vmexit_io_instruction               vmexit_handler_default
#define vmexit_failed_vmenter_guest_state   vmexit_handler_default
#define vmexit_failed_vmenter_msr_loading   vmexit_handler_default
#define vmexit_failed_vmexit                vmexit_handler_default
#define vmexit_mwait_instruction            vmexit_handler_default
#define vmexit_monitor                      vmexit_handler_default
#define vmexit_pause                        vmexit_handler_default
#define vmexit_machine_check                vmexit_handler_default
#define vmexit_tpr_below_threshold          vmexit_handler_default
#define vmexit_apic_access                  vmexit_handler_default

#define CPUID_XSAVE_SUPPORTED_BIT 26

BOOLEAN is_cr4_osxsave_supported(void)
{
    CPUID_PARAMS cpuid_params;
    cpuid_params.m_rax = 1;
    hw_cpuid(&cpuid_params);
    return (BOOLEAN) BIT_GET64( cpuid_params.m_rcx, CPUID_XSAVE_SUPPORTED_BIT );
}
