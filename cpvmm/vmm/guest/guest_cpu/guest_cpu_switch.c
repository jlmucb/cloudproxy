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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_CPU_SWITCH_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_CPU_SWITCH_C, __condition)
#include "guest_cpu_internal.h"
#include "vmx_ctrl_msrs.h"
#include "gpm_api.h"
#include "guest.h"
#include "vmx_asm.h"
#include "ipc.h"
#include "vmm_dbg.h"
#include "vmm_events_data.h"
#include "vmcs_merge_split.h"
#include "vmcs_api.h"
#include "vmexit_cr_access.h"
#include "pat_manager.h"
#include "vmx_nmi.h"
#include "host_cpu.h"
#include "vmdb.h"
#include "vmcs_init.h"
#include "unrestricted_guest.h"
#include "fvs.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

extern BOOLEAN is_ib_registered(void);

#ifdef VMCALL_NOT_ALLOWED_FROM_RING_1_TO_3
    extern BOOLEAN gcpu_inject_invalid_opcode_exception(GUEST_CPU_HANDLE gcpu);
#endif

// do not report warning on unused params
#pragma warning( disable: 4100 )


// Decide on important events
typedef enum _GCPU_RESUME_EMULATOR_ACTION {
    GCPU_RESUME_EMULATOR_ACTION_DO_NOTHING = 0,
    GCPU_RESUME_EMULATOR_ACTION_START_EMULATOR
} GCPU_RESUME_EMULATOR_ACTION;

typedef enum _GCPU_RESUME_FLAT_PT_ACTION {
    GCPU_RESUME_FLAT_PT_ACTION_DO_NOTHING = 0,
    GCPU_RESUME_FLAT_PT_ACTION_INSTALL_32_BIT_PT,
    GCPU_RESUME_FLAT_PT_ACTION_INSTALL_64_BIT_PT,
    GCPU_RESUME_FLAT_PT_ACTION_REMOVE
} GCPU_RESUME_FLAT_PT_ACTION;

typedef struct _GCPU_RESUME_ACTION {
    GCPU_RESUME_EMULATOR_ACTION emulator;
    GCPU_RESUME_FLAT_PT_ACTION  flat_pt;
} GCPU_RESUME_ACTION;

typedef enum  { // bit values
    VMCS_HW_ENFORCE_EMULATOR = 1,
    VMCS_HW_ENFORCE_FLAT_PT  = 2,
    VMCS_HW_ENFORCE_CACHE_DISABLED = 4,
} VMCS_HW_ENFORCEMENT_ID;

extern BOOLEAN vmcs_sw_shadow_disable[];
static VMM_STATUS gcpu_set_hw_enforcement(GUEST_CPU_HANDLE gcpu, VMCS_HW_ENFORCEMENT_ID enforcement);
static VMM_STATUS gcpu_remove_hw_enforcement(GUEST_CPU_HANDLE gcpu, VMCS_HW_ENFORCEMENT_ID enforcement);
static void       gcpu_apply_hw_enforcements(GUEST_CPU_HANDLE gcpu);
#define gcpu_hw_enforcement_is_active( gcpu, enforcement) (((gcpu)->hw_enforcements & enforcement) != 0)


static void gcpu_cache_disabled_support( const GUEST_CPU_HANDLE  gcpu, BOOLEAN CD_value_requested)
{
    if (1 == CD_value_requested) { // cache disabled - WSM does not support this!
        if (!gcpu_hw_enforcement_is_active(gcpu, VMCS_HW_ENFORCE_CACHE_DISABLED)) {
            VMM_LOG(mask_anonymous, level_trace,
                            "Guest %d:%d trying to set CD = 1\n",
                            guest_vcpu(gcpu)->guest_id,
                            guest_vcpu(gcpu)->guest_cpu_id);
            gcpu_set_hw_enforcement(gcpu, VMCS_HW_ENFORCE_CACHE_DISABLED);
        }
    }
    else {
        if (gcpu_hw_enforcement_is_active(gcpu, VMCS_HW_ENFORCE_CACHE_DISABLED)) {
            VMM_LOG(mask_anonymous, level_trace, "Guest %d:%d removing CD = 0 enforcement\n",
                            guest_vcpu(gcpu)->guest_id, guest_vcpu(gcpu)->guest_cpu_id);
            gcpu_remove_hw_enforcement(gcpu, VMCS_HW_ENFORCE_CACHE_DISABLED);
        }
    }
}

// Receives cr0 and efer guest-visible values
// returns TRUE is something should be done + description of what should be
// done
static BOOLEAN gcpu_decide_on_resume_actions(const GUEST_CPU_HANDLE  gcpu, UINT64 cr0_value,
                                       UINT64 efer_value, GCPU_RESUME_ACTION* action)
{
    EM64T_CR0          cr0;
    IA32_EFER_S        efer;
    BOOLEAN            do_something = FALSE;
    BOOLEAN            PE, PG, CD, LME;

    VMM_ASSERT( gcpu );
    VMM_ASSERT( action );
    if (IS_MODE_EMULATOR(gcpu)) {
        // if we under emulator, emulator will take care for everything
        return FALSE;
    }
    action->emulator = GCPU_RESUME_EMULATOR_ACTION_DO_NOTHING;
    action->flat_pt  = GCPU_RESUME_FLAT_PT_ACTION_DO_NOTHING;
    // now we in NATIVE mode only
    if (IS_STATE_INACTIVE(GET_CACHED_ACTIVITY_STATE(gcpu))) {
        // if we are in the wait-for-SIPI mode - do nothing
        return FALSE;
    }
    cr0.Uint64 = cr0_value;
    efer.Uint64 = efer_value;
    PE  = (cr0.Bits.PE == 1);
    PG  = (cr0.Bits.PG == 1);
    CD = (cr0.Bits.CD == 1);
    LME = (efer.Bits.LME == 1);
    if (CD && global_policy_is_cache_dis_virtualized()) {
        EM64T_CR0  real_cr0;
        VMM_DEBUG_CODE(
        const VIRTUAL_CPU_ID  *vcpu = guest_vcpu(gcpu);
        VMM_LOG(mask_anonymous, level_trace,"Guest %d:%d trying to set CD = 1\n", (int) vcpu->guest_id, (int) vcpu->guest_cpu_id);
        );
        // CD = 1 is not allowed.
        real_cr0.Uint64 = gcpu_get_control_reg(gcpu, IA32_CTRL_CR0);
        real_cr0.Bits.CD = 0;
        gcpu_set_control_reg(gcpu, IA32_CTRL_CR0, real_cr0.Uint64);
    }
    // Run emulator explicitly
    if( GET_EXPLICIT_EMULATOR_REQUEST_FLAG(gcpu) ) {
        if (IS_MODE_UNRESTRICTED_GUEST(gcpu) ) {
                        gcpu_clr_unrestricted_guest(gcpu);
                }
        // if we start emulator, emulator will take care for everything
        action->emulator = GCPU_RESUME_EMULATOR_ACTION_START_EMULATOR;
        return TRUE;
    }
    // We have UG on all the time, except during Task Switch
    if (is_unrestricted_guest_supported()) {
        if (!IS_MODE_UNRESTRICTED_GUEST(gcpu)) {
            unrestricted_guest_enable(gcpu);
        }
    }
    if (PE == FALSE) {
        // if we start emulator, emulator will take care for everything
        if (!is_unrestricted_guest_supported()) {
            action->emulator = GCPU_RESUME_EMULATOR_ACTION_START_EMULATOR;
            do_something = TRUE;
        }
        return do_something;
    }
    // now PE is 1
    if (!is_unrestricted_guest_supported()) {
        if (PG == FALSE) {
            // paging is off -> we need flat page tables.
            if ((LME == FALSE) && (!GET_FLAT_PAGES_TABLES_32_FLAG(gcpu))) {
                do_something = TRUE;
                action->flat_pt = GCPU_RESUME_FLAT_PT_ACTION_INSTALL_32_BIT_PT;
            }
            // special case - Paging is OFF but Long Mode Enable (LME) is ON
            // -> switch from 32bit to 64 bit page tables even is 32bit exist
            if ((LME == TRUE) && (!GET_FLAT_PAGES_TABLES_64_FLAG(gcpu))) {
                do_something = TRUE;
                action->flat_pt = GCPU_RESUME_FLAT_PT_ACTION_INSTALL_64_BIT_PT;
            }
        }
        // Paging is ON
        else {
            if(IS_FLAT_PT_INSTALLED(gcpu)) {
                do_something = TRUE;
                action->flat_pt = GCPU_RESUME_FLAT_PT_ACTION_REMOVE;
            }
        }
    }
    if (global_policy_is_cache_dis_virtualized()) {
        gcpu_cache_disabled_support( gcpu, CD );
    }
    return do_something;
}


// Working with flat page tables

// called each time before resume if flat page tables are active
static void gcpu_enforce_flat_memory_setup( GUEST_CPU* gcpu )
{
    EM64T_CR4  cr4;
    EM64T_CR0  cr0;

    VMM_ASSERT( IS_FLAT_PT_INSTALLED( gcpu ) );
    VMM_ASSERT( gcpu->active_flat_pt_hpa );
    gcpu_set_control_reg( gcpu, IA32_CTRL_CR3, gcpu->active_flat_pt_hpa );
    cr4.Uint64 = gcpu_get_control_reg( gcpu, IA32_CTRL_CR4 );
    cr0.Uint64 = gcpu_get_control_reg( gcpu, IA32_CTRL_CR0 );

    // set required bits
    // note: CR4.PAE ... are listed in the GCPU_CR4_VMM_CONTROLLED_BITS
    //       so their real values will not be visible by guest
    if (! (cr4.Bits.PAE && cr4.Bits.PSE)) {
        cr4.Bits.PAE = 1;
        cr4.Bits.PSE = 1;
        gcpu_set_control_reg( gcpu, IA32_CTRL_CR4, cr4.Uint64 );
    }
    // note: CR0.PG ... are listed in the GCPU_CR0_VMM_CONTROLLED_BITS
    //       so their real values will not be visible by guest
    if (! cr0.Bits.PG) {
        cr0.Bits.PG = 1;
        gcpu_set_control_reg( gcpu, IA32_CTRL_CR0, cr0.Uint64 );
    }
}

static void gcpu_install_flat_memory( GUEST_CPU* gcpu, 
                            GCPU_RESUME_FLAT_PT_ACTION pt_type )
{
    BOOLEAN    gpm_flat_page_tables_ok = FALSE;

    if (IS_FLAT_PT_INSTALLED(gcpu)) {
        fpt_destroy_flat_page_tables( gcpu->active_flat_pt_handle );
    }
    else {
        // first time install - save current user CR3
        if (INVALID_CR3_SAVED_VALUE == gcpu->save_area.gp.reg[CR3_SAVE_AREA]) {
            gcpu->save_area.gp.reg[CR3_SAVE_AREA]= gcpu_get_control_reg(gcpu, IA32_CTRL_CR3);
        }
    }
    if (GCPU_RESUME_FLAT_PT_ACTION_INSTALL_32_BIT_PT == pt_type) {
        UINT32     cr3_hpa;

        gpm_flat_page_tables_ok =
             fpt_create_32_bit_flat_page_tables(gcpu,
                       &(gcpu->active_flat_pt_handle), &cr3_hpa );
        gcpu->active_flat_pt_hpa = cr3_hpa;

        CLR_FLAT_PAGES_TABLES_64_FLAG(gcpu);
        SET_FLAT_PAGES_TABLES_32_FLAG(gcpu);
    }
    else if (GCPU_RESUME_FLAT_PT_ACTION_INSTALL_64_BIT_PT == pt_type) {
        gpm_flat_page_tables_ok =
             fpt_create_64_bit_flat_page_tables(gcpu, &(gcpu->active_flat_pt_handle),
                              &(gcpu->active_flat_pt_hpa) );
        CLR_FLAT_PAGES_TABLES_32_FLAG(gcpu);
        SET_FLAT_PAGES_TABLES_64_FLAG(gcpu);
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,"Unknown Flat Page Tables type: %d\n", pt_type);
        VMM_DEADLOOP();
    }
    VMM_ASSERT( gpm_flat_page_tables_ok );
    gcpu_set_hw_enforcement(gcpu, VMCS_HW_ENFORCE_FLAT_PT);
}

static void gcpu_destroy_flat_memory( GUEST_CPU* gcpu )
{
    EM64T_CR4  user_cr4;
    RAISE_EVENT_RETVAL event_retval;

    if (IS_FLAT_PT_INSTALLED(gcpu)) {
        fpt_destroy_flat_page_tables( gcpu->active_flat_pt_handle );
        gcpu->active_flat_pt_hpa = 0;
    }
    // now we should restore the original PAE and PSE bits
    // actually we should ask uVMM-based application about this by
    // issuing appropriate event
    user_cr4.Uint64 = gcpu_get_guest_visible_control_reg( gcpu, IA32_CTRL_CR4 );
    gcpu_set_control_reg( gcpu, IA32_CTRL_CR4, user_cr4.Uint64 );
    event_retval = cr_raise_write_events( gcpu, IA32_CTRL_CR4, user_cr4.Uint64 );
    VMM_ASSERT(event_retval != EVENT_NOT_HANDLED);
    gcpu_set_control_reg( gcpu, IA32_CTRL_CR3, gcpu->save_area.gp.reg[CR3_SAVE_AREA] );
    event_retval = cr_raise_write_events( gcpu, IA32_CTRL_CR3, gcpu->save_area.gp.reg[CR3_SAVE_AREA] );
    VMM_ASSERT(event_retval != EVENT_NOT_HANDLED);
    gcpu_remove_hw_enforcement(gcpu, VMCS_HW_ENFORCE_FLAT_PT);
    CLR_FLAT_PAGES_TABLES_32_FLAG(gcpu);
    CLR_FLAT_PAGES_TABLES_64_FLAG(gcpu);
}

void gcpu_physical_memory_modified( GUEST_CPU_HANDLE gcpu )
{
    BOOLEAN    gpm_flat_page_tables_ok = FALSE;

    // this function is called after somebody modified guest physical memory
    // renew flat page tables if required
    if (! IS_FLAT_PT_INSTALLED(gcpu)) {
        return;
    }
    fpt_destroy_flat_page_tables( gcpu->active_flat_pt_handle );
    if (GET_FLAT_PAGES_TABLES_32_FLAG(gcpu)) {
        UINT32     cr3_hpa;

        gpm_flat_page_tables_ok =
             fpt_create_32_bit_flat_page_tables(gcpu, &(gcpu->active_flat_pt_handle),
                                                &cr3_hpa );
        gcpu->active_flat_pt_hpa = cr3_hpa;
    }
    else if (GET_FLAT_PAGES_TABLES_64_FLAG(gcpu)) {
        gpm_flat_page_tables_ok =
             fpt_create_64_bit_flat_page_tables(gcpu, &(gcpu->active_flat_pt_handle),
                                                &(gcpu->active_flat_pt_hpa) );
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,"Unknown Flat Page Tables type during FPT update after GPM modification\n");
        VMM_DEADLOOP();
    }
    VMM_ASSERT( gpm_flat_page_tables_ok );
}


// Perform pre-resume actions
static void gcpu_perform_resume_actions( GUEST_CPU* gcpu,
                                  const GCPU_RESUME_ACTION* action )
{
    VMM_ASSERT( gcpu );
    VMM_ASSERT( IS_MODE_NATIVE(gcpu) );
    VMM_ASSERT( action );

#ifdef ENABLE_EMULATOR
    if (action->emulator == GCPU_RESUME_EMULATOR_ACTION_START_EMULATOR) {
        emul_start_guest_execution( gcpu_emulator_handle(gcpu) );
        gcpu_set_hw_enforcement(gcpu, VMCS_HW_ENFORCE_EMULATOR);
        CLR_EXPLICIT_EMULATOR_REQUEST_FLAG(gcpu);
        SET_MODE_EMULATOR(gcpu);           // enable redirection of set/get to emulator
        VMM_ASSERT( action->flat_pt == GCPU_RESUME_FLAT_PT_ACTION_DO_NOTHING );
    }
#endif
    switch (action->flat_pt) {
        case GCPU_RESUME_FLAT_PT_ACTION_INSTALL_32_BIT_PT:
            gcpu_install_flat_memory( gcpu, GCPU_RESUME_FLAT_PT_ACTION_INSTALL_32_BIT_PT );
            break;
        case GCPU_RESUME_FLAT_PT_ACTION_INSTALL_64_BIT_PT:
            gcpu_install_flat_memory( gcpu, GCPU_RESUME_FLAT_PT_ACTION_INSTALL_64_BIT_PT );
            break;
        case GCPU_RESUME_FLAT_PT_ACTION_REMOVE:
            gcpu_destroy_flat_memory( gcpu );
            break;
        case GCPU_RESUME_FLAT_PT_ACTION_DO_NOTHING:
            break;
       default:
            VMM_LOG(mask_anonymous, level_trace,"Unknown GCPU pre-resume flat_pt action value: %d\n", action->flat_pt);
            VMM_DEADLOOP();
    }
}


// Context switching


// perform full state save before switching to another guest
void gcpu_swap_out( GUEST_CPU_HANDLE gcpu )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);

    // save state that is not saved by default
    if (!GET_DEBUG_REGS_CACHED_FLAG(gcpu)) {
        cache_debug_registers(gcpu);
    }
    if (!GET_FX_STATE_CACHED_FLAG(gcpu)) {
        cache_fx_state(gcpu);
    }
    vmcs_deactivate( vmcs );
}

// perform state restore after switching from another guest
void gcpu_swap_in( const GUEST_CPU_HANDLE gcpu )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);

    // make global assembler save area for this host CPU point to new guest
    g_guest_regs_save_area[hw_cpu_id()] = &(gcpu->save_area);
    vmcs_activate(vmcs);
    SET_ALL_MODIFIED(gcpu);
}


// Initialize gcpu environment for each VMEXIT
// Must be the first gcpu call in each VMEXIT
void gcpu_vmexit_start( const GUEST_CPU_HANDLE gcpu )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);

    // save current
    gcpu->save_area.gp.reg[ CR2_SAVE_AREA ] = hw_read_cr2();
    // CR3 should not be saved because guest asccess CR3 always causes VmExit and
    // should be cached by CR3-access handler
    gcpu->save_area.gp.reg[ CR8_SAVE_AREA ] = hw_read_cr8();

    if (!vmcs_sw_shadow_disable[hw_cpu_id()]) {
        CLR_ALL_CACHED(gcpu);
        vmcs_clear_cache( vmcs );
    }
    // if CR3 is not virtualized, update
    // internal storage with user-visible guest value
    if (IS_MODE_NATIVE(gcpu) && !IS_FLAT_PT_INSTALLED (gcpu) &&
        !gcpu_cr3_virtualized( gcpu )) {
        gcpu_set_guest_visible_control_reg( gcpu, IA32_CTRL_CR3, INVALID_CR3_SAVED_VALUE );
    }
}

void gcpu_raise_proper_events_after_level_change(GUEST_CPU_HANDLE gcpu,
                                                 MERGE_ORIG_VALUES *optional)
{
    UINT64 value;
    RAISE_EVENT_RETVAL update_event;
    EVENT_GCPU_GUEST_MSR_WRITE_DATA msr_update_data;

    value = gcpu_get_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR0, VMCS_MERGED);
    if (optional && optional->visible_cr0 == value) {
        update_event = cr_raise_write_events(gcpu, IA32_CTRL_CR0, value);
        VMM_ASSERT(update_event != EVENT_NOT_HANDLED); // Mustn't be GPF0
    }
    value = gcpu_get_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR4, VMCS_MERGED);
    if (optional && optional->visible_cr4 == value) {
        update_event = cr_raise_write_events(gcpu, IA32_CTRL_CR4, value);
        VMM_ASSERT(update_event != EVENT_NOT_HANDLED); // Mustn't be GPF0
    }
    value = gcpu_get_msr_reg_layered(gcpu, IA32_VMM_MSR_EFER, VMCS_MERGED);
    if (optional && optional->EFER == value) {
        msr_update_data.msr_index = IA32_MSR_EFER;
        msr_update_data.new_guest_visible_value = value;
        update_event = event_raise(EVENT_GCPU_AFTER_EFER_MSR_WRITE, gcpu, &msr_update_data);
    }
    if (optional && optional->visible_cr3 == value) {
        value = gcpu_get_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR3, VMCS_MERGED);
        update_event = cr_raise_write_events(gcpu, IA32_CTRL_CR3, value);
        VMM_ASSERT(update_event != EVENT_NOT_HANDLED); // Mustn't be GPF0
    }
    // PAT update will be tracked later in resume
}

GUEST_CPU_HANDLE gcpu_perform_split_merge (GUEST_CPU_HANDLE gcpu)
{
    VMCS_HIERARCHY* hierarchy = &(gcpu->vmcs_hierarchy);
    VMCS_OBJECT* level0_vmcs;
    VMCS_OBJECT* level1_vmcs;

    if ((gcpu->last_guest_level == GUEST_LEVEL_1_SIMPLE) &&
        (gcpu->last_guest_level == gcpu->next_guest_level)) {

        VMM_ASSERT(vmcs_read(vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_0), VMCS_EXIT_MSR_STORE_ADDRESS) == vmcs_read(vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_0), VMCS_ENTER_MSR_LOAD_ADDRESS));
        VMM_ASSERT(vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_0) == vmcs_hierarchy_get_vmcs(hierarchy, VMCS_MERGED));
        return gcpu;
    }
    level0_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_0);
    level1_vmcs = vmcs_hierarchy_get_vmcs(hierarchy, VMCS_LEVEL_1);
    if (gcpu->last_guest_level != gcpu->next_guest_level) {
        if (gcpu->last_guest_level == GUEST_LEVEL_1_SIMPLE) {
            VMM_ASSERT(gcpu->next_guest_level == GUEST_LEVEL_1_VMM);
            // TODO: separate "level-0" and "merged" VMCSs
            VMM_LOG(mask_anonymous, level_trace,
                "%s: Separation of (level-0) and (merged) VMCSs is not implemented yet\n", 
                __FUNCTION__);
            VMM_DEADLOOP();
        }
        else if (gcpu->last_guest_level == GUEST_LEVEL_1_VMM) {
            if (gcpu->next_guest_level == GUEST_LEVEL_1_SIMPLE) {
                // TODO: (level-1) --> simple guest mode
                VMM_LOG(mask_anonymous, level_trace,
                        "%s: Layering switch off is not implemented yet\n", 
                        __FUNCTION__);
                VMM_DEADLOOP();
            }
            else {
                VMM_ASSERT(gcpu->next_guest_level == GUEST_LEVEL_2);
                ms_merge_to_level2(gcpu, FALSE /* merge all fields */);
            }
        }
        else {
            VMM_ASSERT(gcpu->next_guest_level == GUEST_LEVEL_2);
            VMM_ASSERT(gcpu->next_guest_level == GUEST_LEVEL_1_VMM);

            ms_split_from_level2(gcpu);
            ms_merge_to_level1(gcpu, FALSE /* vmexit level2 -> level1 */, 
                               FALSE /* merge all fields */);
        }
        gcpu_raise_proper_events_after_level_change(gcpu, NULL);
    }
    else {
        /* gcpu->last_guest_level == gcpu->next_guest_level */
        if (gcpu->last_guest_level == GUEST_LEVEL_1_VMM) {
            BOOLEAN merge_only_dirty = GET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu) ? FALSE : TRUE;
            ms_merge_to_level1(gcpu, TRUE /* level1 -> level1 */, merge_only_dirty);
        }
        else {
            BOOLEAN merge_only_dirty = GET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu) ? FALSE : TRUE;

            VMM_ASSERT(gcpu->last_guest_level == GUEST_LEVEL_2)
            ms_merge_to_level2(gcpu, merge_only_dirty);
        }
    }
    vmcs_clear_dirty(level0_vmcs);
    vmcs_clear_dirty(level1_vmcs);
    // gcpu->last_guest_level = gcpu->next_guest_level;
    return gcpu;
}

static void gcpu_process_activity_state_change( GUEST_CPU_HANDLE gcpu )
{
    EVENT_GCPU_ACTIVITY_STATE_CHANGE_DATA event_data;

    event_data.new_state = gcpu_get_activity_state(gcpu);
    event_data.prev_state = GET_CACHED_ACTIVITY_STATE(gcpu);
    if (event_data.new_state != event_data.prev_state) {
        event_raise( EVENT_GCPU_ACTIVITY_STATE_CHANGE, gcpu, &event_data );
        SET_CACHED_ACTIVITY_STATE(gcpu, event_data.new_state);

        if (IS_STATE_INACTIVE(event_data.new_state)) {
            // switched from active to Wait-For-SIPI
            // the HW CPU will not be able to respond to any interrupts
            ipc_change_state_to_sipi( gcpu );
        }
        if (IS_STATE_INACTIVE(event_data.prev_state)) {
            // switched from Wait-For-SIPI to active state
            //:TODO: Looks like there is not need to apply GCPU control setup to VMCS-LEVEL0
            //:TODO: after CPU switched to Active state, because IPC messages are passed not
            //:TODO: in Wait-For-SIPI state also
            // apply all vmexit-request changes that were not applied because of 
            // Wait-For-SIPI state
            // gcpu_control_apply_only(gcpu);
            ipc_change_state_to_active(gcpu);
        }
    }
    CLR_ACTIVITY_STATE_CHANGED_FLAG(gcpu);
}


// Resume execution.  Never returns.
void gcpu_resume(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT* vmcs;
#ifdef JLMDEBUG1
    bprint("gcpu_resume\n");
#endif

    if (IS_MODE_NATIVE( gcpu )) {
        gcpu = gcpu->resume_func(gcpu);    // layered specific resume
        gcpu->last_guest_level = gcpu->next_guest_level;
        // nmi_resume_handler(gcpu);   // process platform NMI if any
    }
    vmcs = gcpu_get_vmcs(gcpu);
    VMM_ASSERT(vmcs);
    // exception which caused VMEXIT must be handled before resume
    VMM_ASSERT(0 == GET_EXCEPTION_RESOLUTION_REQUIRED_FLAG(gcpu));
    if (GET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu)) {
        if (GET_ACTIVITY_STATE_CHANGED_FLAG(gcpu)) {
            gcpu_process_activity_state_change(gcpu);
        }
        // if we in the emulator, it will take care about all settings
        if (IS_MODE_NATIVE(gcpu)) {
            GCPU_RESUME_ACTION action;

            if (gcpu_decide_on_resume_actions(gcpu,
                    gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0),
                    gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER), &action )) {
                // do something
                gcpu_perform_resume_actions( gcpu, &action );
            }
        }
        CLR_IMPORTANT_EVENT_OCCURED_FLAG(gcpu);
    }
    // support for active CR3
    if (IS_MODE_NATIVE(gcpu)) {
        if (IS_FLAT_PT_INSTALLED( gcpu )) {
            // gcpu_enforce_flat_memory_setup( gcpu ); VTDBG
        }
        else {
            if (!gcpu_cr3_virtualized( gcpu )) {
                UINT64 visible_cr3 = gcpu->save_area.gp.reg[CR3_SAVE_AREA];
                if (INVALID_CR3_SAVED_VALUE != visible_cr3) {
                    // CR3 user-visible value was changed inside vmm or CR3 
                    // virtualization was switched off
                    gcpu_set_control_reg(gcpu, IA32_CTRL_CR3, visible_cr3);
                }
            }
        }
    }
#ifdef FAST_VIEW_SWITCH
    if ( fvs_is_eptp_switching_supported() ) {
        fvs_save_resumed_eptp(gcpu);
    }
#endif
    // restore registers
    hw_write_cr2( gcpu->save_area.gp.reg[ CR2_SAVE_AREA ] );
    // CR3 should not be restored because guest asccess CR3 always causes VmExit and
    // should be cached by CR3-access handler
    hw_write_cr8( gcpu->save_area.gp.reg[ CR8_SAVE_AREA ] );
    if (IS_MODE_NATIVE(gcpu)) {
        vmdb_settings_apply_to_hw(gcpu); // apply GDB settings
    }
    //host_cpu_save_dr7(hw_cpu_id());
    if (0 != gcpu->hw_enforcements) {
        gcpu_apply_hw_enforcements(gcpu);
    }
    { 
        IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;
        idt_vectoring_info.Uint32 = (UINT32)vmcs_read(vmcs,VMCS_EXIT_INFO_IDT_VECTORING);
        if(idt_vectoring_info.Bits.Valid && 
           ((idt_vectoring_info.Bits.InterruptType==IdtVectoringInterruptTypeExternalInterrupt )
                ||(idt_vectoring_info.Bits.InterruptType==IdtVectoringInterruptTypeNmi))) {
            IA32_VMX_VMCS_VM_ENTER_INTERRUPT_INFO   interrupt_info;
            PROCESSOR_BASED_VM_EXECUTION_CONTROLS ctrls;

            interrupt_info.Uint32= (UINT32)vmcs_read(vmcs,VMCS_ENTER_INTERRUPT_INFO);
            VMM_ASSERT(!interrupt_info.Bits.Valid);
            interrupt_info.Uint32 = 0;
            interrupt_info.Bits.Valid = 1;
            interrupt_info.Bits.Vector = idt_vectoring_info.Bits.Vector;
            interrupt_info.Bits.InterruptType= idt_vectoring_info.Bits.InterruptType;
            vmcs_write(vmcs,VMCS_ENTER_INTERRUPT_INFO, interrupt_info.Uint32);
            if(idt_vectoring_info.Bits.InterruptType == IdtVectoringInterruptTypeNmi)
                vmcs_write(vmcs,VMCS_GUEST_INTERRUPTIBILITY,0);
            else
                vmcs_write(vmcs,VMCS_GUEST_INTERRUPTIBILITY,
                    vmcs_read(vmcs,VMCS_GUEST_INTERRUPTIBILITY) & ~0x3 );
            ctrls.Uint32 = (UINT32)vmcs_read(vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
            if((ctrls.Bits.MonitorTrapFlag)&&(vmcs_read(vmcs,VMCS_EXIT_INFO_REASON)==
                Ia32VmxExitBasicReasonEptViolation))
                gcpu->trigger_log_event = 1 + interrupt_info.Bits.Vector; 
        }
    }
    // flash VMCS
    if (!vmcs_sw_shadow_disable[hw_cpu_id()])
       vmcs_flush_to_cpu(vmcs);
    vmcs_sw_shadow_disable[hw_cpu_id()] = FALSE;
    if (!vmcs_launch_required(vmcs))
        nmi_window_update_before_vmresume(vmcs);
    // check for Launch and resume
    if (vmcs_launch_required(vmcs)) {
        vmcs_set_launched(vmcs);
#ifdef JLMDEBUG1
        bprint("launch required\n");
#endif
        // call assembler launch
        vmentry_func(TRUE);
        VMM_LOG(mask_anonymous, level_trace,
                "VmLaunch failed for GCPU %d GUEST %d in %s mode\n",
                gcpu->vcpu.guest_cpu_id, gcpu->vcpu.guest_id,
                IS_MODE_NATIVE(gcpu) ? "NATIVE" : "EMULATED");
    }
    else {
#ifdef JLMDEBUG1
        bprint("launch NOT required\n");
#endif
        // call assembler resume
        vmentry_func(FALSE);
        VMM_LOG(mask_anonymous, level_trace,
                "VmResume failed for GCPU %d GUEST %d in %s mode\n",
                gcpu->vcpu.guest_cpu_id, gcpu->vcpu.guest_id,
                IS_MODE_NATIVE(gcpu) ? "NATIVE" : "EMULATED" );
    }
#ifdef JLMDEBUG
    bprint("looping at the end of gcpu_resume\n");
    LOOP_FOREVER
#endif
    VMM_DEADLOOP();
    VMM_BREAKPOINT();
}

#ifdef ENABLE_EMULATOR

// Perform single step.
BOOLEAN gcpu_perform_single_step( const GUEST_CPU_HANDLE gcpu )
{
    return emul_run_single_instruction(gcpu->emulator_handle);
}

void gcpu_run_emulator(const GUEST_CPU_HANDLE gcpu)
{
    VMM_ASSERT( IS_MODE_NATIVE(gcpu) );

    SET_EXPLICIT_EMULATOR_REQUEST_FLAG( gcpu );
    SET_IMPORTANT_EVENT_OCCURED_FLAG( gcpu );
}


// Change execution mode - switch to native execution mode
VMM_STATUS gcpu_return_to_native_execution(GUEST_CPU_HANDLE gcpu, 
                ADDRESS* arg1 UNUSED, ADDRESS* arg2 UNUSED, 
                ADDRESS* arg3 UNUSED)
{
    // check if emulator finished already
    if (IS_MODE_EMULATOR(gcpu) && (gcpu->emulator_handle != NULL) &&
        emul_is_running( gcpu->emulator_handle )) {
        SET_MODE_NATIVE(gcpu); // disable redirection of set/get to emulator
        emul_stop_guest_execution( gcpu->emulator_handle );
        gcpu_remove_hw_enforcement(gcpu, VMCS_HW_ENFORCE_EMULATOR);
        return VMM_OK;
    }
#ifdef VMCALL_NOT_ALLOWED_FROM_RING_1_TO_3
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMM_ERROR;
}


BOOLEAN gcpu_is_mode_native(GUEST_CPU_HANDLE gcpu)
{
    return IS_MODE_NATIVE( gcpu );
}
#endif

VMM_STATUS gcpu_set_hw_enforcement(GUEST_CPU_HANDLE gcpu, VMCS_HW_ENFORCEMENT_ID enforcement)
{
    VMM_STATUS  status = VMM_OK;

    switch (enforcement) {
      case VMCS_HW_ENFORCE_EMULATOR:
      case VMCS_HW_ENFORCE_FLAT_PT:
      case VMCS_HW_ENFORCE_CACHE_DISABLED:
        gcpu->hw_enforcements |= enforcement;
        break;
      default:
        VMM_ASSERT(0);
        status = VMM_ERROR;
        break;
    }
    return status;
}

VMM_STATUS gcpu_remove_hw_enforcement(GUEST_CPU_HANDLE gcpu, 
                                      VMCS_HW_ENFORCEMENT_ID enforcement)
{
    VMM_STATUS status = VMM_OK;

    switch (enforcement) {
    case VMCS_HW_ENFORCE_EMULATOR:
        gcpu_enforce_settings_on_hardware(gcpu, GCPU_TEMP_EXCEPTIONS_RESTORE_ALL);
        gcpu_enforce_settings_on_hardware(gcpu, GCPU_TEMP_CR0_RESTORE_WP);
        break;
    case VMCS_HW_ENFORCE_FLAT_PT:
        gcpu_enforce_settings_on_hardware(gcpu, GCPU_TEMP_RESTORE_PF_AND_CR3);
        break;
    case VMCS_HW_ENFORCE_CACHE_DISABLED:
        // do nothing
        break;
    default:
        VMM_ASSERT(0);
        status = VMM_ERROR;
        break;
    }
    gcpu->hw_enforcements&= ~enforcement;
    return status;
}


void gcpu_apply_hw_enforcements(GUEST_CPU_HANDLE gcpu)
{
    VMM_ASSERT( !GET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu) );
    if (gcpu->hw_enforcements & VMCS_HW_ENFORCE_EMULATOR) {
        gcpu_enforce_settings_on_hardware(gcpu, GCPU_TEMP_EXCEPTIONS_EXIT_ON_ALL);
        gcpu_enforce_settings_on_hardware(gcpu, GCPU_TEMP_CR0_NO_EXIT_ON_WP);
    }
    else if (gcpu->hw_enforcements & VMCS_HW_ENFORCE_FLAT_PT) {
        gcpu_enforce_settings_on_hardware(gcpu, GCPU_TEMP_EXIT_ON_PF_AND_CR3);
        gcpu_enforce_flat_memory_setup(gcpu);
    }
    if (gcpu->hw_enforcements & VMCS_HW_ENFORCE_CACHE_DISABLED) {
        // CD = 1 is not allowed.
        vmcs_update( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, VMCS_MERGED),
                     VMCS_GUEST_CR0, 0, CR0_CD);
        // flush HW caches
        hw_wbinvd();
        // the solution is not full because of
        //   1. the OS may assume that some non-write-back memory is uncached
        //   2. caching influencies in multicore environment
        //   3. internal CPU behavior like in HSW VMCS caching effects.
    }
    VMM_ASSERT( !GET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu) );
}

