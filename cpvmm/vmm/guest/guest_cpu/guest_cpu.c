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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_CPU_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_CPU_C, __condition)
#include "guest_cpu_internal.h"
#include "guest_internal.h"
#include "heap.h"
#include "array_iterators.h"
#include "gpm_api.h"
#include "scheduler.h"
#include "vmx_ctrl_msrs.h"
#include "host_memory_manager_api.h"
#include "vmcs_init.h"
#include "cli.h"
#include "pat_manager.h"
#include "page_walker.h"
#include "vmm_startup.h"
#include "memory_allocator.h"
#include "host_cpu.h"
#include "vmx_timer.h"
#include "unrestricted_guest.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#pragma warning( disable: 4100 )

// Guest CPU
// Guest CPU may be in 2 different modes:
//    16 mode - run under emulator
//    any other mode - run native
static GUEST_CPU_HANDLE g_gcpus = NULL; // list of all guest cpus

// this is a shortcut pointer for assembler code
GUEST_CPU_SAVE_AREA** g_guest_regs_save_area = NULL;
static UINT32         g_host_cpu_count = 0;

CLI_CODE( static void gcpu_install_show_service(void);)

// Global gcpu iterator
typedef GUEST_CPU_HANDLE GLOBAL_GUEST_CPU_ITERATOR;

INLINE GUEST_CPU_HANDLE global_gcpu_first( GLOBAL_GUEST_CPU_ITERATOR* ctx )
{
    *ctx = g_gcpus;
    return g_gcpus;
}

INLINE GUEST_CPU_HANDLE global_gcpu_next( GLOBAL_GUEST_CPU_ITERATOR* ctx )
{
    GUEST_CPU_HANDLE gcpu;
    if(ctx == NULL || *ctx == NULL) {
        return NULL;
    }
    gcpu = *ctx;
    *ctx = gcpu->next_gcpu;
    return gcpu->next_gcpu;
}

// cache debug registers
// only dr0-dr6 should be cached here, dr7 is in VMCS
void cache_debug_registers( const GUEST_CPU* gcpu )
{
    // make volatile
    GUEST_CPU* vgcpu = (GUEST_CPU*)gcpu;

    if (GET_DEBUG_REGS_CACHED_FLAG( vgcpu )) {
        return;
    }
    SET_DEBUG_REGS_CACHED_FLAG(vgcpu);
    vgcpu->save_area.debug.reg[IA32_REG_DR0] = hw_read_dr(0);
    vgcpu->save_area.debug.reg[IA32_REG_DR1] = hw_read_dr(1);
    vgcpu->save_area.debug.reg[IA32_REG_DR2] = hw_read_dr(2);
    vgcpu->save_area.debug.reg[IA32_REG_DR3] = hw_read_dr(3);
    // dr4 and dr5 are reserved
    vgcpu->save_area.debug.reg[IA32_REG_DR6] = hw_read_dr(6);
}

#ifdef INCLUDE_UNUSED_CODE
void restore_hw_debug_registers( GUEST_CPU* gcpu )
{
    // modified without cached is possible for initial start
    CLR_DEBUG_REGS_MODIFIED_FLAG(gcpu);
    if (! GET_DEBUG_REGS_CACHED_FLAG( gcpu )) {
        return;
    }
    hw_write_dr(0, gcpu->save_area.debug.reg[IA32_REG_DR0]);
    hw_write_dr(1, gcpu->save_area.debug.reg[IA32_REG_DR1]);
    hw_write_dr(2, gcpu->save_area.debug.reg[IA32_REG_DR2]);
    hw_write_dr(3, gcpu->save_area.debug.reg[IA32_REG_DR3]);
    // dr4 and dr5 are reserved
    // hw_write_dr(6, gcpu->save_area.debug.reg[IA32_REG_DR6]);  Read Only $VT$ 
}
#endif

// cache fx state
// note, that fx state include mmx registers also, that are wrong at this state,
// because contain VMM and not guest values
void cache_fx_state( const GUEST_CPU* gcpu )
{
    // make volatile
    GUEST_CPU* vgcpu = (GUEST_CPU*)gcpu;

    if (GET_FX_STATE_CACHED_FLAG( vgcpu )) {
        return;
    }
    SET_FX_STATE_CACHED_FLAG(vgcpu);
    hw_fxsave( vgcpu->save_area.fxsave_area );
}

#ifdef INCLUDE_UNUSED_CODE
void restore_fx_state( GUEST_CPU* gcpu )
{
    // modified without cached is possible for initial start
    CLR_FX_STATE_MODIFIED_FLAG(gcpu);
    if (! GET_FX_STATE_CACHED_FLAG( gcpu )) {
        return;
    }
    hw_fxrestore( gcpu->save_area.fxsave_area );
}
#endif


// perform minimal init of vmcs
// assumes that all uninit fields are 0 by default, except those that
// are required to be 1 according to
// Intel(R) 64 and IA-32 Architectures volume 3B,
// paragraph 22.3.1 "Checks on the Guest State Area"
static void setup_default_state( GUEST_CPU_HANDLE gcpu )
{
#ifdef JLMDEBUG
    bprint("setup_default_state starting\n");
#endif
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    VMM_ASSERT(vmcs);
    // init control fields
    guest_cpu_control_setup( gcpu );
#ifdef JLMDEBUG
    bprint("guest_cpu_control_setup done\n");
#endif
    // set control registers to any supported value
    gcpu_set_control_reg( gcpu, IA32_CTRL_CR0, 0);
    gcpu_set_control_reg( gcpu, IA32_CTRL_CR4, 0);
    gcpu_set_control_reg( gcpu, IA32_CTRL_CR8, 0);

    // set all segment selectors except TR and CS to unusable state
    // CS: Accessed Code NotSystem NonConforming Present 32bit bit-granularity
    gcpu_set_segment_reg(gcpu, IA32_SEG_CS, 0, 0, 0, 0x99 );
    gcpu_set_segment_reg(gcpu, IA32_SEG_DS, 0, 0, 0, EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE);
    gcpu_set_segment_reg(gcpu, IA32_SEG_SS, 0, 0, 0, EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE);
    gcpu_set_segment_reg(gcpu, IA32_SEG_ES, 0, 0, 0, EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE);
    gcpu_set_segment_reg(gcpu, IA32_SEG_FS, 0, 0, 0, EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE);
    gcpu_set_segment_reg(gcpu, IA32_SEG_GS, 0, 0, 0, EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE);
    gcpu_set_segment_reg(gcpu, IA32_SEG_LDTR, 0, 0, 0, EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE );
    // TR: 32bit busy TSS System Present bit-granularity
    gcpu_set_segment_reg(gcpu, IA32_SEG_TR,   0, 0, 0, 0x8B);
    // FLAGS: reserved bit 1 must be 1, all other - 0
#ifdef JLMDEBUG
    bprint("about to call gcpu_set_gp_reg\n");
#endif
    gcpu_set_gp_reg( gcpu, IA32_REG_RFLAGS, 0x2);
#ifdef JLMDEBUG
    bprint("about to call vmcs_init_all_msr_lists\n");
#endif
    vmcs_init_all_msr_lists(vmcs);
#ifdef JLMDEBUG
    bprint("about to call  host_cpu_init_vmexit_store_and_vmenter_load_msr_lists_according_to_vmexit_load_list\n");
#endif
    host_cpu_init_vmexit_store_and_vmenter_load_msr_lists_according_to_vmexit_load_list(gcpu);
#ifdef JLMDEBUG
    bprint("about to call gcpu_set_msr_reg\n");
#endif
    gcpu_set_msr_reg(gcpu, IA32_VMM_MSR_EFER, 0);
    gcpu_set_msr_reg(gcpu, IA32_VMM_MSR_PAT, hw_read_msr(IA32_MSR_PAT));
    VMM_ASSERT(vmcs_read(vmcs, VMCS_EXIT_MSR_STORE_ADDRESS) == vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_ADDRESS));

    // by default put guest CPU into the Wait-for-SIPI state
    VMM_ASSERT( vmcs_hw_get_vmx_constraints()->vm_entry_in_wait_for_sipi_state_supported );
#ifdef JLMDEBUG
    bprint("about to call gcpu_set_activity_state\n");
#endif
    gcpu_set_activity_state( gcpu, Ia32VmxVmcsGuestSleepStateWaitForSipi );
#ifdef JLMDEBUG
    bprint("about to call vmcs_write\n");
#endif
    vmcs_write( vmcs, VMCS_ENTER_INTERRUPT_INFO, 0 );
    vmcs_write( vmcs, VMCS_ENTER_EXCEPTION_ERROR_CODE, 0 );
#ifdef ENABLE_PREEMPTION_TIMER
    vmx_timer_create(gcpu);
#endif
    vmcs_set_launch_required( vmcs );
}


void gcpu_manager_init( UINT16 host_cpu_count )
{
    // BEFORE_VMLAUNCH
    VMM_ASSERT( host_cpu_count );
    g_host_cpu_count = host_cpu_count;
    g_guest_regs_save_area = vmm_memory_alloc( sizeof(GUEST_CPU_SAVE_AREA*) * host_cpu_count );
    // BEFORE_VMLAUNCH
    VMM_ASSERT( g_guest_regs_save_area );
    // init subcomponents
    vmcs_hw_init();
    vmcs_manager_init();
    CLI_CODE( gcpu_install_show_service();)
}

GUEST_CPU_HANDLE gcpu_allocate( VIRTUAL_CPU_ID vcpu, GUEST_HANDLE guest )
{
    GUEST_CPU_HANDLE          gcpu = NULL;
    GLOBAL_GUEST_CPU_ITERATOR ctx;
    VMM_STATUS  status;

#ifdef JLMDEBUG
    bprint("gcpu_allocate, g_cpu: 0x%016x\n", g_gcpus);
#endif
    // ensure that this vcpu yet not allocated
    for (gcpu = global_gcpu_first(&ctx); gcpu; gcpu = global_gcpu_next(&ctx)) {
        if ((gcpu->vcpu.guest_id == vcpu.guest_id) &&
            (gcpu->vcpu.guest_cpu_id == vcpu.guest_cpu_id)) {
            VMM_LOG(mask_anonymous,level_trace,
                     "The CPU %d for the Guest %d was already allocated.\n",
                     vcpu.guest_cpu_id, vcpu.guest_id);
            VMM_ASSERT(FALSE);
            return gcpu;
        }
    }
    // allocate next gcpu
    gcpu = (GUEST_CPU_HANDLE) vmm_memory_alloc(sizeof(GUEST_CPU));
    VMM_ASSERT(gcpu);
    vmm_zeromem(gcpu, sizeof(GUEST_CPU));
    gcpu->next_gcpu = g_gcpus;
    g_gcpus = gcpu;
#ifdef JLMDEBUG
    bprint("gcpu_allocate, got memory\n");
#endif
    gcpu->vcpu = vcpu;
    gcpu->last_guest_level = GUEST_LEVEL_1_SIMPLE;
    gcpu->next_guest_level = GUEST_LEVEL_1_SIMPLE;
    gcpu->state_flags = 0;
    gcpu->caching_flags = 0;
    // gcpu->vmcs  = vmcs_allocate();
    status = vmcs_hierarchy_create(&gcpu->vmcs_hierarchy, gcpu);
    VMM_ASSERT(VMM_OK == status);
#ifdef JLMDEBUG
    bprint("gcpu_allocate, created hierarchy\n");
#endif
    gcpu->emulator_handle = 0;
    gcpu->guest_handle = guest;
    gcpu->active_gpm = NULL;
    SET_MODE_NATIVE(gcpu);
    SET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu);
    SET_CACHED_ACTIVITY_STATE(gcpu, Ia32VmxVmcsGuestSleepStateActive);
#ifdef JLMDEBUG
    bprint("about to call setup_default_state\n");
#endif
    setup_default_state( gcpu );
    gcpu->resume_func = gcpu_perform_split_merge; // default "resume" function
#ifdef FAST_VIEW_SWITCH
     gcpu->fvs_cpu_desc.vmentry_eptp = 0;
     gcpu->fvs_cpu_desc.enabled = FALSE;
 #endif
    return gcpu;
}

// Get Guest CPU state by VIRTUAL_CPU_ID
// Return NULL if no such guest cpu
GUEST_CPU_HANDLE gcpu_state( const VIRTUAL_CPU_ID* vcpu )
{
    GUEST_CPU_HANDLE gcpu = NULL;
    GLOBAL_GUEST_CPU_ITERATOR ctx;

    for (gcpu = global_gcpu_first(&ctx); gcpu; gcpu = global_gcpu_next(&ctx)) {
        if ((gcpu->vcpu.guest_id == vcpu->guest_id) &&
                (gcpu->vcpu.guest_cpu_id == vcpu->guest_cpu_id)) {  // found guest cpu
            return gcpu;
        }
    }
    return NULL;
}

// get VMCS object to work directly
VMCS_OBJECT* gcpu_get_vmcs( GUEST_CPU_HANDLE  gcpu )
{
    if(gcpu == NULL) {
        return NULL;
    }
    return vmcs_hierarchy_get_vmcs(&gcpu->vmcs_hierarchy, VMCS_MERGED);
}

VMCS_HIERARCHY * gcpu_get_vmcs_hierarchy( GUEST_CPU_HANDLE  gcpu )
{
    if(gcpu == NULL) {
        return NULL;
    }
    return &gcpu->vmcs_hierarchy;
}

VMCS_OBJECT* gcpu_get_vmcs_layered( GUEST_CPU_HANDLE  gcpu, VMCS_LEVEL level)
{
    if(gcpu == NULL) {
        return NULL;
    }
    return vmcs_hierarchy_get_vmcs(&gcpu->vmcs_hierarchy, level);
}


BOOLEAN gcpu_is_vmcs_layered( GUEST_CPU_HANDLE  gcpu)
{
    VMM_ASSERT(gcpu);

    return vmcs_hierarchy_is_layered(&gcpu->vmcs_hierarchy);
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN gcpu_is_merge_required(GUEST_CPU_HANDLE gcpu)
{
    return gcpu->merge_required;
}
#endif

#ifdef INCLUDE_UNUSED_CODE
void gcpu_configure_merge_required(GUEST_CPU_HANDLE gcpu, BOOLEAN required)
{
    gcpu->merge_required = (UINT8) required;
}
#endif

BOOLEAN gcpu_uses_host_page_tables(GUEST_CPU_HANDLE gcpu)
{
    return gcpu->use_host_page_tables;
}

void gcpu_do_use_host_page_tables(GUEST_CPU_HANDLE gcpu, BOOLEAN use)
{
    gcpu->use_host_page_tables = (UINT8) use;
}

// Get VIRTUAL_CPU_ID by Guest CPU
const VIRTUAL_CPU_ID* guest_vcpu( const GUEST_CPU_HANDLE gcpu )
{
    if(gcpu == NULL) {
        return NULL;
    }
    return &gcpu->vcpu;
}

// Get Guest Handle by Guest CPU
GUEST_HANDLE gcpu_guest_handle( const GUEST_CPU_HANDLE gcpu )
{
    if(gcpu == NULL) {
        return NULL;
    }
    return gcpu->guest_handle;
}

#ifdef ENABLE_EMULATOR
// Emulator-related
EMULATOR_HANDLE gcpu_emulator_handle( GUEST_CPU_HANDLE gcpu )
{
    if(gcpu == NULL) {
        return NULL;
    }
    if (gcpu->emulator_handle == NULL) {
        gcpu->emulator_handle = emul_create_handle( gcpu );
        VMM_ASSERT(gcpu->emulator_handle);
        emul_intialize(gcpu->emulator_handle);
    }
    return gcpu->emulator_handle;
}


BOOLEAN gcpu_process_interrupt(VECTOR_ID vector_id)
{
    BOOLEAN recognized = emulator_is_running_as_guest();

    if (recognized) {
        // call emulator handler
        GUEST_CPU_HANDLE gcpu = scheduler_current_gcpu();
        VMM_ASSERT(gcpu && IS_MODE_EMULATOR(gcpu));
        VMM_ASSERT(gcpu->emulator_handle);
        emulator_interrupt_handler(gcpu->emulator_handle, vector_id);
    }
    return recognized;
}
#else
BOOLEAN gcpu_process_interrupt(VECTOR_ID vector_id)
{
    return FALSE;
}
#endif


// Initialize guest CPU
// Should be called only if initial GCPU state is not Wait-For-Sipi
void gcpu_initialize( GUEST_CPU_HANDLE gcpu,
                      const VMM_GUEST_CPU_STARTUP_STATE* initial_state )
{
    UINT32 idx;
    VMM_ASSERT( gcpu );
    if (! initial_state) {
        return;
    }
    if (initial_state->size_of_this_struct != sizeof( VMM_GUEST_CPU_STARTUP_STATE )) {
        // wrong state
        VMM_LOG(mask_anonymous, level_trace,"gcpu_initialize() called with unknown structure\n");
        VMM_DEADLOOP();
        return;
    }
    if (initial_state->version_of_this_struct != VMM_GUEST_CPU_STARTUP_STATE_VERSION) {
        // wrong version
        VMM_LOG(mask_anonymous, level_trace,
            "gcpu_initialize() called with non-compatible VMM_GUEST_CPU_STARTUP_STATE "
            "structure: given version: %d expected version: %d\n",
            initial_state->version_of_this_struct, VMM_GUEST_CPU_STARTUP_STATE_VERSION );
        VMM_DEADLOOP();
        return;
    }
    //    vmcs_set_launch_required( gcpu->vmcs );
    vmcs_set_launch_required( gcpu_get_vmcs(gcpu) );
    // init gp registers
    for (idx = IA32_REG_RAX; idx < IA32_REG_GP_COUNT; ++idx) {
        gcpu_set_gp_reg( gcpu, (VMM_IA32_GP_REGISTERS)idx, initial_state->gp.reg[idx] );
    }
    // init xmm registers
    for (idx = IA32_REG_XMM0; idx < IA32_REG_XMM_COUNT; ++idx) {
        gcpu_set_xmm_reg( gcpu, (VMM_IA32_XMM_REGISTERS)idx, initial_state->xmm.reg[idx] );
    }
    // init segment registers
    for (idx = IA32_SEG_CS; idx < IA32_SEG_COUNT; ++idx) {
        gcpu_set_segment_reg(gcpu, (VMM_IA32_SEGMENT_REGISTERS)idx, 
                initial_state->seg.segment[idx].selector,
                initial_state->seg.segment[idx].base, initial_state->seg.segment[idx].limit,
                initial_state->seg.segment[idx].attributes);
    }
    // init control registers
    for (idx = IA32_CTRL_CR0; idx < IA32_CTRL_COUNT; ++idx) {
        gcpu_set_control_reg(gcpu, (VMM_IA32_CONTROL_REGISTERS)idx, 
                                   initial_state->control.cr[idx]);
        gcpu_set_guest_visible_control_reg( gcpu, (VMM_IA32_CONTROL_REGISTERS)idx, 
                                   initial_state->control.cr[idx] );
    }
    gcpu_set_gdt_reg( gcpu, initial_state->control.gdtr.base, initial_state->control.gdtr.limit );
    gcpu_set_idt_reg( gcpu, initial_state->control.idtr.base, initial_state->control.idtr.limit );
    // init selected model-specific registers
    gcpu_set_msr_reg( gcpu, IA32_VMM_MSR_DEBUGCTL,     initial_state->msr.msr_debugctl );
    gcpu_set_msr_reg( gcpu, IA32_VMM_MSR_EFER,         initial_state->msr.msr_efer );
    gcpu_set_msr_reg( gcpu, IA32_VMM_MSR_PAT,          initial_state->msr.msr_pat );
    gcpu_set_msr_reg( gcpu, IA32_VMM_MSR_SYSENTER_ESP, initial_state->msr.msr_sysenter_esp );
    gcpu_set_msr_reg( gcpu, IA32_VMM_MSR_SYSENTER_EIP, initial_state->msr.msr_sysenter_eip );
    gcpu_set_msr_reg( gcpu, IA32_VMM_MSR_SYSENTER_CS,  initial_state->msr.msr_sysenter_cs );
    gcpu_set_msr_reg( gcpu, IA32_VMM_MSR_SMBASE,       initial_state->msr.smbase );
    gcpu_set_pending_debug_exceptions( gcpu, initial_state->msr.pending_exceptions );
    gcpu_set_interruptibility_state( gcpu,   initial_state->msr.interruptibility_state );

    // set cached value to the same in order not to trigger events
    gcpu_set_activity_state( gcpu,  (IA32_VMX_VMCS_GUEST_SLEEP_STATE)initial_state->msr.activity_state );
    // set state in vmenter control fields
    gcpu_set_vmenter_control( gcpu );
    cache_fx_state(gcpu);
    cache_debug_registers(gcpu);
    SET_MODE_NATIVE(gcpu);
    SET_ALL_MODIFIED(gcpu);
}


BOOLEAN gcpu_gva_to_gpa(GUEST_CPU_HANDLE gcpu, GVA gva, GPA* gpa)
{
    UINT64 gpa_tmp;
    UINT64 pfec_tmp;
    BOOLEAN res;
    EM64T_CR0 visible_cr0;
    visible_cr0.Uint64 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);

    // GVA = GPA in non-paged mode
    if(is_unrestricted_guest_supported() && !visible_cr0.Bits.PG) {
        *gpa = gva;
        return TRUE;
    }
    if (IS_FLAT_PT_INSTALLED(gcpu)) {
        *gpa = gva;
        return TRUE;
    }
    else {
        res = pw_perform_page_walk(gcpu, gva, FALSE, FALSE, FALSE, FALSE, &gpa_tmp, &pfec_tmp);
        if (res == PW_RETVAL_SUCCESS) {
            *gpa = gpa_tmp;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN gcpu_gva_to_hva(GUEST_CPU_HANDLE gcpu, GVA gva, HVA* hva)
{
    GUEST_HANDLE guest_handle;
    GPM_HANDLE gpm_handle;
    UINT64 gpa;
    UINT64 hva_tmp;

    if (!gcpu_gva_to_gpa(gcpu, gva, &gpa)) {
        VMM_LOG(mask_uvmm, level_error,"%s: Failed to convert gva=%P to gpa\n", __FUNCTION__, gva);
        return FALSE;
    }
    guest_handle = gcpu_guest_handle(gcpu);
    gpm_handle = gcpu_get_current_gpm(guest_handle);
    if (!gpm_gpa_to_hva(gpm_handle, gpa, &hva_tmp)) {
        VMM_LOG(mask_uvmm, level_error,"%s: Failed to convert gpa=%P to hva\n", __FUNCTION__, gpa);
        return FALSE;
    }
    *hva = hva_tmp;
    return TRUE;
}

#ifdef INCLUDE_UNUSED_CODE
void gcpu_assign_resume_func(GUEST_CPU_HANDLE gcpu, GCPU_RESUME_FUNC resume_func) {
    gcpu->resume_func = resume_func;
}

void gcpu_install_vmexit_func(GUEST_CPU_HANDLE gcpu, GCPU_VMEXIT_FUNC vmexit_func)
{
    gcpu->vmexit_func = vmexit_func;
}
#endif

GUEST_CPU_HANDLE gcpu_call_vmexit_function(GUEST_CPU_HANDLE gcpu, UINT32 reason)
{
    if (gcpu->vmexit_func)
        return gcpu->vmexit_func(gcpu, reason);
    else
        return NULL;
}


#define PRINT_GP_REG(__gcpu, __reg) CLI_PRINT("\t%13s (addr=%P): %P\n", #__reg, &(__gcpu->save_area.gp.reg[__reg]), __gcpu->save_area.gp.reg[__reg]);

CLI_CODE(

int gcpu_show_gp_registers(unsigned argc, char *args[])
{
    GUEST_ID guest_id;
    GUEST_CPU_HANDLE gcpu;

    if (argc < 2)
        return -1;
    guest_id = (GUEST_ID) CLI_ATOL(args[1]);
    gcpu = scheduler_get_current_gcpu_for_guest(guest_id);
    if (NULL == gcpu)
        return -1;
    CLI_PRINT("=============================================\n");
    PRINT_GP_REG(gcpu, IA32_REG_RAX);
    PRINT_GP_REG(gcpu, IA32_REG_RBX);
    PRINT_GP_REG(gcpu, IA32_REG_RCX);
    PRINT_GP_REG(gcpu, IA32_REG_RDX);
    PRINT_GP_REG(gcpu, IA32_REG_RDI);
    PRINT_GP_REG(gcpu, IA32_REG_RSI);
    PRINT_GP_REG(gcpu, IA32_REG_RBP);
    PRINT_GP_REG(gcpu, IA32_REG_R8);
    PRINT_GP_REG(gcpu, IA32_REG_R9);
    PRINT_GP_REG(gcpu, IA32_REG_R10);
    PRINT_GP_REG(gcpu, IA32_REG_R11);
    PRINT_GP_REG(gcpu, IA32_REG_R12);
    PRINT_GP_REG(gcpu, IA32_REG_R13);
    PRINT_GP_REG(gcpu, IA32_REG_R14);
    CLI_PRINT("\n");
    PRINT_GP_REG(gcpu, CR2_SAVE_AREA);
    PRINT_GP_REG(gcpu, CR3_SAVE_AREA);
    PRINT_GP_REG(gcpu, CR8_SAVE_AREA);
    //CLI_PRINT("\t%13s (addr=%P): %P\n", "EFER", &(gcpu->save_area.auto_swap_msrs.efer.MsrData), gcpu->save_area.auto_swap_msrs.efer.MsrData);
    //CLI_PRINT("\n");
    CLI_PRINT("\t%s : %P\n", "Guest visible CR0", gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0));
    CLI_PRINT("\t%s : %P\n", "Guest visible CR4", gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4));
    CLI_PRINT("=============================================\n");

    return 0;
}

) // End Of CLI_CODE

#ifdef ENABLE_EMULATOR
int gcpu_show_emulator_state(unsigned argc, char *args[])
{
    GUEST_ID guest_id;
    GUEST_CPU_HANDLE gcpu;

    if (argc < 2)
        return -1;
    guest_id = (GUEST_ID) CLI_ATOL(args[1]);
    gcpu = scheduler_get_current_gcpu_for_guest(guest_id);
    if (NULL == gcpu)
        return -1;
    if (FALSE == emul_state_show(gcpu->emulator_handle))
        return -1;
    return 0;
}

CLI_CODE(
void gcpu_install_show_service(void)
{
    CLI_AddCommand(gcpu_show_emulator_state,
        "debug emulator show",
        "Print Emulator Architectural State", "<guest_id>",
        CLI_ACCESS_LEVEL_SYSTEM);

    CLI_AddCommand(gcpu_show_gp_registers,
        "debug guest show registers",
        "Print Guest CPU General Purpose Registers on current CPU", "<guest_id>",
        CLI_ACCESS_LEVEL_USER);
}
) // End Of CLI_CODE
#else
CLI_CODE(
void gcpu_install_show_service(void)
{
    CLI_AddCommand(gcpu_show_gp_registers,
        "debug guest show registers",
        "Print Guest CPU General Purpose Registers on current CPU", "<guest_id>",
        CLI_ACCESS_LEVEL_USER);
}
) // End Of CLI_CODE
#endif

void gcpu_change_level0_vmexit_msr_load_list(GUEST_CPU_HANDLE gcpu, 
        IA32_VMX_MSR_ENTRY* msr_list, UINT32 msr_list_count) {
    UINT64 addr = 0;
    VMCS_OBJECT* level0_vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy(gcpu), VMCS_LEVEL_0);

    if (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE) {
        VMM_ASSERT(vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy(gcpu), VMCS_MERGED) == level0_vmcs);
        if ((msr_list_count != 0) && (!hmm_hva_to_hpa((HVA)msr_list, &addr))) {
            VMM_LOG(mask_anonymous, level_trace,"%s: Failed to convert HVA to HPA\n", __FUNCTION__);
            // BEFORE_VMLAUNCH
            VMM_DEADLOOP();
        }
    }
    else {
        // When layering HVA is stored
        addr = (UINT64)msr_list;
    }
    vmcs_write(level0_vmcs, VMCS_EXIT_MSR_LOAD_ADDRESS, addr);
    vmcs_write(level0_vmcs, VMCS_EXIT_MSR_LOAD_COUNT, msr_list_count);
}
