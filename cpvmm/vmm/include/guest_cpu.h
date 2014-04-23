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

#ifndef _GUEST_CPU_H_
#define _GUEST_CPU_H_

#include "vmm_arch_defs.h"
#include "vmx_vmcs.h"
#include "vmm_objects.h"
#include "vmexit.h"
#include "vmm_startup.h"
#include "vmcs_hierarchy.h"
#include "vmm_dbg.h"

#define PRINT_GCPU_IDENTITY(__gcpu)                                            \
VMM_DEBUG_CODE( 															   \
{                                                                              \
    const VIRTUAL_CPU_ID * __vcpuid = guest_vcpu(__gcpu);                      \
                                                                               \
    VMM_LOG(mask_anonymous,	level_trace, "CPU(%d) Guest(%d) GuestCPU(%d)",		\
        hw_cpu_id(),                                                           \
        __vcpuid->guest_id,                                                    \
        __vcpuid->guest_cpu_id);                                              \
                                                                               \
	}																			\
)


// guest cpu state

// define single guest virtual cpu
typedef struct _VIRTUAL_CPU_ID
{
    GUEST_ID guest_id;
    CPU_ID   guest_cpu_id; // guest cpu id and not host
} VIRTUAL_CPU_ID;


typedef enum {
    GUEST_LEVEL_1_SIMPLE,
    GUEST_LEVEL_1_VMM,
    GUEST_LEVEL_2
} GUEST_LEVEL_ENUM;


UINT64 gcpu_get_native_gp_reg_layered( const GUEST_CPU_HANDLE gcpu,
          VMM_IA32_GP_REGISTERS reg, VMCS_LEVEL level);
void   gcpu_set_native_gp_reg_layered( GUEST_CPU_HANDLE gcpu,
          VMM_IA32_GP_REGISTERS reg, UINT64 value, VMCS_LEVEL level);
#ifdef INCLUDE_UNUSED_CODE
void gcpu_get_all_gp_regs_internal( const GUEST_CPU_HANDLE gcpu, UINT64 *GPreg );
#endif
UINT64 gcpu_get_gp_reg_layered( const GUEST_CPU_HANDLE gcpu,
                VMM_IA32_GP_REGISTERS reg, VMCS_LEVEL level);
void gcpu_set_all_gp_regs_internal( const GUEST_CPU_HANDLE gcpu, UINT64 *GPReg );
void gcpu_set_gp_reg_layered( GUEST_CPU_HANDLE gcpu,
              VMM_IA32_GP_REGISTERS reg, UINT64  value, VMCS_LEVEL level);
void   gcpu_get_segment_reg_layered(
              const GUEST_CPU_HANDLE gcpu, VMM_IA32_SEGMENT_REGISTERS reg,
              UINT16* selector, UINT64* base, UINT32* limit,
              UINT32* attributes, VMCS_LEVEL level);
void   gcpu_set_segment_reg_layered(
              GUEST_CPU_HANDLE gcpu, VMM_IA32_SEGMENT_REGISTERS reg,
              UINT16  selector, UINT64 base, UINT32 limit,
              UINT32  attributes, VMCS_LEVEL level);
UINT64 gcpu_get_control_reg_layered( const GUEST_CPU_HANDLE gcpu, 
		VMM_IA32_CONTROL_REGISTERS reg, VMCS_LEVEL level);
void   gcpu_set_control_reg_layered( GUEST_CPU_HANDLE gcpu, 
		VMM_IA32_CONTROL_REGISTERS reg, UINT64 value, VMCS_LEVEL level);
UINT64 gcpu_get_guest_visible_control_reg_layered( const GUEST_CPU_HANDLE gcpu, 
		VMM_IA32_CONTROL_REGISTERS reg, VMCS_LEVEL level);
void gcpu_set_guest_visible_control_reg_layered( const GUEST_CPU_HANDLE gcpu, 
               VMM_IA32_CONTROL_REGISTERS reg, UINT64 value, VMCS_LEVEL level);
void    gcpu_set_cr0_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, 
		UINT64 value );
UINT64  gcpu_get_cr0_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level);
void    gcpu_set_cr4_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, 
		UINT64 value );
UINT64  gcpu_get_cr4_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level );
void    gcpu_set_pin_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, 
		UINT64 value );
UINT64  gcpu_get_pin_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level );
void    gcpu_set_processor_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, 
		UINT64 value );
UINT64  gcpu_get_processor_ctrls_layered( GUEST_CPU_HANDLE gcpu, 
		VMCS_LEVEL level );
void    gcpu_set_processor_ctrls2_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, 
		UINT64 value );
UINT64  gcpu_get_processor_ctrls2_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level );
void    gcpu_set_exceptions_map_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, 
		UINT64 value);
UINT64  gcpu_get_exceptions_map_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level );
void    gcpu_set_exit_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32 value );
UINT32  gcpu_get_exit_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level );
void    gcpu_set_enter_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32 value );
UINT32  gcpu_get_enter_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level );
void gcpu_get_pf_error_code_mask_and_match_layered(GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32* pf_mask, UINT32* pf_match);
void gcpu_set_pf_error_code_mask_and_match_layered(GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32 pf_mask, UINT32 pf_match);

#ifdef INCLUDE_UNUSED_CODE
void   gcpu_get_ldt_reg_layered( const GUEST_CPU_HANDLE gcpu,
              UINT64* base, UINT32* limit, VMCS_LEVEL level);
void   gcpu_set_ldt_reg_layered( const GUEST_CPU_HANDLE gcpu,
              UINT64 base, UINT32 limit, VMCS_LEVEL level);
void   gcpu_get_tr_reg_layered( const GUEST_CPU_HANDLE gcpu,
              UINT64* base, UINT32* limit, VMCS_LEVEL level);
void   gcpu_set_tr_reg_layered(const GUEST_CPU_HANDLE gcpu,
                             UINT64 base, UINT32 limit, VMCS_LEVEL level);
#endif

void   gcpu_get_gdt_reg_layered(const GUEST_CPU_HANDLE gcpu,
                             UINT64* base, UINT32* limit, VMCS_LEVEL level);
void   gcpu_set_gdt_reg_layered( const GUEST_CPU_HANDLE gcpu, UINT64 base,
                             UINT32 limit, VMCS_LEVEL level);
void   gcpu_get_idt_reg_layered( const GUEST_CPU_HANDLE gcpu, UINT64* base,
                             UINT32* limit, VMCS_LEVEL level);
void   gcpu_set_idt_reg_layered( const GUEST_CPU_HANDLE gcpu, UINT64 base,
                             UINT32 limit, VMCS_LEVEL level);
UINT64 gcpu_get_debug_reg_layered( const GUEST_CPU_HANDLE gcpu, VMM_IA32_DEBUG_REGISTERS reg,
                              VMCS_LEVEL level);
void gcpu_set_debug_reg_layered( const GUEST_CPU_HANDLE gcpu, 
			VMM_IA32_DEBUG_REGISTERS reg, UINT64 value, VMCS_LEVEL level);
UINT64 gcpu_get_msr_reg_internal_layered(const GUEST_CPU_HANDLE gcpu,
                              VMM_IA32_MODEL_SPECIFIC_REGISTERS reg, VMCS_LEVEL level);
UINT64 gcpu_get_msr_reg_layered(const GUEST_CPU_HANDLE gcpu,
                              VMM_IA32_MODEL_SPECIFIC_REGISTERS reg, VMCS_LEVEL level);
void   gcpu_set_msr_reg_layered(GUEST_CPU_HANDLE gcpu, 
			VMM_IA32_MODEL_SPECIFIC_REGISTERS reg,
                              UINT64 value, VMCS_LEVEL level);
void gcpu_set_msr_reg_by_index_layered( GUEST_CPU_HANDLE gcpu, UINT32 msr_index,
                              UINT64 value, VMCS_LEVEL level);

UINT64 gcpu_get_msr_reg_by_index_layered(GUEST_CPU_HANDLE gcpu,
                              UINT32 msr_index, VMCS_LEVEL level);

// Get Guest CPU state by VIRTUAL_CPU_ID
// Return NULL if no such guest cpu
GUEST_CPU_HANDLE gcpu_state( const VIRTUAL_CPU_ID* vcpu );

// Get VIRTUAL_CPU_ID by Guest CPU
const VIRTUAL_CPU_ID* guest_vcpu( const GUEST_CPU_HANDLE gcpu );

// Get Guest Handle by Guest CPU
GUEST_HANDLE gcpu_guest_handle( const GUEST_CPU_HANDLE gcpu );

// Context switching
// perform full state save before switching to another guest
void gcpu_swap_out( GUEST_CPU_HANDLE gcpu );

// perform state restore after switching from another guest
void gcpu_swap_in( const GUEST_CPU_HANDLE gcpu );


// Change execution mode - switch to native execution mode
// This function should be called by appropriate VMCALL handler to end
// non-native execution mode.
// Current usage: terminate guest emulation
// Note: arguments arg1, arg2 and arg3 are not used. Added because this
// function is registered as VMCALL handler
VMM_STATUS gcpu_return_to_native_execution( GUEST_CPU_HANDLE gcpu,
                                            ADDRESS*, ADDRESS*, ADDRESS* );

// return TRUE if running in native (non-emulator) mode
BOOLEAN gcpu_is_native_execution( GUEST_CPU_HANDLE gcpu );

// switch to emulator. Should be used only on non-implemented events,
// like hardware task switch.
void gcpu_run_emulator( const GUEST_CPU_HANDLE gcpu );

// Initialize gcpu environment for each VMEXIT
// Must be the first gcpu call in each VMEXIT
void gcpu_vmexit_start( const GUEST_CPU_HANDLE gcpu );

// Resume execution.
// never returns.
void gcpu_resume( GUEST_CPU_HANDLE gcpu );

// Perform single step.
BOOLEAN gcpu_perform_single_step( const GUEST_CPU_HANDLE gcpu );

// Initialize guest CPU
// Should be called only if initial GCPU state is not Wait-For-Sipi
void gcpu_initialize( GUEST_CPU_HANDLE gcpu,
                      const VMM_GUEST_CPU_STARTUP_STATE* initial_state );

UINT32 gcpu_get_interruptibility_state_layered( const GUEST_CPU_HANDLE gcpu,
                         VMCS_LEVEL level);

void gcpu_set_interruptibility_state_layered(const GUEST_CPU_HANDLE gcpu,
                         UINT32 value, VMCS_LEVEL  level);

INLINE UINT32 gcpu_get_interruptibility_state(const GUEST_CPU_HANDLE gcpu) {
    return gcpu_get_interruptibility_state_layered(gcpu, VMCS_MERGED);
}

INLINE void gcpu_set_interruptibility_state(const GUEST_CPU_HANDLE  gcpu, UINT32 value) {
    gcpu_set_interruptibility_state_layered(gcpu, value, VMCS_MERGED);
}

IA32_VMX_VMCS_GUEST_SLEEP_STATE
    gcpu_get_activity_state_layered( const GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level);

void gcpu_set_activity_state_layered( GUEST_CPU_HANDLE gcpu,
                         IA32_VMX_VMCS_GUEST_SLEEP_STATE value, VMCS_LEVEL level);

INLINE
IA32_VMX_VMCS_GUEST_SLEEP_STATE gcpu_get_activity_state( const GUEST_CPU_HANDLE gcpu) {
    return gcpu_get_activity_state_layered(gcpu, VMCS_MERGED);
}

INLINE void gcpu_set_activity_state( GUEST_CPU_HANDLE gcpu,
                         IA32_VMX_VMCS_GUEST_SLEEP_STATE value) {
    gcpu_set_activity_state_layered(gcpu, value, VMCS_MERGED);
}

UINT64 gcpu_get_pending_debug_exceptions_layered(const GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level);

void gcpu_set_pending_debug_exceptions_layered( const GUEST_CPU_HANDLE gcpu,
                         UINT64 value, VMCS_LEVEL level);

void gcpu_set_vmenter_control_layered( const GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level);
#ifdef INCLUDE_UNUSED_CODE
INLINE UINT64 gcpu_get_pending_debug_exceptions( const GUEST_CPU_HANDLE gcpu) {
    return gcpu_get_pending_debug_exceptions_layered(gcpu, VMCS_MERGED);
}
#endif

INLINE void gcpu_set_pending_debug_exceptions(const GUEST_CPU_HANDLE  gcpu, UINT64 value) {
    gcpu_set_pending_debug_exceptions_layered(gcpu, value, VMCS_MERGED);
}

INLINE void gcpu_set_vmenter_control(const GUEST_CPU_HANDLE gcpu) {
    gcpu_set_vmenter_control_layered(gcpu, VMCS_MERGED);
}


// Guest CPU vmexits control
// request vmexits for given guest CPU
// Receives 2 bitmasks:
//    For each 1bit in mask check the corresponding request bit. If request bit
//    is 1 - request the vmexit on this bit change, else - remove the
//    previous request for this bit.


// setup vmexit requests without applying - for guest.c
void gcpu_control_setup_only( GUEST_CPU_HANDLE gcpu, const VMEXIT_CONTROL* request );

// applies what was requested before
void gcpu_control_apply_only( GUEST_CPU_HANDLE gcpu );
void gcpu_control2_apply_only( GUEST_CPU_HANDLE gcpu );

// shortcut for single-gcpu change if gcpu is active on current host cpu
INLINE void gcpu_control_setup( GUEST_CPU_HANDLE gcpu, const VMEXIT_CONTROL* request )
{
    gcpu_control_setup_only( gcpu, request );
    gcpu_control_apply_only( gcpu );
}

INLINE void gcpu_control2_setup( GUEST_CPU_HANDLE gcpu, const VMEXIT_CONTROL* request )
{
    gcpu_control_setup_only( gcpu, request );
    gcpu_control2_apply_only( gcpu );
}

// get VMCS object to work directly
VMCS_OBJECT* gcpu_get_vmcs( GUEST_CPU_HANDLE gcpu );
VMCS_HIERARCHY * gcpu_get_vmcs_hierarchy( GUEST_CPU_HANDLE  gcpu );
VMCS_OBJECT* gcpu_get_vmcs_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level );
BOOLEAN gcpu_is_vmcs_layered( GUEST_CPU_HANDLE  gcpu);


#ifdef INCLUDE_UNUSED_CODE
BOOLEAN gcpu_is_merge_required(GUEST_CPU_HANDLE  gcpu);
void gcpu_configure_merge_required(GUEST_CPU_HANDLE  gcpu, BOOLEAN required);
void gcpu_do_use_host_page_tables(GUEST_CPU_HANDLE gcpu, BOOLEAN use);
#endif

BOOLEAN gcpu_uses_host_page_tables(GUEST_CPU_HANDLE gcpu);

// check if emulator runs as a guest, and if so do emulator processing
// returns TRUE if interrupt was processed
BOOLEAN gcpu_process_interrupt( VECTOR_ID vector_id );

// convert GVA to GPA (wrapper for page walker)
BOOLEAN gcpu_gva_to_gpa(GUEST_CPU_HANDLE gcpu, GVA gva, GPA* gpa);

// convert GVA to HVA
BOOLEAN gcpu_gva_to_hva(GUEST_CPU_HANDLE gcpu, GVA gva, HVA* hva);

// Private API for guest.c
//
void gcpu_manager_init(UINT16 host_cpu_count);
GUEST_CPU_HANDLE gcpu_allocate(VIRTUAL_CPU_ID vcpu, GUEST_HANDLE guest);
void gcpu_physical_memory_modified(GUEST_CPU_HANDLE gcpu);

// MSRs to be autoswapped at each vmexit/vmentry
// guest MSRs that are saved automatically at vmexit and loaded at vmentry
typedef struct _VMM_AUTOSWAP_MSRS {
    IA32_VMX_MSR_ENTRY  efer;
} VMM_AUTOSWAP_MSRS;

#define VMM_AUTOSWAP_MSRS_COUNT (sizeof(VMM_AUTOSWAP_MSRS) / sizeof(IA32_VMX_MSR_ENTRY))
struct _EMULATOR_STATE * gcpu_emulator_handle( GUEST_CPU_HANDLE gcpu );


GUEST_LEVEL_ENUM gcpu_get_guest_level(GUEST_CPU_HANDLE gcpu);
#ifdef INCLUDE_UNUSED_CODE
void gcpu_set_guest_level(GUEST_CPU_HANDLE gcpu, GUEST_LEVEL_ENUM level);
GUEST_LEVEL_ENUM gcpu_get_next_guest_level(GUEST_CPU_HANDLE gcpu);
#endif
void gcpu_set_next_guest_level(GUEST_CPU_HANDLE gcpu, GUEST_LEVEL_ENUM level);
#ifdef INCLUDE_UNUSED_CODE
UINT128 gcpu_get_xmm_reg( const GUEST_CPU_HANDLE gcpu, VMM_IA32_XMM_REGISTERS reg );
#endif
void   gcpu_set_xmm_reg( GUEST_CPU_HANDLE gcpu, VMM_IA32_XMM_REGISTERS reg, UINT128 value );


// get/set native GP regardless of exection mode (emulator/native/etc)
// if guest is not running natively (ex. under emulator) this will return/set
// emulator registers and not real guest registers
INLINE UINT64 gcpu_get_native_gp_reg( const GUEST_CPU_HANDLE gcpu,
                        VMM_IA32_GP_REGISTERS  reg ) {
    return gcpu_get_native_gp_reg_layered( gcpu, reg, VMCS_MERGED );
}

INLINE void   gcpu_set_native_gp_reg( GUEST_CPU_HANDLE gcpu,
                        VMM_IA32_GP_REGISTERS reg, UINT64 value ) {
    gcpu_set_native_gp_reg_layered(gcpu, reg, value, VMCS_MERGED);
}


// Get/Set register value
#ifdef INCLUDE_UNUSED_CODE
INLINE void gcpu_get_all_gp_regs( const GUEST_CPU_HANDLE gcpu, UINT64 *GPreg ) {
    gcpu_get_all_gp_regs_internal(gcpu, GPreg);
}
#endif
INLINE UINT64 gcpu_get_gp_reg( const GUEST_CPU_HANDLE  gcpu, VMM_IA32_GP_REGISTERS reg ) {
    return gcpu_get_gp_reg_layered(gcpu, reg, VMCS_MERGED);
}

INLINE void gcpu_set_all_gp_regs( GUEST_CPU_HANDLE gcpu, UINT64 *GPReg ) {
    gcpu_set_all_gp_regs_internal(gcpu, GPReg);
}

INLINE void gcpu_set_gp_reg( GUEST_CPU_HANDLE gcpu,
                        VMM_IA32_GP_REGISTERS reg, UINT64 value ) {
    gcpu_set_gp_reg_layered(gcpu, reg, value, VMCS_MERGED);
}

// all result pointers are optional
INLINE void gcpu_get_segment_reg( const GUEST_CPU_HANDLE gcpu,
                VMM_IA32_SEGMENT_REGISTERS reg, UINT16* selector, UINT64* base,
                UINT32* limit, UINT32* attributes ) {
    gcpu_get_segment_reg_layered(gcpu, reg, selector, base, limit, attributes, VMCS_MERGED);
}

INLINE void gcpu_set_segment_reg( GUEST_CPU_HANDLE gcpu, VMM_IA32_SEGMENT_REGISTERS reg,
                          UINT16 selector, UINT64 base, UINT32 limit, UINT32 attributes ) {
    gcpu_set_segment_reg_layered(gcpu, reg, selector, base, limit, attributes, VMCS_MERGED);
}

INLINE UINT64 gcpu_get_control_reg( const GUEST_CPU_HANDLE gcpu,
                          VMM_IA32_CONTROL_REGISTERS reg ) {
    return gcpu_get_control_reg_layered(gcpu, reg, VMCS_MERGED);
}

INLINE void   gcpu_set_control_reg( GUEST_CPU_HANDLE gcpu,
                          VMM_IA32_CONTROL_REGISTERS reg, UINT64 value ) {
    gcpu_set_control_reg_layered(gcpu, reg, value, VMCS_MERGED);
}

// special case of CR registers - some bits of CR0 and CR4 may be overridden by
// VMM, so that guest will see not real values
// all other registers return the same value as gcpu_get_control_reg()
// Valid for CR0, CR3, CR4
INLINE UINT64 gcpu_get_guest_visible_control_reg( const GUEST_CPU_HANDLE gcpu, 
                        VMM_IA32_CONTROL_REGISTERS reg ) {
    return gcpu_get_guest_visible_control_reg_layered(gcpu, reg, VMCS_MERGED);
}

// valid only for CR0, CR3 and CR4
// Contains faked values for the bits that have 1 in the mask. Those bits are
// returned to the guest upon reading the register instead real bits
INLINE void gcpu_set_guest_visible_control_reg( const GUEST_CPU_HANDLE gcpu,
                          VMM_IA32_CONTROL_REGISTERS reg, UINT64 value ) {
     gcpu_set_guest_visible_control_reg_layered(gcpu, reg, value, VMCS_MERGED);
}
#ifdef INCLUDE_UNUSED_CODE
INLINE void   gcpu_get_ldt_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64* base, UINT32* limit ) {
    gcpu_get_ldt_reg_layered(gcpu, base, limit, VMCS_MERGED);
}
INLINE void   gcpu_set_ldt_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64 base, UINT32 limit ) {
    gcpu_set_ldt_reg_layered(gcpu, base, limit, VMCS_MERGED);
}
INLINE void   gcpu_get_tr_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64* base, UINT32* limit ) {
    gcpu_get_tr_reg_layered(gcpu, base, limit, VMCS_MERGED);
}

INLINE void   gcpu_set_tr_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64 base, UINT32 limit ) {
    gcpu_set_tr_reg_layered(gcpu, base, limit, VMCS_MERGED);
}
#endif

// all result pointers are optional
INLINE void   gcpu_get_gdt_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64* base, UINT32* limit ) {
    gcpu_get_gdt_reg_layered(gcpu, base, limit, VMCS_MERGED);
}

INLINE void   gcpu_set_gdt_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64  base, UINT32  limit ) {
    gcpu_set_gdt_reg_layered(gcpu, base, limit, VMCS_MERGED);
}

void gcpu_skip_guest_instruction( GUEST_CPU_HANDLE gcpu );

// all result pointers are optional
INLINE void   gcpu_get_idt_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64* base, UINT32* limit ) {
    gcpu_get_idt_reg_layered(gcpu, base, limit, VMCS_MERGED);
}

INLINE void   gcpu_set_idt_reg( const GUEST_CPU_HANDLE  gcpu,
                         UINT64  base, UINT32  limit ) {
    gcpu_set_idt_reg_layered(gcpu, base, limit, VMCS_MERGED);
}

INLINE UINT64 gcpu_get_debug_reg( const GUEST_CPU_HANDLE gcpu,
                         VMM_IA32_DEBUG_REGISTERS reg )
    { return gcpu_get_debug_reg_layered(gcpu, reg, VMCS_MERGED); }

INLINE void gcpu_set_debug_reg( const GUEST_CPU_HANDLE  gcpu,
                         VMM_IA32_DEBUG_REGISTERS reg, UINT64  value ) {
    gcpu_set_debug_reg_layered(gcpu, reg, value, VMCS_MERGED);
}

INLINE UINT64 gcpu_get_msr_reg( const GUEST_CPU_HANDLE gcpu,
                         VMM_IA32_MODEL_SPECIFIC_REGISTERS reg ) {
    return gcpu_get_msr_reg_layered(gcpu, reg, VMCS_MERGED);
}

INLINE void   gcpu_set_msr_reg( GUEST_CPU_HANDLE gcpu,
                         VMM_IA32_MODEL_SPECIFIC_REGISTERS reg, UINT64  value ) {
    gcpu_set_msr_reg_layered(gcpu, reg, value, VMCS_MERGED);
}

INLINE void gcpu_set_msr_reg_by_index( GUEST_CPU_HANDLE gcpu,
	UINT32 msr_index, UINT64 value)
{
    gcpu_set_msr_reg_by_index_layered(gcpu, msr_index, value, VMCS_MERGED);
}

INLINE UINT64 gcpu_get_msr_reg_by_index(GUEST_CPU_HANDLE gcpu, UINT32 msr_index)
{
    return gcpu_get_msr_reg_by_index_layered(gcpu, msr_index, VMCS_MERGED);
}

typedef GUEST_CPU_HANDLE (*GCPU_RESUME_FUNC)(GUEST_CPU_HANDLE);

#ifdef INCLUDE_UNUSED_CODE
void gcpu_assign_resume_func(GUEST_CPU_HANDLE gcpu, GCPU_RESUME_FUNC resume_func);
void gcpu_install_vmexit_func(GUEST_CPU_HANDLE gcpu, GCPU_VMEXIT_FUNC vmexit_func);
UINT64 gcpu_read_get_32_bit_pdpt_entry(GUEST_CPU_HANDLE gcpu, UINT32 entry_index);
#endif

typedef GUEST_CPU_HANDLE (*GCPU_VMEXIT_FUNC)(GUEST_CPU_HANDLE gcpu, UINT32 reason);
GUEST_CPU_HANDLE gcpu_call_vmexit_function(GUEST_CPU_HANDLE gcpu, UINT32 reason);
GUEST_CPU_HANDLE gcpu_perform_split_merge (GUEST_CPU_HANDLE gcpu);

// call only if gcpu_perform_split_merge() is not used!!!
typedef struct _MERGE_ORIG_VALUES {
    UINT64 visible_cr0;
    UINT64 visible_cr3;
    UINT64 visible_cr4;
    UINT64 EFER;
} MERGE_ORIG_VALUES;

void gcpu_raise_proper_events_after_level_change(GUEST_CPU_HANDLE gcpu, 
                    MERGE_ORIG_VALUES *optional);
BOOLEAN gcpu_get_32_bit_pdpt(GUEST_CPU_HANDLE gcpu, void* pdpt_ptr);
void gcpu_change_level0_vmexit_msr_load_list(GUEST_CPU_HANDLE gcpu, 
                    IA32_VMX_MSR_ENTRY* msr_list, UINT32 msr_list_count);
BOOLEAN gcpu_is_mode_native(GUEST_CPU_HANDLE gcpu);
void gcpu_load_segment_reg_from_gdt( GUEST_CPU_HANDLE guest_cpu,
    UINT64 gdt_base, UINT16 selector, VMM_IA32_SEGMENT_REGISTERS reg_id);
void *gcpu_get_vmdb(GUEST_CPU_HANDLE gcpu);
void gcpu_set_vmdb(GUEST_CPU_HANDLE gcpu, void * vmdb);
void * gcpu_get_timer(GUEST_CPU_HANDLE gcpu);
void gcpu_assign_timer(GUEST_CPU_HANDLE gcpu, void *timer);
#endif // _GUEST_CPU_H_

