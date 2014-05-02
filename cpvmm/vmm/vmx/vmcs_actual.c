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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMCS_ACTUAL_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMCS_ACTUAL_C, __condition)
#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "memory_allocator.h"
#include "cache64.h"
#include "vmm_objects.h"
#include "guest.h"
#include "gpm_api.h"
#include "vmcs_init.h"
#include "hw_vmx_utils.h"
#include "hw_utils.h"
#include "hw_interlocked.h"
#include "gdt.h"
#include "libc.h"
#include "vmcs_actual.h"
#include "vmcs_internal.h"
#include "vmx_nmi.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define UPDATE_SUCCEEDED    0
#define UPDATE_FINISHED     1
#define UPDATE_FAILED       2

typedef enum _FLAGS {
    LAUNCHED_FLAG = 0,      // was already launched
    ACTIVATED_FLAG,         // is set curent on the owning CPU
    NEVER_ACTIVATED_FLAG    // is in the init stage
} FLAGS;

#define FIELD_IS_HW_WRITABLE(__access) (VMCS_WRITABLE & (__access))
#define NMI_WINDOW_BIT  22

typedef struct _VMCS_ACTUAL_OBJECT {
    struct _VMCS_OBJECT     vmcs_base[1];
    CACHE64_OBJECT      cache;
    ADDRESS             hpa;
    ADDRESS             hva;
    GUEST_CPU_HANDLE    gcpu_owner;
    UINT32              update_status;
    FLAGS               flags;
    CPU_ID              owning_host_cpu; // the VMCS object was launched in this cpu
    UINT8               pad[6];
} VMCS_ACTUAL_OBJECT;

#define CPU_NEVER_USED ((CPU_ID)-1)
#define HW_VMCS_IS_EMPTY ((UINT64)-1)

static const char* g_instr_error_message[] = {
    "VMCS_INSTR_NO_INSTRUCTION_ERROR",                                  // VMxxxxx
    "VMCS_INSTR_VMCALL_IN_ROOT_ERROR",                                  // VMCALL
    "VMCS_INSTR_VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR",                // VMCLEAR
    "VMCS_INSTR_VMCLEAR_WITH_CURRENT_CONTROLLING_PTR_ERROR",            // VMCLEAR
    "VMCS_INSTR_VMLAUNCH_WITH_NON_CLEAR_VMCS_ERROR",                    // VMLAUNCH
    "VMCS_INSTR_VMRESUME_WITH_NON_LAUNCHED_VMCS_ERROR",                 // VMRESUME
    "VMCS_INSTR_VMRESUME_WITH_NON_CHILD_VMCS_ERROR",                    // VMRESUME
    "VMCS_INSTR_VMENTER_BAD_CONTROL_FIELD_ERROR",                       // VMENTER
    "VMCS_INSTR_VMENTER_BAD_MONITOR_STATE_ERROR",                       // VMENTER
    "VMCS_INSTR_VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR",                // VMPTRLD
    "VMCS_INSTR_VMPTRLD_WITH_CURRENT_CONTROLLING_PTR_ERROR",            // VMPTRLD
    "VMCS_INSTR_VMPTRLD_WITH_BAD_REVISION_ID_ERROR",                    // VMPTRLD
    "VMCS_INSTR_VMREAD_OR_VMWRITE_OF_UNSUPPORTED_COMPONENT_ERROR",      // VMREAD
    "VMCS_INSTR_VMWRITE_OF_READ_ONLY_COMPONENT_ERROR",                  // VMWRITE
    "VMCS_INSTR_VMWRITE_INVALID_FIELD_VALUE_ERROR",                     // VMWRITE
    "VMCS_INSTR_VMXON_IN_VMX_ROOT_OPERATION_ERROR",                     // VMXON
    "VMCS_INSTR_VMENTRY_WITH_BAD_OSV_CONTROLLING_VMCS_ERROR",           // VMENTER
    "VMCS_INSTR_VMENTRY_WITH_NON_LAUNCHED_OSV_CONTROLLING_VMCS_ERROR",  // VMENTER
    "VMCS_INSTR_VMENTRY_WITH_NON_ROOT_OSV_CONTROLLING_VMCS_ERROR",      // VMENTER
    "VMCS_INSTR_VMCALL_WITH_NON_CLEAR_VMCS_ERROR",                      // VMCALL
    "VMCS_INSTR_VMCALL_WITH_BAD_VMEXIT_FIELDS_ERROR",                   // VMCALL
    "VMCS_INSTR_VMCALL_WITH_INVALID_MSEG_MSR_ERROR",                    // VMCALL
    "VMCS_INSTR_VMCALL_WITH_INVALID_MSEG_REVISION_ERROR",               // VMCALL
    "VMCS_INSTR_VMXOFF_WITH_CONFIGURED_SMM_MONITOR_ERROR",              // VMXOFF
    "VMCS_INSTR_VMCALL_WITH_BAD_SMM_MONITOR_FEATURES_ERROR",            // VMCALL
    "VMCS_INSTR_RETURN_FROM_SMM_WITH_BAD_VM_EXECUTION_CONTROLS_ERROR",  // Return from SMM
    "VMCS_INSTR_VMENTRY_WITH_EVENTS_BLOCKED_BY_MOV_SS_ERROR",           // VMENTER
    "VMCS_INSTR_BAD_ERROR_CODE",                                        // Bad error code
    "VMCS_INSTR_INVALIDATION_WITH_INVALID_OPERAND"                      // INVEPT, INVVPID
};


static UINT64 vmcs_act_read(const struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id);
static void vmcs_act_write(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, 
                            UINT64 value);
static void vmcs_act_flush_to_cpu(const struct _VMCS_OBJECT *vmcs);
static void vmcs_act_flush_to_memory(struct _VMCS_OBJECT *vmcs);
static BOOLEAN vmcs_act_is_dirty(const struct _VMCS_OBJECT *vmcs);
static GUEST_CPU_HANDLE vmcs_act_get_owner(const struct _VMCS_OBJECT *vmcs);
static void vmcs_act_destroy(struct _VMCS_OBJECT *vmcs);
static void vmcs_act_add_msr_to_vmexit_store_list(struct _VMCS_OBJECT *vmcs, 
                            UINT32 msr_index, UINT64 value);
static void vmcs_act_add_msr_to_vmexit_load_list(struct _VMCS_OBJECT *vmcs, 
                            UINT32 msr_index, UINT64 value);
static void vmcs_act_add_msr_to_vmenter_load_list(struct _VMCS_OBJECT *vmcs, 
                            UINT32 msr_index, UINT64 value);
static void vmcs_act_add_msr_to_vmexit_store_and_vmenter_load_lists(
                        struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
static void vmcs_act_delete_msr_from_vmexit_store_list(struct _VMCS_OBJECT *vmcs, 
                        UINT32 msr_index);
static void vmcs_act_delete_msr_from_vmexit_load_list(struct _VMCS_OBJECT *vmcs, 
                        UINT32 msr_index);
static void vmcs_act_delete_msr_from_vmenter_load_list(struct _VMCS_OBJECT *vmcs, 
                        UINT32 msr_index);
static void vmcs_act_delete_msr_from_vmexit_store_and_vmenter_load_lists(
                        struct _VMCS_OBJECT *vmcs, UINT32 msr_index);

static void vmcs_act_flush_field_to_cpu(UINT32 entry_no, VMCS_ACTUAL_OBJECT *p_vmcs);
static void vmcs_act_flush_nmi_depended_field_to_cpu(VMCS_ACTUAL_OBJECT *p_vmcs, 
                        UINT64 value);
static UINT64 vmcs_act_read_from_hardware(VMCS_ACTUAL_OBJECT *p_vmcs, 
                        VMCS_FIELD field_id);
static void vmcs_act_write_to_hardware(VMCS_ACTUAL_OBJECT *p_vmcs, 
                        VMCS_FIELD field_id, UINT64 value);

static UINT64  temp_replace_vmcs_ptr(UINT64 new_ptr);
static void    restore_previous_vmcs_ptr(UINT64 ptr_to_restore);
static void    error_processing(UINT64 vmcs, HW_VMX_RET_VALUE ret_val,
                              const char* operation, VMCS_FIELD  field);
static BOOLEAN nmi_window[VMM_MAX_CPU_SUPPORTED]; // stores NMI Windows which should be injected per CPU


// JLM:added
extern HW_VMX_RET_VALUE hw_vmx_read_current_vmcs(UINT64 field_id, UINT64 *value );
extern HW_VMX_RET_VALUE hw_vmx_flush_current_vmcs(UINT64 *address);

/*----------------------------------------------------------------------------*
**                              NMI Handling
**  When NMI occured:
**    FS := non zero value        ; mark that NMI occured during VMEXIT
**    nmi_window[cpu-no] := TRUE  ; mark that NMI Window should be injected on next VMENTER
**    spoil transaction status (see below).
**
**  When NMI-Window is set - like ordinar VMCS field
**  When NMI-Window is clear - clear it, but then check FS !=0 and if so, set NMI-Window back
**  When flushing VMCS cache into CPU:
**    do it in transactional way, i.e.
**        set start transaction flage
**        do the job
**        check if succeeded
**        if not repeat
*----------------------------------------------------------------------------*/

INLINE BOOLEAN nmi_is_nmi_occured(void) {
    return (0 != hw_read_fs());
}

INLINE void nmi_window_set(void)
{
    nmi_window[hw_cpu_id()] = TRUE;
}

INLINE void nmi_window_clear(void)
{
    nmi_window[hw_cpu_id()] = FALSE;
    if (nmi_is_nmi_occured()) {
        nmi_window[hw_cpu_id()] = TRUE;
    }
}

INLINE void nmi_remember_occured_nmi(void) {
    hw_write_fs(DATA32_GDT_ENTRY_OFFSET);
    nmi_window_set();
}

INLINE BOOLEAN nmi_window_is_requested(void)
{
    return nmi_is_nmi_occured() || nmi_window[hw_cpu_id()];
}

void vmcs_nmi_handler(struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    UINT64  value;
    VMM_ASSERT(p_vmcs);

    // mark that NMI Window must be set, in case that SW still did not flush VMCSS to hardware
    nmi_remember_occured_nmi();

    // spoil VMCS flush process in case it is in progress
    p_vmcs->update_status = UPDATE_FAILED;

    // write directly into hardware in case that SW already did flush to CPU
    value = vmcs_act_read_from_hardware(p_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    BIT_SET64(value, NMI_WINDOW_BIT);
    vmcs_act_write_to_hardware(p_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS, value);
}

void nmi_window_update_before_vmresume(struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    UINT64 value;

    if(nmi_is_nmi_occured() || nmi_is_pending_this()) {
        VMM_ASSERT(p_vmcs);
        value = vmcs_act_read_from_hardware(p_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
        BIT_SET64(value, NMI_WINDOW_BIT);
        vmcs_act_write_to_hardware(p_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS, value);
        nmi_window_set();
    }
}

void vmcs_write_nmi_window_bit(struct _VMCS_OBJECT *vmcs, BOOLEAN value)
{
    vmcs_update(vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS,
                FALSE == value ? 0 : (UINT64) -1, BIT_VALUE(NMI_WINDOW_BIT));
    if (value)
        nmi_window_set();
    else
        nmi_window_clear();
}


BOOLEAN vmcs_read_nmi_window_bit(struct _VMCS_OBJECT *vmcs)
{
    UINT64 value = vmcs_read(vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS);
    return (0 != BIT_GET64(value, NMI_WINDOW_BIT));
}


struct _VMCS_OBJECT * vmcs_act_create(GUEST_CPU_HANDLE gcpu)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs;

#ifdef JLMDEBUG
    bprint("vmcs_act_create\n");
#endif
    p_vmcs = vmm_malloc(sizeof(*p_vmcs));
    if (NULL == p_vmcs) {
        VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Allocation failed\n", __FUNCTION__);
        return NULL;
    }
    p_vmcs->cache = cache64_create(VMCS_FIELD_COUNT);
    if (NULL == p_vmcs->cache) {
        vmm_mfree(p_vmcs);
        VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Allocation failed\n", __FUNCTION__);
        return NULL;
    }
#ifdef JLMDEBUG
    bprint("about to set vmcs entries in vmcs create\n");
#endif
    p_vmcs->hva = vmcs_hw_allocate_region(&p_vmcs->hpa);    // validate it's ok TBD
    p_vmcs->flags|= NEVER_ACTIVATED_FLAG;
    p_vmcs->owning_host_cpu = CPU_NEVER_USED;
    p_vmcs->gcpu_owner = gcpu;
    p_vmcs->vmcs_base->vmcs_read = vmcs_act_read;
    p_vmcs->vmcs_base->vmcs_write = vmcs_act_write;
    p_vmcs->vmcs_base->vmcs_flush_to_cpu = vmcs_act_flush_to_cpu;
    p_vmcs->vmcs_base->vmcs_flush_to_memory = vmcs_act_flush_to_memory;
    p_vmcs->vmcs_base->vmcs_is_dirty = vmcs_act_is_dirty;
    p_vmcs->vmcs_base->vmcs_get_owner = vmcs_act_get_owner;
    p_vmcs->vmcs_base->vmcs_destroy = vmcs_act_destroy;
    p_vmcs->vmcs_base->vmcs_add_msr_to_vmexit_store_list = 
        vmcs_act_add_msr_to_vmexit_store_list;
    p_vmcs->vmcs_base->vmcs_add_msr_to_vmexit_load_list = 
        vmcs_act_add_msr_to_vmexit_load_list;
    p_vmcs->vmcs_base->vmcs_add_msr_to_vmenter_load_list = 
        vmcs_act_add_msr_to_vmenter_load_list;
    p_vmcs->vmcs_base->vmcs_add_msr_to_vmexit_store_and_vmenter_load_list  = 
        vmcs_act_add_msr_to_vmexit_store_and_vmenter_load_lists;
    p_vmcs->vmcs_base->vmcs_delete_msr_from_vmexit_store_list = 
        vmcs_act_delete_msr_from_vmexit_store_list;
    p_vmcs->vmcs_base->vmcs_delete_msr_from_vmexit_load_list = 
        vmcs_act_delete_msr_from_vmexit_load_list;
    p_vmcs->vmcs_base->vmcs_delete_msr_from_vmenter_load_list = 
        vmcs_act_delete_msr_from_vmenter_load_list;
    p_vmcs->vmcs_base->vmcs_delete_msr_from_vmexit_store_and_vmenter_load_list  = 
        vmcs_act_delete_msr_from_vmexit_store_and_vmenter_load_lists;
    p_vmcs->vmcs_base->level = VMCS_MERGED;
    p_vmcs->vmcs_base->skip_access_checking = FALSE;
    p_vmcs->vmcs_base->signature = VMCS_SIGNATURE;
    vmcs_init_all_msr_lists(p_vmcs->vmcs_base);
    return p_vmcs->vmcs_base;
}


BOOLEAN vmcs_act_is_dirty(const struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    return cache64_is_dirty(p_vmcs->cache);
}

GUEST_CPU_HANDLE vmcs_act_get_owner(const struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    return p_vmcs->gcpu_owner;
}

extern BOOLEAN vmcs_sw_shadow_disable[];
void vmcs_act_write(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, UINT64 value)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    if (!vmcs_sw_shadow_disable[hw_cpu_id()])
        cache64_write(p_vmcs->cache, value, (UINT32 )field_id);
    else
        vmcs_act_write_to_hardware(p_vmcs, field_id, value);
}


UINT64 vmcs_act_read(const struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    UINT64           value;

    VMM_ASSERT(p_vmcs);
    VMM_ASSERT(field_id < VMCS_FIELD_COUNT);
    if (TRUE != cache64_read(p_vmcs->cache, &value, (UINT32) field_id)) {
        // special case - if hw VMCS was never filled, there is nothing to read
        // from HW
        if (p_vmcs->flags&NEVER_ACTIVATED_FLAG) {
            // assume the init was with all 0
            cache64_write(p_vmcs->cache, 0, (UINT32) field_id);
            return 0;
        }
        value = vmcs_act_read_from_hardware(p_vmcs, field_id);
        cache64_write(p_vmcs->cache, value, (UINT32) field_id); // update cache
    }
    return value;
}


UINT64 vmcs_act_read_from_hardware(VMCS_ACTUAL_OBJECT *p_vmcs, VMCS_FIELD field_id)
{
    UINT64           value;
    HW_VMX_RET_VALUE ret_val;
    UINT64           previous_vmcs = 0; // 0 - not replaced
    UINT32           encoding;

    VMM_DEBUG_CODE(
        if ((p_vmcs->owning_host_cpu != CPU_NEVER_USED) && (p_vmcs->owning_host_cpu != hw_cpu_id())) {
            VMM_LOG(mask_anonymous, level_trace,"Trying to access VMCS, used on another CPU\n");
            VMM_DEADLOOP();
        }
    )

    encoding = vmcs_get_field_encoding(field_id, NULL);
    VMM_ASSERT(encoding != VMCS_NO_COMPONENT);
    // if VMCS is not "current" now, make it current temporary
    if (0 == (p_vmcs->flags&ACTIVATED_FLAG)) {
        previous_vmcs = temp_replace_vmcs_ptr(p_vmcs->hpa);
    }
    ret_val = hw_vmx_read_current_vmcs(encoding, &value);
    if (ret_val != HW_VMX_SUCCESS) {
        error_processing(p_vmcs->hpa, ret_val, "hw_vmx_read_current_vmcs", field_id);
    }
    // flush current VMCS if it was never used on this CPU
    if (p_vmcs->owning_host_cpu == CPU_NEVER_USED) {
        ret_val = hw_vmx_flush_current_vmcs(&p_vmcs->hpa);

        if (ret_val != HW_VMX_SUCCESS) {
            error_processing(p_vmcs->hpa, ret_val, "hw_vmx_flush_current_vmcs", VMCS_FIELD_COUNT);
        }
    }
    // restore the previous "current" VMCS
    if (0 != previous_vmcs) {
        restore_previous_vmcs_ptr( previous_vmcs );
    }
    return value;
}


void vmcs_act_write_to_hardware(VMCS_ACTUAL_OBJECT *p_vmcs, VMCS_FIELD field_id, UINT64 value)
{
    HW_VMX_RET_VALUE ret_val;
    UINT32           encoding;
    RW_ACCESS        access_type;

    VMM_DEBUG_CODE(
        if ((p_vmcs->owning_host_cpu != CPU_NEVER_USED) &&
            (p_vmcs->owning_host_cpu != hw_cpu_id()))
        {
            VMM_LOG(mask_anonymous, level_trace,"Trying to access VMCS, used on another CPU\n");
            VMM_DEADLOOP();
        }
    )
    encoding = vmcs_get_field_encoding( field_id, &access_type);
    VMM_ASSERT(encoding != VMCS_NO_COMPONENT);

    if (0 == FIELD_IS_HW_WRITABLE(access_type)) {
        return;
    }
    ret_val = hw_vmx_write_current_vmcs(encoding, value);
    if (ret_val != HW_VMX_SUCCESS) {
        error_processing(p_vmcs->hpa, ret_val, "hw_vmx_write_current_vmcs",
                         field_id);
    }
}


void vmcs_act_flush_to_cpu(const struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;

#ifdef JLMDEBUG
    bprint("vmcs_act_flush_to_cpu\n");
#endif
    VMM_ASSERT((p_vmcs->flags&ACTIVATED_FLAG)!=0);
    VMM_ASSERT(p_vmcs->owning_host_cpu == hw_cpu_id());

    /* in case the guest was re-scheduled, NMI Window is set in other VMCS
    ** To speed the handling up, set NMI-Window in current VMCS if needed.
    */
    if (nmi_window_is_requested()) {
        vmcs_update((struct _VMCS_OBJECT *)vmcs,
            VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS,
            UINT64_ALL_ONES, BIT_VALUE64(NMI_WINDOW_BIT));
    }

#ifdef JLMDEBUG
    bprint("Halfway through vmcs_act_flush_to_cpu\n");
#endif
    if (cache64_is_dirty(p_vmcs->cache)) {
        cache64_flush_dirty(p_vmcs->cache, CACHE_ALL_ENTRIES,
            (CACHE64_FIELD_PROCESS_FUNCTION) vmcs_act_flush_field_to_cpu, p_vmcs);
    }
#ifdef JLMDEBUG
    bprint("vmcs_act_flush_to_cpu, done\n");
#endif
}


void vmcs_act_flush_field_to_cpu(UINT32 field_id, VMCS_ACTUAL_OBJECT *p_vmcs)
{
    UINT64 value;

    if(FALSE == cache64_read(p_vmcs->cache, &value, field_id)) {
        VMM_LOG(mask_anonymous, level_trace,"Read field %d from cache failed.\n", field_id);
        return;
    }
    if (VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS != field_id) {
        vmcs_act_write_to_hardware(p_vmcs, (VMCS_FIELD)field_id, value);
    }
    else {
        vmcs_act_flush_nmi_depended_field_to_cpu(p_vmcs, value);
    }
}


void vmcs_act_flush_nmi_depended_field_to_cpu(VMCS_ACTUAL_OBJECT *p_vmcs, UINT64 value)
{
    BOOLEAN success = FALSE;

    while (FALSE == success) {
        p_vmcs->update_status = UPDATE_SUCCEEDED;
        if (nmi_window_is_requested()) {
            BIT_SET64(value, NMI_WINDOW_BIT);
        }
        vmcs_act_write_to_hardware(p_vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS,
                                    value);
        if (UPDATE_SUCCEEDED == hw_interlocked_compare_exchange(
                                    &p_vmcs->update_status, UPDATE_SUCCEEDED,
                                    UPDATE_FINISHED)) {
            success = TRUE;
        }
        else {
            VMM_DEBUG_CODE( VMM_LOG(mask_anonymous, level_trace,"NMI Occured during update\n"); );
        }
    }
}

void vmcs_act_flush_to_memory(struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    HW_VMX_RET_VALUE ret_val;
    UINT64           previous_vmcs;

    VMM_ASSERT(p_vmcs);
    VMM_ASSERT((p_vmcs->flags&ACTIVATED_FLAG) == 0);

    if (p_vmcs->owning_host_cpu == CPU_NEVER_USED) {
        return;
    }
    VMM_ASSERT(hw_cpu_id() == p_vmcs->owning_host_cpu);
    vmx_vmptrst(&previous_vmcs);

    // make my active temporary
    vmcs_activate(vmcs);

    // flush all modifications from cache to CPU
    vmcs_act_flush_to_cpu(vmcs);

    // now flush from hardware
    ret_val = hw_vmx_flush_current_vmcs(&p_vmcs->hpa);

    if (ret_val != HW_VMX_SUCCESS) {
        error_processing(p_vmcs->hpa, ret_val, "hw_vmx_flush_current_vmcs", VMCS_FIELD_COUNT);
    }
    vmcs_deactivate(vmcs);

    // reset launching field
    p_vmcs->flags&= (UINT16)(~LAUNCHED_FLAG);
    p_vmcs->owning_host_cpu = CPU_NEVER_USED;

    // restore previous
    restore_previous_vmcs_ptr(previous_vmcs);

}


void vmcs_act_destroy(struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);

    vmcs_act_flush_to_memory(vmcs);
    vmcs_destroy_all_msr_lists_internal(vmcs, TRUE);
    cache64_destroy(p_vmcs->cache);
    vmm_mfree((void *) p_vmcs->hva);
}


// Handle temporary VMCS PTR replacements
UINT64 temp_replace_vmcs_ptr( UINT64 new_ptr ) // return previous ptr
{
    HW_VMX_RET_VALUE ret_val;
    UINT64           previous_vmcs;

    vmx_vmptrst(&previous_vmcs);
    ret_val = vmx_vmptrld( &new_ptr );
    if (ret_val != HW_VMX_SUCCESS) {
        error_processing(new_ptr, ret_val, "vmx_vmptrld", VMCS_FIELD_COUNT);
    }
    return previous_vmcs;
}


void restore_previous_vmcs_ptr( UINT64 ptr_to_restore )
{
    HW_VMX_RET_VALUE ret_val;
    UINT64           temp_vmcs_ptr;

    // restore previous VMCS pointer
    if (ptr_to_restore != HW_VMCS_IS_EMPTY) {
        ret_val = vmx_vmptrld( &ptr_to_restore );

        if (ret_val != HW_VMX_SUCCESS) {
            error_processing(ptr_to_restore, ret_val,
                             "vmx_vmptrld", VMCS_FIELD_COUNT);
        }
    }
    else {
        // reset hw VMCS pointer
        vmx_vmptrst( &temp_vmcs_ptr );

        if (temp_vmcs_ptr != HW_VMCS_IS_EMPTY) {
            ret_val = hw_vmx_flush_current_vmcs( &temp_vmcs_ptr );

            if (ret_val != HW_VMX_SUCCESS) {
                error_processing(temp_vmcs_ptr, ret_val, "hw_vmx_flush_current_vmcs",
                                 VMCS_FIELD_COUNT);
            }
        }
    }
}


// Reset all read caching. MUST NOT be called with modifications not flushed to hw
void vmcs_clear_cache( VMCS_OBJECT *obj)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) obj;

    VMM_ASSERT(p_vmcs);
    cache64_invalidate(p_vmcs->cache, CACHE_ALL_ENTRIES);
}


// Activate
void vmcs_activate(VMCS_OBJECT* obj)
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) obj;
    CPU_ID                      this_cpu = hw_cpu_id();
    HW_VMX_RET_VALUE            ret_val;

#ifdef JLMDEBUG
    bprint("vmcs_activate\n");
#endif
    VMM_ASSERT(obj);
    VMM_ASSERT(p_vmcs->hpa);
    VMM_ASSERT((p_vmcs->flags&ACTIVATED_FLAG) == 0);
    VMM_DEBUG_CODE(
        if ((p_vmcs->owning_host_cpu != CPU_NEVER_USED) && 
            (p_vmcs->owning_host_cpu != this_cpu)) {
            VMM_LOG(mask_anonymous, level_trace,"Trying to activate VMCS, used on another CPU\n");
            VMM_DEADLOOP();
        }
    )

    // special case - if VMCS is still in the initialization state (first load)
    // init the hw before activating it
    if (p_vmcs->flags&NEVER_ACTIVATED_FLAG) {
        ret_val = hw_vmx_flush_current_vmcs(&p_vmcs->hpa);
        if (ret_val != HW_VMX_SUCCESS) {
            error_processing(p_vmcs->hpa, ret_val, 
                             "hw_vmx_flush_current_vmcs", VMCS_FIELD_COUNT);
        }
    }
    ret_val = vmx_vmptrld(&p_vmcs->hpa);
    if (ret_val != HW_VMX_SUCCESS) {
        error_processing(p_vmcs->hpa, ret_val, "vmx_vmptrld", VMCS_FIELD_COUNT);
    }
    p_vmcs->owning_host_cpu = this_cpu;
    p_vmcs->flags|= ACTIVATED_FLAG;
    VMM_ASSERT((p_vmcs->flags&ACTIVATED_FLAG) == 1);
    p_vmcs->flags&= (UINT16)(~NEVER_ACTIVATED_FLAG);
}


// Deactivate
void vmcs_deactivate( VMCS_OBJECT* obj )
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) obj;

    VMM_ASSERT(obj);
    VMM_ASSERT(hw_cpu_id() == p_vmcs->owning_host_cpu);
    p_vmcs->flags&= (UINT16)(~ACTIVATED_FLAG);
}

BOOLEAN vmcs_launch_required( const VMCS_OBJECT* obj )
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) obj;
    VMM_ASSERT(p_vmcs);
    return ((p_vmcs->flags&LAUNCHED_FLAG) == 0);
}

void vmcs_set_launched( VMCS_OBJECT* obj )
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) obj;

    VMM_ASSERT(p_vmcs);
    p_vmcs->flags|= LAUNCHED_FLAG;
}

void vmcs_set_launch_required( VMCS_OBJECT* obj )
{
    struct _VMCS_ACTUAL_OBJECT *p_vmcs = (struct _VMCS_ACTUAL_OBJECT *) obj;

    VMM_ASSERT(p_vmcs);
    p_vmcs->flags&= (UINT16)(~LAUNCHED_FLAG);
}


// Error message
VMCS_INSTRUCTION_ERROR vmcs_last_instruction_error_code(const VMCS_OBJECT* obj,
                                const char** error_message)
{
    UINT32 err = (UINT32)vmcs_read( obj, VMCS_EXIT_INFO_INSTRUCTION_ERROR_CODE );

    if (error_message) {
        *error_message = (err <= VMCS_INSTR_BAD_ERROR_CODE) ?
            g_instr_error_message[err] : "UNKNOWN VMCS_EXIT_INFO_INSTRUCTION_ERROR_CODE";
    }
    return (VMCS_INSTRUCTION_ERROR)err;
}


#pragma warning( push )
#pragma warning( disable : 4100 )
void error_processing(UINT64 vmcs, HW_VMX_RET_VALUE ret_val,
                      const char* operation, VMCS_FIELD  field)
{
    const char* error_message = 0;
    UINT64      err = 0;
    HW_VMX_RET_VALUE my_err;

    switch (ret_val) {
        case HW_VMX_SUCCESS:
            return;
        case HW_VMX_FAILED_WITH_STATUS:
            my_err = hw_vmx_read_current_vmcs(
                VM_EXIT_INFO_INSTRUCTION_ERROR_CODE,   // use hard-coded encoding
                &err);

            if (my_err == HW_VMX_SUCCESS) {
                error_message = g_instr_error_message[(UINT32)err];
                break;
            }
            // fall through
        case HW_VMX_FAILED:
        default:
            error_message = "operation FAILED";
    }
    if (field == VMCS_FIELD_COUNT) {
#ifdef JLMDEBUG
        bprint("%s ( %p ) failed with the error: %s\n", operation, vmcs,
                error_message ? error_message : "unknown error");
#endif
#if 0
        VMM_LOG(mask_anonymous, level_trace,"%s( %P ) failed with the error: %s\n",
                 operation, vmcs, error_message ? error_message : "unknown error");
#endif
    }
    else {
#ifdef JLMDEBUG
        bprint("%s( %p, %s ) failed with the error: %s\n", operation, vmcs,
                vmcs_get_field_name(field),
                error_message ? error_message : "unknown error");
#endif
#if 0
        VMM_LOG(mask_anonymous, level_trace,"%s( %P, %s ) failed with the error: %s\n",
                 operation, vmcs, vmcs_get_field_name(field),
                 error_message ? error_message : "unknown error");
#endif
    }


#ifdef JLMDEBUG
    LOOP_FOREVER
#endif
    VMM_DEADLOOP();
    return;
}
#pragma warning( pop )

static void vmcs_act_add_msr_to_vmexit_store_list(struct _VMCS_OBJECT *vmcs, 
                        UINT32 msr_index, UINT64 value)
{
    vmcs_add_msr_to_vmexit_store_list_internal(vmcs, msr_index, value, TRUE);
}

static void vmcs_act_add_msr_to_vmexit_load_list(struct _VMCS_OBJECT *vmcs, 
                        UINT32 msr_index, UINT64 value)
{
    vmcs_add_msr_to_vmexit_load_list_internal(vmcs, msr_index, value, TRUE);
}

static void vmcs_act_add_msr_to_vmenter_load_list(struct _VMCS_OBJECT *vmcs, 
                        UINT32 msr_index, UINT64 value)
{
    vmcs_add_msr_to_vmenter_load_list_internal(vmcs, msr_index, value, TRUE);
}

static void vmcs_act_add_msr_to_vmexit_store_and_vmenter_load_lists(
            struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value)
{
    vmcs_add_msr_to_vmexit_store_and_vmenter_load_lists_internal(vmcs, msr_index, 
                                            value, TRUE);
}

static void vmcs_act_delete_msr_from_vmexit_store_list(struct _VMCS_OBJECT *vmcs, 
            UINT32 msr_index)
{
    vmcs_delete_msr_from_vmexit_store_list_internal(vmcs, msr_index, TRUE);
}

static void vmcs_act_delete_msr_from_vmexit_load_list(struct _VMCS_OBJECT *vmcs, 
            UINT32 msr_index)
{
    vmcs_delete_msr_from_vmexit_load_list_internal(vmcs, msr_index, TRUE);
}

static void vmcs_act_delete_msr_from_vmenter_load_list(struct _VMCS_OBJECT *vmcs, 
            UINT32 msr_index)
{
    vmcs_delete_msr_from_vmenter_load_list_internal(vmcs, msr_index, TRUE);
}

static void vmcs_act_delete_msr_from_vmexit_store_and_vmenter_load_lists(
            struct _VMCS_OBJECT *vmcs, UINT32 msr_index)
{
    vmcs_delete_msr_from_vmexit_store_and_vmenter_load_lists_internal(vmcs, 
            msr_index, TRUE);
}

