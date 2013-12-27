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

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#ifndef _VMCS_API_H_
#define _VMCS_API_H_

#include "vmm_dbg.h"
#include "vmm_objects.h"
#include "memory_allocator.h"

#define VMCS_INVALID_ADDRESS    (ADDRESS)(-1)   // means that the address is invalid


// VMCS fields
typedef enum _VMCS_FIELD {
    VMCS_VPID                           = 0,
    VMCS_EPTP_INDEX,
    VMCS_CONTROL_VECTOR_PIN_EVENTS,
    VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS, // Special case - NmiWindow cannot be updated
                                          // using this value. Use special APIs to update
                                          // NmiWindow setting
    VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS,
    VMCS_EXCEPTION_BITMAP,
    VMCS_CR3_TARGET_COUNT,
    VMCS_CR0_MASK,
    VMCS_CR4_MASK,
    VMCS_CR0_READ_SHADOW,
    VMCS_CR4_READ_SHADOW,
    VMCS_PAGE_FAULT_ERROR_CODE_MASK,
    VMCS_PAGE_FAULT_ERROR_CODE_MATCH,
    VMCS_EXIT_CONTROL_VECTOR,
    VMCS_EXIT_MSR_STORE_COUNT,
    VMCS_EXIT_MSR_LOAD_COUNT,
    VMCS_ENTER_CONTROL_VECTOR,
    VMCS_ENTER_INTERRUPT_INFO,
    VMCS_ENTER_EXCEPTION_ERROR_CODE,
    VMCS_ENTER_INSTRUCTION_LENGTH,
    VMCS_ENTER_MSR_LOAD_COUNT,
    VMCS_IO_BITMAP_ADDRESS_A,
    VMCS_IO_BITMAP_ADDRESS_B,
    VMCS_MSR_BITMAP_ADDRESS,
    VMCS_EXIT_MSR_STORE_ADDRESS,
    VMCS_EXIT_MSR_LOAD_ADDRESS,
    VMCS_ENTER_MSR_LOAD_ADDRESS,
    VMCS_OSV_CONTROLLING_VMCS_ADDRESS,
    VMCS_TSC_OFFSET,
    VMCS_EXIT_INFO_GUEST_PHYSICAL_ADDRESS,
    VMCS_EXIT_INFO_INSTRUCTION_ERROR_CODE,
    VMCS_EXIT_INFO_REASON,
    VMCS_EXIT_INFO_EXCEPTION_INFO,
    VMCS_EXIT_INFO_EXCEPTION_ERROR_CODE,
    VMCS_EXIT_INFO_IDT_VECTORING,
    VMCS_EXIT_INFO_IDT_VECTORING_ERROR_CODE,
    VMCS_EXIT_INFO_INSTRUCTION_LENGTH,
    VMCS_EXIT_INFO_INSTRUCTION_INFO,
    VMCS_EXIT_INFO_QUALIFICATION,
    VMCS_EXIT_INFO_IO_RCX,
    VMCS_EXIT_INFO_IO_RSI,
    VMCS_EXIT_INFO_IO_RDI,
    VMCS_EXIT_INFO_IO_RIP,
    VMCS_EXIT_INFO_GUEST_LINEAR_ADDRESS,
    VMCS_VIRTUAL_APIC_ADDRESS,
    VMCS_APIC_ACCESS_ADDRESS,
    VMCS_EXIT_TPR_THRESHOLD,
    VMCS_EPTP_ADDRESS,
    VMCS_PREEMPTION_TIMER,
    VMCS_GUEST_CR0,
    VMCS_GUEST_CR3,
    VMCS_GUEST_CR4,
    VMCS_GUEST_DR7,
    VMCS_GUEST_ES_SELECTOR,
    VMCS_GUEST_ES_BASE,
    VMCS_GUEST_ES_LIMIT,
    VMCS_GUEST_ES_AR,
    VMCS_GUEST_CS_SELECTOR,
    VMCS_GUEST_CS_BASE,
    VMCS_GUEST_CS_LIMIT,
    VMCS_GUEST_CS_AR,
    VMCS_GUEST_SS_SELECTOR,
    VMCS_GUEST_SS_BASE,
    VMCS_GUEST_SS_LIMIT,
    VMCS_GUEST_SS_AR,
    VMCS_GUEST_DS_SELECTOR,
    VMCS_GUEST_DS_BASE,
    VMCS_GUEST_DS_LIMIT,
    VMCS_GUEST_DS_AR,
    VMCS_GUEST_FS_SELECTOR,
    VMCS_GUEST_FS_BASE,
    VMCS_GUEST_FS_LIMIT,
    VMCS_GUEST_FS_AR,
    VMCS_GUEST_GS_SELECTOR,
    VMCS_GUEST_GS_BASE,
    VMCS_GUEST_GS_LIMIT,
    VMCS_GUEST_GS_AR,
    VMCS_GUEST_LDTR_SELECTOR,
    VMCS_GUEST_LDTR_BASE,
    VMCS_GUEST_LDTR_LIMIT,
    VMCS_GUEST_LDTR_AR,
    VMCS_GUEST_TR_SELECTOR,
    VMCS_GUEST_TR_BASE,
    VMCS_GUEST_TR_LIMIT,
    VMCS_GUEST_TR_AR,
    VMCS_GUEST_GDTR_BASE,
    VMCS_GUEST_GDTR_LIMIT,
    VMCS_GUEST_IDTR_BASE,
    VMCS_GUEST_IDTR_LIMIT,
    VMCS_GUEST_RSP,
    VMCS_GUEST_RIP,
    VMCS_GUEST_RFLAGS,
    VMCS_GUEST_PEND_DBE,
    VMCS_GUEST_WORKING_VMCS_PTR,
    VMCS_GUEST_DEBUG_CONTROL,
    VMCS_GUEST_INTERRUPTIBILITY,
    VMCS_GUEST_SLEEP_STATE,
    VMCS_GUEST_SMBASE,
    VMCS_GUEST_SYSENTER_CS,
    VMCS_GUEST_SYSENTER_ESP,
    VMCS_GUEST_SYSENTER_EIP,
    VMCS_GUEST_PAT,
    VMCS_GUEST_EFER,
    VMCS_GUEST_IA32_PERF_GLOBAL_CTRL,
    VMCS_GUEST_PDPTR0,
    VMCS_GUEST_PDPTR1,
    VMCS_GUEST_PDPTR2,
    VMCS_GUEST_PDPTR3,
    VMCS_HOST_CR0,
    VMCS_HOST_CR3,
    VMCS_HOST_CR4,
    VMCS_HOST_ES_SELECTOR,
    VMCS_HOST_CS_SELECTOR,
    VMCS_HOST_SS_SELECTOR,
    VMCS_HOST_DS_SELECTOR,
    VMCS_HOST_FS_SELECTOR,
    VMCS_HOST_FS_BASE,
    VMCS_HOST_GS_SELECTOR,
    VMCS_HOST_GS_BASE,
    VMCS_HOST_TR_SELECTOR,
    VMCS_HOST_TR_BASE,
    VMCS_HOST_GDTR_BASE,
    VMCS_HOST_IDTR_BASE,
    VMCS_HOST_RSP,
    VMCS_HOST_RIP,
    VMCS_HOST_SYSENTER_CS,
    VMCS_HOST_SYSENTER_ESP,
    VMCS_HOST_SYSENTER_EIP,
    VMCS_HOST_PAT,
    VMCS_HOST_EFER,
    VMCS_HOST_IA32_PERF_GLOBAL_CTRL,
    VMCS_CR3_TARGET_VALUE_0,
    VMCS_CR3_TARGET_VALUE_1,
    VMCS_CR3_TARGET_VALUE_2,
    VMCS_CR3_TARGET_VALUE_3,
#ifdef FAST_VIEW_SWITCH
    VMCS_VMFUNC_CONTROL,
    VMCS_VMFUNC_EPTP_LIST_ADDRESS,
#endif
    VMCS_VE_INFO_ADDRESS,

    // last
    VMCS_FIELD_COUNT
} VMCS_FIELD;

#define VMCS_CR3_TARGET_VALUE(__x) (VMCS_CR3_TARGET_VALUE_0 + (__x))


#define VMCS_NOT_EXISTS         0
#define VMCS_READABLE           1
#define VMCS_WRITABLE           2
#define VMCS_WRITABLE_IN_CACHE  4



#define VMCS_SIGNATURE 0x12345678

typedef enum {
    VMCS_LEVEL_0,   // VMCS of current level-1 VMM
    VMCS_LEVEL_1,   // VMCS of level-0 VMM. NULL means no layering
    VMCS_MERGED,    // merged VMCS; when no layering, identical to vmcs0
    VMCS_LEVELS
} VMCS_LEVEL;


struct _VMCS_OBJECT {
    UINT32  signature;
    UINT32  level;
    BOOLEAN skip_access_checking;
    UINT32  max_num_of_vmexit_store_msrs;
    UINT32  max_num_of_vmexit_load_msrs;
    UINT32  max_num_of_vmenter_load_msrs;
    UINT64  (*vmcs_read)(const struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id);
    void    (*vmcs_write)(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, UINT64 value);
    void    (*vmcs_flush_to_cpu)(const struct _VMCS_OBJECT *vmcs);
    void    (*vmcs_flush_to_memory)(struct _VMCS_OBJECT *vmcs);
    BOOLEAN (*vmcs_is_dirty)(const struct _VMCS_OBJECT *vmcs);
    GUEST_CPU_HANDLE (*vmcs_get_owner)(const struct _VMCS_OBJECT *vmcs);
    void    (*vmcs_destroy)(struct _VMCS_OBJECT *vmcs);
    void    (*vmcs_add_msr_to_vmexit_store_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
    void    (*vmcs_add_msr_to_vmexit_load_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
    void    (*vmcs_add_msr_to_vmenter_load_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
    void    (*vmcs_add_msr_to_vmexit_store_and_vmenter_load_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
    void    (*vmcs_delete_msr_from_vmexit_store_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);
    void    (*vmcs_delete_msr_from_vmexit_load_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);
    void    (*vmcs_delete_msr_from_vmenter_load_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);
    void    (*vmcs_delete_msr_from_vmexit_store_and_vmenter_load_list)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);
};

void    vmcs_copy(struct _VMCS_OBJECT *vmcs_dst, const struct _VMCS_OBJECT *vmcs_src);
void    vmcs_write(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, UINT64 value);
void    vmcs_write_nocheck(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, UINT64 value);
UINT64  vmcs_read(const struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id);
BOOLEAN vmcs_field_is_supported(VMCS_FIELD field_id);


INLINE void vmcs_flush_to_cpu(const struct _VMCS_OBJECT *vmcs) {
    vmcs->vmcs_flush_to_cpu(vmcs);
}

INLINE void vmcs_flush_to_memory(struct _VMCS_OBJECT *vmcs) {
    vmcs->vmcs_flush_to_memory(vmcs);
}
INLINE void vmcs_clear_dirty(const struct _VMCS_OBJECT *vmcs) {
    vmcs->vmcs_flush_to_cpu(vmcs);
}

INLINE BOOLEAN vmcs_is_dirty(const struct _VMCS_OBJECT *vmcs) {
    return vmcs->vmcs_is_dirty(vmcs);
}

INLINE GUEST_CPU_HANDLE vmcs_get_owner(const struct _VMCS_OBJECT *vmcs) {
    return vmcs->vmcs_get_owner(vmcs);
}
INLINE void vmcs_destroy(struct _VMCS_OBJECT *vmcs) {
    vmcs->vmcs_destroy(vmcs);
    vmm_mfree(vmcs);
}

INLINE VMCS_LEVEL vmcs_get_level(struct _VMCS_OBJECT *vmcs) {
    return (VMCS_LEVEL) vmcs->level;
}

#ifdef INCLUDE_DEAD_CODE
INLINE BOOLEAN vmcs_is_vmcs(struct _VMCS_OBJECT *vmcs) {
    return VMCS_SIGNATURE == vmcs->signature;
}
INLINE UINT32 vmcs_get_storage_size(void) {
    return sizeof(UINT64) * VMCS_FIELD_COUNT;
}
#endif

void vmcs_init_all_msr_lists(struct _VMCS_OBJECT* vmcs);

INLINE void vmcs_add_msr_to_vmexit_store_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value) {
    vmcs->vmcs_add_msr_to_vmexit_store_list(vmcs, msr_index, value);
}
INLINE void vmcs_add_msr_to_vmexit_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value) {
    vmcs->vmcs_add_msr_to_vmexit_load_list(vmcs, msr_index, value);
}
INLINE void vmcs_add_msr_to_vmenter_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value) {
    vmcs->vmcs_add_msr_to_vmenter_load_list(vmcs, msr_index, value);
}

INLINE void vmcs_add_msr_to_vmexit_store_and_vmenter_load_lists(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value) {
    vmcs->vmcs_add_msr_to_vmexit_store_and_vmenter_load_list(vmcs, msr_index, value);
}
#ifdef ENABLE_LAYERING
INLINE void vmcs_delete_msr_from_vmexit_store_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index) {
    vmcs->vmcs_delete_msr_from_vmexit_store_list(vmcs, msr_index);
}

INLINE void vmcs_delete_msr_from_vmexit_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index) {
    vmcs->vmcs_delete_msr_from_vmexit_load_list(vmcs, msr_index);
}

INLINE void vmcs_delete_msr_from_vmenter_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index) {
    vmcs->vmcs_delete_msr_from_vmenter_load_list(vmcs, msr_index);
}

INLINE void vmcs_delete_msr_from_vmexit_store_and_vmenter_load_lists(struct _VMCS_OBJECT *vmcs, UINT32 msr_index) {
    vmcs->vmcs_delete_msr_from_vmexit_store_and_vmenter_load_list(vmcs, msr_index);
}
#endif

void vmcs_assign_vmexit_msr_load_list(struct _VMCS_OBJECT* vmcs,
                                      UINT64 address_value,
                                      UINT64 count_value);

void vmcs_assign_vmexit_msr_load_list(struct _VMCS_OBJECT* vmcs,
                                      UINT64 address_value,
                                      UINT64 count_value);
INLINE void vmcs_clear_vmexit_store_list(struct _VMCS_OBJECT* vmcs) {
    vmcs_write(vmcs, VMCS_EXIT_MSR_STORE_COUNT, 0);
}

INLINE void vmcs_clear_vmexit_load_list(struct _VMCS_OBJECT* vmcs) {
    vmcs_write(vmcs, VMCS_EXIT_MSR_LOAD_COUNT, 0);
}

INLINE void vmcs_clear_vmenter_load_list(struct _VMCS_OBJECT* vmcs) {
    vmcs_write(vmcs, VMCS_ENTER_MSR_LOAD_COUNT, 0);
}

void   vmcs_store(struct _VMCS_OBJECT *vmcs, UINT64 *buffer);
void   vmcs_load(struct _VMCS_OBJECT *vmcs, UINT64 *buffer);
UINT32 vmcs_get_field_encoding(VMCS_FIELD field_id, RW_ACCESS *p_access);
void   vmcs_update(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, UINT64 value, UINT64 bits_to_update);
void   vmcs_manager_init(void);

// is_HIGH_part is TRUE if encodign is for high part only of the VMCS field
VMCS_FIELD vmcs_get_field_id_by_encoding( UINT32 encoding, OPTIONAL BOOLEAN* is_HIGH_part );

BOOLEAN vmcs_is_msr_in_vmexit_store_list(struct _VMCS_OBJECT* vmcs, UINT32 msr_index);

BOOLEAN vmcs_is_msr_in_vmexit_load_list(struct _VMCS_OBJECT* vmcs, UINT32 msr_index);

BOOLEAN vmcs_is_msr_in_vmenter_load_list(struct _VMCS_OBJECT* vmcs, UINT32 msr_index);

//VMM_DEBUG_CODE(
//------------------------------------------------------------------------------
//
// Print VMCS fields
//
//------------------------------------------------------------------------------
#ifdef CLI_INCLUDE
void vmcs_print_guest_state( const struct _VMCS_OBJECT* obj );
void vmcs_print_host_state( const struct _VMCS_OBJECT* obj );
void vmcs_print_controls( const struct _VMCS_OBJECT* obj );
void vmcs_print_all( const struct _VMCS_OBJECT* obj );
void vmcs_print_all_filtered(
const struct _VMCS_OBJECT* obj, UINT32 num_of_filters, char *filters[]);
#endif
const char * vmcs_get_field_name( VMCS_FIELD field_id );
void vmcs_print_vmenter_msr_load_list(struct _VMCS_OBJECT* vmcs);
void vmcs_print_vmexit_msr_store_list(struct _VMCS_OBJECT* vmcs);
//)

// dump vmcs to guest buffer
void vmcs_store_initial(GUEST_CPU_HANDLE gcpu, CPU_ID cpu_id);
void vmcs_restore_initial(GUEST_CPU_HANDLE gcpu);
void vmcs_dump_all(GUEST_CPU_HANDLE gcpu);

#endif // _VMCS_API_H_

