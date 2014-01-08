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

#ifndef HOST_MEMORY_MANAGER_H
#define HOST_MEMORY_MANAGER_H

#include <vmm_defs.h>
#include <memory_address_mapper_api.h>
#include <lock.h>

#define HMM_MAX_LOW_ADDRESS 0x7FFFFFFFFFFF
#define HMM_FIRST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS 0x8000000000
#define HMM_LAST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS  0x800000000000

#define HMM_WP_BIT_MASK ((UINT64)0x10000)

typedef struct HMM_S {
    MAM_HANDLE hva_to_hpa_mapping;
    MAM_HANDLE hpa_to_hva_mapping;
    UINT64 current_vmm_page_tabless_hpa;
    VMM_LOCK update_lock;
    HVA    new_allocations_curr_ptr;
    VMM_PHYS_MEM_TYPE mem_types_table[VMM_PHYS_MEM_LAST_TYPE + 1][VMM_PHYS_MEM_LAST_TYPE + 1];
    UINT64 final_mapped_virt_address;
    UINT32 wb_pat_index;
    UINT32 uc_pat_index;
} HMM; // Host Memory Manager


INLINE
MAM_HANDLE hmm_get_hva_to_hpa_mapping(HMM* hmm) {
    return hmm->hva_to_hpa_mapping;
}

INLINE
void hmm_set_hva_to_hpa_mapping(HMM* hmm, MAM_HANDLE mapping) {
    hmm->hva_to_hpa_mapping = mapping;
}

INLINE
MAM_HANDLE hmm_get_hpa_to_hva_mapping(HMM* hmm) {
    return hmm->hpa_to_hva_mapping;
}

INLINE
void hmm_set_hpa_to_hva_mapping(HMM* hmm, MAM_HANDLE mapping) {
    hmm->hpa_to_hva_mapping = mapping;
}

INLINE
UINT64 hmm_get_current_vmm_page_tables(HMM* hmm) {
    return hmm->current_vmm_page_tabless_hpa;
}

INLINE
void hmm_set_current_vmm_page_tables(HMM* hmm, UINT64 value) {
    hmm->current_vmm_page_tabless_hpa = value;
}

INLINE
VMM_LOCK* hmm_get_update_lock(HMM* hmm) {
    return &(hmm->update_lock);
}

INLINE
HVA hmm_get_new_allocations_curr_ptr(HMM* hmm) {
    return hmm->new_allocations_curr_ptr;
}

INLINE
void hmm_set_new_allocations_curr_ptr(HMM* hmm, HVA new_value) {
    hmm->new_allocations_curr_ptr = new_value;
}

#ifdef DEBUG
INLINE
UINT64 hmm_get_final_mapped_virt_address(HMM* hmm) {
    return hmm->final_mapped_virt_address;
}
#endif

INLINE
void hmm_set_final_mapped_virt_address(HMM* hmm, UINT64 addr) {
    hmm->final_mapped_virt_address = addr;
}

INLINE
UINT32 hmm_get_wb_pat_index(HMM* hmm) {
    return hmm->wb_pat_index;
}

INLINE
void hmm_set_wb_pat_index(HMM* hmm, UINT32 wb_pat_index) {
    hmm->wb_pat_index = wb_pat_index;
}

INLINE
UINT32 hmm_get_uc_pat_index(HMM* hmm) {
    return hmm->uc_pat_index;
}

INLINE
void hmm_set_uc_pat_index(HMM* hmm, UINT32 uc_pat_index) {
    hmm->uc_pat_index = uc_pat_index;
}

#endif
