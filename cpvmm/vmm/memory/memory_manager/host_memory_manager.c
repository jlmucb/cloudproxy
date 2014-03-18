/*
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
 */

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(HOST_MEMORY_MANAGER_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(HOST_MEMORY_MANAGER_C, __condition)
#include <host_memory_manager_api.h>
#include <memory_address_mapper_api.h>
#include <vmm_arch_defs.h>
#include <e820_abstraction.h>
#include <vmm_stack_api.h>
#include <common_libc.h>
#include <heap.h>
#include <efer_msr_abstraction.h>
#include <mtrrs_abstraction.h>
#include <hw_utils.h>
#include <idt.h>
#include <gdt.h>
#include <parse_pe_image.h>
#include <pat_manager.h>
#include <vmm_dbg.h>
#include <lock.h>
#include <ipc.h>
#include "host_memory_manager.h"

#pragma warning (disable : 4100)
#pragma warning (disable : 4101 4189)

enum {
    HMM_INVALID_MEMORY_TYPE = (MAM_MAPPING_SUCCESSFUL + 1),
    HMM_THUNK_IMAGE_UNMAP_REASON,
    HMM_VIRT_MEMORY_NOT_FOR_USE,
};

static HMM g_hmm_s;
static HMM* const g_hmm = &g_hmm_s;

extern UINT64 g_additional_heap_pa;
extern UINT32 g_heap_pa_num;
extern UINT64 g_additional_heap_base;
extern UINT32 g_is_post_launch;

/*-----------------------------------------------------------*/

#ifdef INCLUDE_UNUSED_CODE
INLINE
BOOLEAN hmm_were_page_tables_created(void) {
    return (hmm_get_current_vmm_page_tables(g_hmm) != HMM_INVALID_VMM_PAGE_TABLES);
}
#endif

INLINE
BOOLEAN hmm_is_page_available_for_allocation(MAM_MAPPING_RESULT result) {
    return ((result == MAM_UNKNOWN_MAPPING) || (result == HMM_INVALID_MEMORY_TYPE));
}

static
BOOLEAN hmm_allocate_continuous_free_virtual_pages(UINT32 num_of_pages,
                                                   UINT64* hva) {
    UINT64 new_allocations_curr_ptr = hmm_get_new_allocations_curr_ptr(g_hmm);
    UINT64 new_allocations_curr_ptr_tmp = new_allocations_curr_ptr;
    UINT32 counter = 0;
    UINT64 loop_counter = 0;
    const UINT64 max_loop_counter = HMM_LAST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS - HMM_FIRST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS;
    HPA hpa;
    MAM_ATTRIBUTES attrs;
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_MAPPING_RESULT result;

    VMM_ASSERT(num_of_pages > 0);

    do {
        if (loop_counter >= max_loop_counter) {
            return FALSE; // looked at all available ranges
        }

        result = mam_get_mapping(hva_to_hpa, new_allocations_curr_ptr_tmp, &hpa, &attrs);
        if (!hmm_is_page_available_for_allocation(result)) {
            // HVA is occupied

            new_allocations_curr_ptr = new_allocations_curr_ptr_tmp + PAGE_4KB_SIZE;
            if (new_allocations_curr_ptr >= HMM_LAST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS) {
                new_allocations_curr_ptr = HMM_FIRST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS;
            }
            new_allocations_curr_ptr_tmp = new_allocations_curr_ptr;
            counter = 0;
            loop_counter++;
            continue;
        }

        counter++;
        new_allocations_curr_ptr_tmp += PAGE_4KB_SIZE;

        if ((new_allocations_curr_ptr_tmp >= HMM_LAST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS) &&
            (counter < num_of_pages)) {
            new_allocations_curr_ptr = HMM_FIRST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS;
            new_allocations_curr_ptr_tmp = new_allocations_curr_ptr;
            counter = 0;
            loop_counter++;
            continue;
        }

        loop_counter++;
    } while (counter != num_of_pages);

    *hva = new_allocations_curr_ptr;

    new_allocations_curr_ptr = new_allocations_curr_ptr_tmp;
    if (new_allocations_curr_ptr >= HMM_LAST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS) {
        new_allocations_curr_ptr = HMM_FIRST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS;
    }

    hmm_set_new_allocations_curr_ptr(g_hmm, new_allocations_curr_ptr);

    return TRUE;
}

INLINE
BOOLEAN hmm_allocate_free_virtual_page(UINT64* hva) {
    return hmm_allocate_continuous_free_virtual_pages(1, hva);
}

static
BOOLEAN hmm_get_next_non_existent_range(IN MAM_HANDLE mam_handle,
                                        IN OUT MAM_MEMORY_RANGES_ITERATOR* iter,
                                        IN OUT UINT64 *last_covered_address,
                                        OUT UINT64* range_start,
                                        OUT UINT64* range_size) {
    MAM_MAPPING_RESULT res = MAM_MAPPING_SUCCESSFUL;
    UINT64 tgt_addr;
    MAM_ATTRIBUTES attrs;

    if (*iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        return FALSE;
    }

    do {
        *iter = mam_get_range_details_from_iterator(mam_handle, *iter,
                                                    range_start, range_size);
        res = mam_get_mapping(mam_handle, *range_start, &tgt_addr, &attrs);

        if (res != MAM_UNKNOWN_MAPPING) {
            *last_covered_address = *range_start + *range_size;
        }
        else {
            *last_covered_address = *range_start;
        }
    } while((*iter != MAM_INVALID_MEMORY_RANGES_ITERATOR) &&
            (res != MAM_UNKNOWN_MAPPING));

    if (res == MAM_UNKNOWN_MAPPING) {
        return TRUE;
    }

    return FALSE;
}

static
BOOLEAN hmm_map_remaining_memory(IN MAM_ATTRIBUTES mapping_attrs) {
    MAM_HANDLE hva_to_hpa;
    MAM_HANDLE hpa_to_hva;
    MAM_MEMORY_RANGES_ITERATOR virt_ranges_iter;
    MAM_MEMORY_RANGES_ITERATOR phys_ranges_iter;
    UINT64 last_covered_virt_addr = 0;
    UINT64 last_covered_phys_addr = 0;
    UINT64 virt_range_start = 0;
    UINT64 virt_range_size = 0;
    UINT64 phys_range_start = 0;
    UINT64 phys_range_size = 0;
    const UINT64 size_4G = 0x100000000;
    E820_ABSTRACTION_RANGE_ITERATOR e820_iter;

    hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    virt_ranges_iter = mam_get_memory_ranges_iterator(hva_to_hpa);

    hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    phys_ranges_iter = mam_get_memory_ranges_iterator(hpa_to_hva);

    if (!hmm_get_next_non_existent_range(hva_to_hpa, &virt_ranges_iter, &last_covered_virt_addr, &virt_range_start, &virt_range_size)) {
        virt_range_start = last_covered_virt_addr;
        if (virt_range_start < size_4G) {
            virt_range_size = size_4G - virt_range_start;
        }
        else {
            virt_range_size = 0;
        }
    }

    if (!hmm_get_next_non_existent_range(hpa_to_hva, &phys_ranges_iter, &last_covered_phys_addr, &phys_range_start, &phys_range_size)) {
        phys_range_start = last_covered_phys_addr;
        if (phys_range_start < size_4G) {
            phys_range_size = size_4G - phys_range_start;
        }
        else {
            phys_range_size = 0;
        }
    }

    do {
        UINT64 actual_size;
        if (virt_range_size <= phys_range_size) {
            actual_size = virt_range_size;
        }
        else {
            actual_size = phys_range_size;
        }

        if (actual_size > 0) {
            if (!mam_insert_range(hva_to_hpa, virt_range_start, phys_range_start,  actual_size, mapping_attrs)) {
                return FALSE;
            }

            if (!mam_insert_range(hpa_to_hva, phys_range_start, virt_range_start,  actual_size, MAM_NO_ATTRIBUTES)) {
                return FALSE;
            }

            virt_range_start += actual_size;
            phys_range_start += actual_size;

            virt_range_size -= actual_size;
            phys_range_size -= actual_size;

            last_covered_virt_addr = virt_range_start;
            last_covered_phys_addr = phys_range_start;

            if (virt_range_size == 0) {
                if (!hmm_get_next_non_existent_range(hva_to_hpa, &virt_ranges_iter, &last_covered_virt_addr, &virt_range_start, &virt_range_size)) {
                    virt_range_start = last_covered_virt_addr;
                    if (virt_range_start < size_4G) {
                        virt_range_size = size_4G - virt_range_start;
                    }
                    else {
                        virt_range_size = 0;
                    }
                }
            }

            if (phys_range_size == 0) {
                if (!hmm_get_next_non_existent_range(hpa_to_hva, &phys_ranges_iter, &last_covered_phys_addr, &phys_range_start, &phys_range_size)) {
                    phys_range_start = last_covered_phys_addr;
                    if (phys_range_start < size_4G) {
                        phys_range_size = size_4G - phys_range_start;
                    }
                    else {
                        phys_range_size = 0;
                    }
                }
            }

        }
    } while (last_covered_phys_addr < size_4G);

    // BEFORE_VMLAUNCH
    VMM_ASSERT(last_covered_virt_addr <= last_covered_phys_addr);
    hmm_set_final_mapped_virt_address(g_hmm, last_covered_virt_addr);

    e820_iter = e820_abstraction_iterator_get_first(E820_ORIGINAL_MAP);
    while (e820_iter != E820_ABSTRACTION_NULL_ITERATOR) {
        const INT15_E820_MEMORY_MAP_ENTRY_EXT* e820_entry = e820_abstraction_iterator_get_range_details(e820_iter);

        if ((e820_entry->basic_entry.base_address + e820_entry->basic_entry.length) > last_covered_phys_addr) {
            UINT64 base_addr_to_map;
            UINT64 length_to_map;
            if (e820_entry->basic_entry.base_address < last_covered_phys_addr) {
                base_addr_to_map = last_covered_phys_addr;
                length_to_map = e820_entry->basic_entry.base_address + e820_entry->basic_entry.length - last_covered_phys_addr;
            }
            else {
                base_addr_to_map = e820_entry->basic_entry.base_address;
                length_to_map = e820_entry->basic_entry.length;
            }

                        // Round up to next page boundry 
                        length_to_map = ALIGN_FORWARD(length_to_map, PAGE_4KB_SIZE);
            if (!mam_insert_range(hva_to_hpa, base_addr_to_map, base_addr_to_map,  length_to_map, mapping_attrs)) {
                return FALSE;
            }

            if (!mam_insert_range(hpa_to_hva, base_addr_to_map, base_addr_to_map,  length_to_map, MAM_NO_ATTRIBUTES)) {
                return FALSE;
            }

            hmm_set_final_mapped_virt_address(g_hmm, base_addr_to_map + length_to_map);
        }

        e820_iter = e820_abstraction_iterator_get_next(E820_ORIGINAL_MAP, e820_iter);
    }

    return TRUE;
}

static
void hmm_initalize_memory_types_table(void) {
    UINT32 mtrr_type_index;
    UINT32 pat_type_index;

    for (mtrr_type_index = 0; mtrr_type_index <= VMM_PHYS_MEM_LAST_TYPE; mtrr_type_index++) {
        for (pat_type_index = 0; pat_type_index <= VMM_PHYS_MEM_LAST_TYPE; pat_type_index++) {
            g_hmm->mem_types_table[mtrr_type_index][pat_type_index] = VMM_PHYS_MEM_UNDEFINED;
        }
    }

    // overwrite several cells
    g_hmm->mem_types_table[VMM_PHYS_MEM_UNCACHABLE][VMM_PHYS_MEM_UNCACHABLE] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_UNCACHABLE][VMM_PHYS_MEM_UNCACHED] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_UNCACHABLE][VMM_PHYS_MEM_WRITE_COMBINING] = VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_UNCACHABLE][VMM_PHYS_MEM_WRITE_THROUGH] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_UNCACHABLE][VMM_PHYS_MEM_WRITE_BACK] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_UNCACHABLE][VMM_PHYS_MEM_WRITE_PROTECTED] = VMM_PHYS_MEM_UNCACHABLE;

    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_COMBINING][VMM_PHYS_MEM_UNCACHABLE] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_COMBINING][VMM_PHYS_MEM_UNCACHED] = VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_COMBINING][VMM_PHYS_MEM_WRITE_COMBINING] = VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_COMBINING][VMM_PHYS_MEM_WRITE_THROUGH] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_COMBINING][VMM_PHYS_MEM_WRITE_BACK] = VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_COMBINING][VMM_PHYS_MEM_WRITE_PROTECTED] = VMM_PHYS_MEM_UNCACHABLE;

    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_THROUGH][VMM_PHYS_MEM_UNCACHABLE] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_THROUGH][VMM_PHYS_MEM_UNCACHED] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_THROUGH][VMM_PHYS_MEM_WRITE_COMBINING] =  VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_THROUGH][VMM_PHYS_MEM_WRITE_THROUGH] = VMM_PHYS_MEM_WRITE_THROUGH;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_THROUGH][VMM_PHYS_MEM_WRITE_BACK] = VMM_PHYS_MEM_WRITE_THROUGH;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_THROUGH][VMM_PHYS_MEM_WRITE_PROTECTED] = VMM_PHYS_MEM_WRITE_PROTECTED;

    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_PROTECTED][VMM_PHYS_MEM_UNCACHABLE] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_PROTECTED][VMM_PHYS_MEM_UNCACHED] = VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_PROTECTED][VMM_PHYS_MEM_WRITE_COMBINING] = VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_PROTECTED][VMM_PHYS_MEM_WRITE_THROUGH]   = VMM_PHYS_MEM_WRITE_THROUGH;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_PROTECTED][VMM_PHYS_MEM_WRITE_BACK] = VMM_PHYS_MEM_WRITE_PROTECTED;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_PROTECTED][VMM_PHYS_MEM_WRITE_PROTECTED] = VMM_PHYS_MEM_WRITE_PROTECTED;

    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_BACK][VMM_PHYS_MEM_UNCACHABLE] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_BACK][VMM_PHYS_MEM_UNCACHED] = VMM_PHYS_MEM_UNCACHABLE;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_BACK][VMM_PHYS_MEM_WRITE_COMBINING] = VMM_PHYS_MEM_WRITE_COMBINING;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_BACK][VMM_PHYS_MEM_WRITE_THROUGH] = VMM_PHYS_MEM_WRITE_THROUGH;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_BACK][VMM_PHYS_MEM_WRITE_BACK] = VMM_PHYS_MEM_WRITE_BACK;
    g_hmm->mem_types_table[VMM_PHYS_MEM_WRITE_BACK][VMM_PHYS_MEM_WRITE_PROTECTED] = VMM_PHYS_MEM_WRITE_PROTECTED;
}

static
void hmm_flash_tlb_callback(CPU_ID from UNUSED, void* arg UNUSED) {
    hw_flash_tlb();
}

#ifdef INCLUDE_UNUSED_CODE
static
void hmm_invlpg_callback(CPU_ID from UNUSED, void* arg) {
    hw_invlpg(arg);
}
#endif


#pragma warning(disable : 4710)
static
BOOLEAN hmm_map_phys_page_full_attrs(IN HPA page_hpa, IN MAM_ATTRIBUTES attrs,
                                     IN BOOLEAN flash_all_tlbs_if_needed, OUT HVA* page_hva) {
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    MAM_ATTRIBUTES attrs_tmp;
    HPA hpa_tmp = 0;
    HVA hva_tmp = 0;
    MAM_MAPPING_RESULT mapping_result;
    BOOLEAN result = TRUE;

    VMM_ASSERT((page_hpa & 0xfff) == 0); // must be aligned on page

    lock_acquire(hmm_get_update_lock(g_hmm));

    if (mam_get_mapping(hpa_to_hva, page_hpa, &hva_tmp, &attrs_tmp) == MAM_MAPPING_SUCCESSFUL) {
        mapping_result = mam_get_mapping(hva_to_hpa, hva_tmp, &hpa_tmp, &attrs_tmp);
        // BEFORE_VMLAUNCH. Critical check, keep it.
        VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);

        if (attrs_tmp.uint32 != attrs.uint32) {
            if (!mam_insert_range(hva_to_hpa, hva_tmp, page_hpa, PAGE_4KB_SIZE, attrs)) {
                result = FALSE;
                goto out;
            }
            if (flash_all_tlbs_if_needed) {
                IPC_DESTINATION dest;

                dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
                dest.addr = 0;
                ipc_execute_handler(dest, hmm_flash_tlb_callback, NULL);
                hw_flash_tlb();
            }
        }
        *page_hva = hva_tmp;
        result = TRUE;
        goto out;
    }

    // Check 1-1 mapping
    mapping_result = mam_get_mapping(hva_to_hpa, page_hpa, &hpa_tmp, &attrs_tmp);
    if (hmm_is_page_available_for_allocation(mapping_result)) {
        //the 1-1 mapping is possible;

        if (!mam_insert_range(hva_to_hpa, page_hpa, page_hpa, PAGE_4KB_SIZE, attrs)) {
            result = FALSE; // insufficient memory
            goto out;
        }

        if (!mam_insert_range(hpa_to_hva, page_hpa, page_hpa, PAGE_4KB_SIZE, MAM_NO_ATTRIBUTES)) {
            // try to restore previous hva_to_hpa mapping
            mam_insert_not_existing_range(hva_to_hpa, page_hpa, page_hpa, mapping_result);
            result = FALSE;
            goto out;
        }

        *page_hva = page_hpa;

        result = TRUE;
        goto out;
    }

    // BEFORE_VMLAUNCH. Critical check, keep it.
    // 1-1 mapping is impossible
    VMM_ASSERT(hpa_tmp != page_hpa);

    if (!hmm_allocate_free_virtual_page(&hva_tmp)) {
        result = FALSE;
        goto out;
    }

    // BEFORE_VMLAUNCH. Critical check, keep it.
    VMM_ASSERT(mam_get_mapping(hva_to_hpa, hva_tmp, &hpa_tmp, &attrs_tmp) != MAM_MAPPING_SUCCESSFUL);

    if (!mam_insert_range(hva_to_hpa, hva_tmp, page_hpa, PAGE_4KB_SIZE, attrs)) {
        result = FALSE;
        goto out;
    }

    if (!mam_insert_range(hpa_to_hva, page_hpa, hva_tmp, PAGE_4KB_SIZE, MAM_NO_ATTRIBUTES)) {
        result = FALSE;
        goto out;
    }

    *page_hva = hva_tmp;
    result = TRUE;

out:
    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}
#pragma warning(default : 4710)


#ifdef INCLUDE_UNUSED_CODE
static
BOOLEAN hmm_remap_virtual_memory_internal(HVA from_hva, HVA to_hva, UINT32 size, BOOLEAN change_attributes,
                                          MAM_ATTRIBUTES new_attrs, BOOLEAN flash_tlbs) {
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    HVA curr_from_hva = from_hva;
    HVA curr_to_hva = to_hva;
    HPA curr_hpa;
    MAM_ATTRIBUTES curr_attr;
    BOOLEAN result = TRUE;

    if ((ALIGN_BACKWARD(from_hva, PAGE_4KB_SIZE) != from_hva) ||
        (ALIGN_BACKWARD(to_hva, PAGE_4KB_SIZE) != to_hva)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: from_hva = %P ; to_hva = %P, not aligned\n", __FUNCTION__, from_hva, to_hva);
        return FALSE;
    }

    lock_acquire(hmm_get_update_lock(g_hmm));

    // Check the validity of ranges
    while (curr_from_hva < (from_hva + size)) {
        if (mam_get_mapping(hva_to_hpa, curr_to_hva, &curr_hpa, &curr_attr) == MAM_MAPPING_SUCCESSFUL) {
            VMM_LOG(mask_anonymous, level_trace,"%s: HVA %P in given 'to' range is ALREADY mapped, returning FALSE\n", __FUNCTION__, curr_to_hva);
            result = FALSE;
            break;
        }

        if (mam_get_mapping(hva_to_hpa, curr_from_hva, &curr_hpa, &curr_attr) != MAM_MAPPING_SUCCESSFUL) {
            VMM_LOG(mask_anonymous, level_trace,"%s: HVA %P in given 'from' range is NOT mapped, returning FALSE\n", __FUNCTION__, curr_from_hva);
            result = FALSE;
            break;
        }

        curr_from_hva += PAGE_4KB_SIZE;
        curr_to_hva += PAGE_4KB_SIZE;
    }

    if (!result) {
        goto out;
    }

    // Remap
    curr_from_hva = from_hva;
    curr_to_hva = to_hva;

    while (curr_from_hva < (from_hva + size)) {
        MAM_MAPPING_RESULT mapping_result;

        mapping_result = mam_get_mapping(hva_to_hpa, curr_from_hva, &curr_hpa, &curr_attr);
        VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);

        if (change_attributes) {
            curr_attr.uint32 = new_attrs.uint32;
        }

        if (!mam_insert_range(hva_to_hpa, curr_to_hva, curr_hpa, PAGE_4KB_SIZE, curr_attr)) {
            VMM_LOG(mask_anonymous, level_trace,"%s: FAILED to insert page (hva=%P) to new range, probably memory allocation error\n", __FUNCTION__, curr_to_hva);
            VMM_DEADLOOP();
        }

        if (!mam_insert_not_existing_range(hva_to_hpa, curr_from_hva, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
            VMM_LOG(mask_anonymous, level_trace,"%s: FAILED to remove page (hva=%P) from old range, probably memory allocation error\n", __FUNCTION__, curr_from_hva);
            VMM_DEADLOOP();
        }

        if (!mam_insert_range(hpa_to_hva, curr_hpa, curr_to_hva, PAGE_4KB_SIZE, MAM_NO_ATTRIBUTES)) {
            VMM_LOG(mask_anonymous, level_trace,"%s: FAILED to remap  HPA (%P) --> HVA (%P) , probably memory allocation error\n", __FUNCTION__, curr_hpa, curr_to_hva);
            VMM_DEADLOOP();
        }

        curr_from_hva += PAGE_4KB_SIZE;
        curr_to_hva += PAGE_4KB_SIZE;
    }

    if (flash_tlbs) {
        IPC_DESTINATION dest;

        dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        dest.addr = 0;
        ipc_execute_handler(dest, hmm_flash_tlb_callback, NULL);
        hw_flash_tlb();
    }

    // result remains TRUE;

out:
    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}

static
BOOLEAN hmm_alloc_additional_continuous_virtual_buffer_internal(IN UINT64 current_hva,
                                                                IN UINT64 additional_hva,
                                                                IN UINT32 num_of_pages,
                                                                IN BOOLEAN change_attributes,
                                                                IN MAM_ATTRIBUTES new_attrs) {
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    const UINT32 size = num_of_pages * PAGE_4KB_SIZE;
    HVA curr_from_hva = current_hva;
    HVA curr_to_hva = additional_hva;
    HPA curr_hpa;
    MAM_ATTRIBUTES curr_attr;
    BOOLEAN result = TRUE;

    if ((ALIGN_BACKWARD(current_hva, PAGE_4KB_SIZE) != current_hva) ||
        (ALIGN_BACKWARD(additional_hva, PAGE_4KB_SIZE) != additional_hva)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: current_hva = %P ; additional_hva = %P, not aligned\n", __FUNCTION__, current_hva, additional_hva);
        return FALSE;
    }

    lock_acquire(hmm_get_update_lock(g_hmm));

    // Check the validity of ranges
    while (curr_from_hva < (current_hva + size)) {
        if (mam_get_mapping(hva_to_hpa, curr_to_hva, &curr_hpa, &curr_attr) == MAM_MAPPING_SUCCESSFUL) {
            VMM_LOG(mask_anonymous, level_trace,"%s: HVA %P in new range is ALREADY mapped, returning FALSE\n", __FUNCTION__, curr_to_hva);
            result = FALSE;
            break;
        }

        if (mam_get_mapping(hva_to_hpa, curr_from_hva, &curr_hpa, &curr_attr) != MAM_MAPPING_SUCCESSFUL) {
            VMM_LOG(mask_anonymous, level_trace,"%s: HVA %P in current range is NOT mapped, returning FALSE\n", __FUNCTION__, curr_from_hva);
            result = FALSE;
            break;
        }

        curr_from_hva += PAGE_4KB_SIZE;
        curr_to_hva += PAGE_4KB_SIZE;
    }

    if (!result) {
        goto out;
    }

    // Additional mapping
    curr_from_hva = current_hva;
    curr_to_hva = additional_hva;

    while (curr_from_hva < (current_hva + size)) {
        MAM_MAPPING_RESULT mapping_result;

        mapping_result = mam_get_mapping(hva_to_hpa, curr_from_hva, &curr_hpa, &curr_attr);
        VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);

        if (change_attributes) {
            curr_attr.uint32 = new_attrs.uint32;
        }

        if (!mam_insert_range(hva_to_hpa, curr_to_hva, curr_hpa, PAGE_4KB_SIZE, curr_attr)) {
            VMM_LOG(mask_anonymous, level_trace,"%s: FAILED to insert page (hva=%P) to new range, probably memory allocation error\n", __FUNCTION__, curr_to_hva);
            VMM_DEADLOOP();
        }

        curr_from_hva += PAGE_4KB_SIZE;
        curr_to_hva += PAGE_4KB_SIZE;
    }

// result remains TRUE;

out:
    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}
#endif

BOOLEAN remove_initial_hva_to_hpa_mapping_for_extended_heap(void)
{
    BOOLEAN result = TRUE;
    UINT32 i;
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);

    lock_acquire(hmm_get_update_lock(g_hmm));

    for (i = 0; i < g_heap_pa_num; i++) {
        UINT64 page_hpa;
        UINT64 page_hva;
        MAM_MAPPING_RESULT mapping_result;
        MAM_ATTRIBUTES attrs_tmp;

        page_hva = g_additional_heap_base + (i * PAGE_4KB_SIZE);
                
        mapping_result = mam_get_mapping(hva_to_hpa, page_hva, &page_hpa, &attrs_tmp);
        VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);

        mapping_result = mam_get_mapping(hpa_to_hva, page_hpa, &page_hva, &attrs_tmp);
        VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);


        // Remove old HVA-->HPA mapping
        if (!mam_insert_not_existing_range(hva_to_hpa, page_hva, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) 
                {
            result = FALSE;
            break;
        }
    }

    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}

BOOLEAN build_extend_heap_hpa_to_hva(void)
{
    BOOLEAN result = TRUE;
    UINT32 i;
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);

    lock_acquire(hmm_get_update_lock(g_hmm));

    for (i = 0; i < g_heap_pa_num; i++) {
        UINT64 page_hpa;
        UINT64 page_hva;
        MAM_MAPPING_RESULT mapping_result;
        MAM_ATTRIBUTES attrs_tmp;

        page_hva = g_additional_heap_base + (i * PAGE_4KB_SIZE);
                
        mapping_result = mam_get_mapping(hva_to_hpa, page_hva, &page_hpa, &attrs_tmp);
        VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);

        // Insert new HPA-->HVA mapping
        if (!mam_insert_range(hpa_to_hva, page_hpa, page_hva, PAGE_4KB_SIZE, MAM_NO_ATTRIBUTES)) {
            result = FALSE;
            break;
        }
    }

    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}
static
BOOLEAN hmm_map_continuous_virtual_buffer_for_pages_internal(IN UINT64* hpas_array,
                                                             IN UINT32 num_of_pages,
                                                             IN BOOLEAN change_attributes,
                                                             IN MAM_ATTRIBUTES new_attrs,
                                                             IN BOOLEAN remap_hpa,
                                                             OUT UINT64* hva) {
    UINT64 buffer_hva;
    BOOLEAN result = TRUE;
    UINT32 i;
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    IPC_DESTINATION dest;

    lock_acquire(hmm_get_update_lock(g_hmm));

    if (!hmm_allocate_continuous_free_virtual_pages(num_of_pages, &buffer_hva)) {
        result = FALSE;
        goto out;
    }

    if (!change_attributes) {
        // If copying attributes from old mapping is requested, than all the pages must be mapped
        for (i = 0; i < num_of_pages; i++) {
            UINT64 page_hpa = hpas_array[i];
            UINT64 page_hva;
            MAM_ATTRIBUTES attrs_tmp;

            UINT64 page_hpa_tmp;


            if (mam_get_mapping(hpa_to_hva, page_hpa, &page_hva, &attrs_tmp) != MAM_MAPPING_SUCCESSFUL) {
                VMM_LOG(mask_anonymous, level_trace,"%s: ERROR: There is HPA (%P) is not mapped and transferring attributes is requested, please map\n", __FUNCTION__, page_hpa);
                result = FALSE;
                goto out;
            }

            // BEFORE_VMLAUNCH
            VMM_ASSERT((mam_get_mapping(hva_to_hpa, page_hva, &page_hpa_tmp, &attrs_tmp) == MAM_MAPPING_SUCCESSFUL) &&
                       (page_hpa_tmp == page_hpa));
        }
    }

    for (i = 0; i < num_of_pages; i++) {
        UINT64 page_hpa = hpas_array[i];
        UINT64 page_hva;
        MAM_ATTRIBUTES attrs;

        if (ALIGN_BACKWARD(page_hpa, PAGE_4KB_SIZE) != page_hpa) {
            VMM_LOG(mask_anonymous, level_trace,"%s: ERROR: There is HPA (%P) which is not aligned\n", __FUNCTION__, page_hpa);
            result = FALSE;
            goto out;
        }

        if (change_attributes) {
            attrs.uint32 = new_attrs.uint32;
        }
        else {
            // Take attributes from HVA-->HPA mapping
            MAM_MAPPING_RESULT mapping_result;
            UINT64 page_hva_tmp;
            UINT64 page_hpa_tmp;
            MAM_ATTRIBUTES attrs_tmp;

            mapping_result = mam_get_mapping(hpa_to_hva, page_hpa, &page_hva_tmp, &attrs_tmp);
            // BEFORE_VMLAUNCH
            VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);

            mapping_result = mam_get_mapping(hva_to_hpa, page_hva_tmp, &page_hpa_tmp, &attrs);
            // BEFORE_VMLAUNCH
            VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);
        }

        // Add new HVA-->HPA mapping
        page_hva = buffer_hva + (i * PAGE_4KB_SIZE);
        if (!mam_insert_range(hva_to_hpa, page_hva, page_hpa, PAGE_4KB_SIZE, attrs)) {
            VMM_LOG(mask_anonymous, level_trace,"%s: Insufficient memory\n", __FUNCTION__);
            // BEFORE_VMLAUNCH
            VMM_ASSERT(0);
            result = FALSE;
            goto out;
        }

        if (remap_hpa) {
            MAM_MAPPING_RESULT mapping_result;
            UINT64 old_page_hva;
            MAM_ATTRIBUTES attrs_tmp;

            mapping_result = mam_get_mapping(hpa_to_hva, page_hpa, &old_page_hva, &attrs_tmp);
            // BEFORE_VMLAUNCH
            VMM_ASSERT(mapping_result == MAM_MAPPING_SUCCESSFUL);

            // Remove old HVA-->HPA mapping
            if (!mam_insert_not_existing_range(hva_to_hpa, old_page_hva, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
                VMM_LOG(mask_anonymous, level_trace,"%s: Insufficient memory\n", __FUNCTION__);
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                result = FALSE;
                goto out;
            }

            // Insert new HPA-->HVA mapping
            if (!mam_insert_range(hpa_to_hva, page_hpa, page_hva, PAGE_4KB_SIZE, MAM_NO_ATTRIBUTES)) {
                VMM_LOG(mask_anonymous, level_trace,"%s: Insufficient memory\n", __FUNCTION__);
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                result = FALSE;
                goto out;
            }
        }
    }

    if (result != FALSE) {
        *hva = buffer_hva;
        dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        dest.addr = 0;
        ipc_execute_handler(dest, hmm_flash_tlb_callback, NULL);
        hw_flash_tlb();
    }

out:
    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}

BOOLEAN hmm_alloc_continuous_wb_virtual_buffer_for_pages(IN UINT64* hpas_array,
                                                         IN UINT32 num_of_pages,
                                                         IN BOOLEAN is_writable,
                                                         IN BOOLEAN is_executable,
                                                         OUT UINT64* hva) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = is_writable ? 1 : 0;
    attrs.paging_attr.executable = is_executable ? 1 : 0;
    attrs.paging_attr.pat_index = hmm_get_wb_pat_index(g_hmm);

    return hmm_map_continuous_virtual_buffer_for_pages_internal(hpas_array, num_of_pages, TRUE, attrs, FALSE, hva);
}

/*-----------------------------------------------------------*/

#pragma warning(disable : 4710)
BOOLEAN hmm_initialize(const VMM_STARTUP_STRUCT* startup_struct) {
    MAM_HANDLE hva_to_hpa;
    MAM_HANDLE hpa_to_hva;
    UINT32 curr_wb_index;
    UINT32 curr_uc_index;
    MAM_ATTRIBUTES inner_mapping_attrs;
    MAM_ATTRIBUTES final_mapping_attrs;
    UINT64 vmm_page_tables_hpa = 0;
    CPU_ID i;
    UINT64 first_page_hpa;
    UINT64 first_page_new_hva;
    MAM_ATTRIBUTES attrs_tmp;
    EXEC_IMAGE_SECTION_ITERATOR image_iter;
    const EXEC_IMAGE_SECTION_INFO* image_section_info;

    VMM_LOG(mask_anonymous, level_trace,"\nHMM: Initializing...\n");

    lock_initialize(hmm_get_update_lock(g_hmm));

    // Initialize table of MTRR X PAT types
    hmm_initalize_memory_types_table();

    // Get the index of Write Back caching policy
    curr_wb_index = pat_mngr_retrieve_current_earliest_pat_index_for_mem_type(VMM_PHYS_MEM_WRITE_BACK);
    if (curr_wb_index == PAT_MNGR_INVALID_PAT_INDEX) {
        VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Write Back index doesn't exist in current PAT register\n");
        goto no_destroy_exit;
    }

    curr_uc_index = pat_mngr_retrieve_current_earliest_pat_index_for_mem_type(VMM_PHYS_MEM_UNCACHABLE);
    if (curr_uc_index == PAT_MNGR_INVALID_PAT_INDEX) {
        VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: UNCACHABLE index doesn't exist in current PAT register\n");
        goto no_destroy_exit;
    }

    inner_mapping_attrs.uint32 = 0;
    inner_mapping_attrs.paging_attr.writable = 1;
    inner_mapping_attrs.paging_attr.executable = 1;
    inner_mapping_attrs.paging_attr.pat_index = curr_wb_index;


    // Create HVA -> HPA mapping
    hva_to_hpa = mam_create_mapping(inner_mapping_attrs);
    if (hva_to_hpa == MAM_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to create HVA -> HPA mapping\n");
        goto no_destroy_exit;
    }

    /// Create HPA -> HVA mapping
    hpa_to_hva = mam_create_mapping(MAM_NO_ATTRIBUTES);
    if (hpa_to_hva == MAM_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to create HPA -> HVA mapping\n");
        goto destroy_hva_to_hpa_mapping_exit;
    }

    hmm_set_hva_to_hpa_mapping(g_hmm, hva_to_hpa);
    hmm_set_hpa_to_hva_mapping(g_hmm, hpa_to_hva);
    hmm_set_current_vmm_page_tables(g_hmm, HMM_INVALID_VMM_PAGE_TABLES);
    hmm_set_new_allocations_curr_ptr(g_hmm, HMM_FIRST_VIRTUAL_ADDRESS_FOR_NEW_ALLOCATIONS);
    hmm_set_final_mapped_virt_address(g_hmm, 0);
    hmm_set_wb_pat_index(g_hmm, curr_wb_index);
    hmm_set_uc_pat_index(g_hmm, curr_uc_index);

    VMM_LOG(mask_anonymous, level_trace,"HMM: Successfully created HVA <--> HPA mappings\n");

    // Fill HPA <-> HVA mappings with initial data
    final_mapping_attrs.uint32 = 0;
    final_mapping_attrs.paging_attr.writable = 1;
    final_mapping_attrs.paging_attr.pat_index = curr_wb_index;
    // the mapping is not executable

    // TODO: initial mapping taken from startup_structure

    // Map other memory up to 4G + existing memory above 4G
    if (!hmm_map_remaining_memory(final_mapping_attrs)) {
        VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to set initial mapping\n");
        goto destroy_hpa_to_hva_mapping_exit;
    }
    VMM_LOG(mask_anonymous, level_trace,"HMM: Created initial mapping for range 0 - 4G (+ existing memory above 4G) with WRITE permissions\n");

    // Update permissions for VMM image
    VMM_LOG(mask_anonymous, level_trace,"HMM: Updating permissions to VMM image:\n");
    image_section_info = exec_image_section_first((const void*)startup_struct->vmm_memory_layout[uvmm_image].base_address, startup_struct->vmm_memory_layout[uvmm_image].image_size, &image_iter);
    while (image_section_info != NULL) {
        UINT64 section_start = (UINT64)image_section_info->start;
        UINT64 section_end = ALIGN_FORWARD(section_start + image_section_info->size, PAGE_4KB_SIZE);
        UINT64 section_size = section_end - section_start;

        // BEFORE_VMLAUNCH
        // TODO: check whether HPA->HVA conversion
        VMM_ASSERT(ALIGN_BACKWARD(section_start, PAGE_4KB_SIZE) == section_start);

        if (!image_section_info->writable) {

            MAM_ATTRIBUTES attributes_to_remove;

            attributes_to_remove.uint32 = 0;
            attributes_to_remove.paging_attr.writable = 1;

            if (!mam_remove_permissions_from_existing_mapping(hva_to_hpa, section_start, section_size, attributes_to_remove)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to remove WRITABLE permission from VMM section: [%P - %P]\n", section_start, section_end);
                goto destroy_hpa_to_hva_mapping_exit;
            }
            VMM_LOG(mask_anonymous, level_trace,"\tHMM: Removed WRITABLE permissions to section [%P - %P]\n", section_start, section_end);
        }

        if (image_section_info->executable) {
            MAM_ATTRIBUTES attributes_to_add;

            attributes_to_add.uint32 = 0;
            attributes_to_add.paging_attr.executable = 1;

            if (!mam_add_permissions_to_existing_mapping(hva_to_hpa, section_start, section_size, attributes_to_add)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to add EXECUTABLE permission to VMM section: [%P - %P]\n", section_start, section_end);
                goto destroy_hpa_to_hva_mapping_exit;
            }
            VMM_LOG(mask_anonymous, level_trace,"\tHMM: Added EXECUTABLE permissions to section [%P - %P]\n", section_start, section_end);
        }

        image_section_info = exec_image_section_next(&image_iter);
    }

    // update permissions for the thunk image
    if (startup_struct->vmm_memory_layout[thunk_image].image_size != 0)
    {
        MAM_ATTRIBUTES attributes_to_remove;
        MAM_ATTRIBUTES attributes_to_add;
        MAM_ATTRIBUTES attr_tmp;
        UINT64 thunk_image_start_hva;

        if (mam_get_mapping(hpa_to_hva, startup_struct->vmm_memory_layout[thunk_image].base_address, &thunk_image_start_hva, &attr_tmp) != MAM_MAPPING_SUCCESSFUL) {
                // Mapping must exist
                VMM_LOG(mask_anonymous, level_trace,"HPA %P is not mapped to HVA\n", startup_struct->vmm_memory_layout[thunk_image].base_address);
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
        }

        // remove "writable" permission
        attributes_to_remove.uint32 = 0;
        attributes_to_remove.paging_attr.writable = 1;
        if (!mam_remove_permissions_from_existing_mapping(hva_to_hpa, thunk_image_start_hva, startup_struct->vmm_memory_layout[thunk_image].image_size, attributes_to_remove)) {
                goto destroy_hpa_to_hva_mapping_exit;
            }

        // add "executable" permission
        attributes_to_add.uint32 = 0;
        attributes_to_add.paging_attr.executable = 1;
        if (!mam_add_permissions_to_existing_mapping(hva_to_hpa, thunk_image_start_hva, startup_struct->vmm_memory_layout[thunk_image].image_size, attributes_to_add)) {
                goto destroy_hpa_to_hva_mapping_exit;
        }
    }

    // Remap the first virtual page
    if (mam_get_mapping(hva_to_hpa, 0, &first_page_hpa, &attrs_tmp) != MAM_MAPPING_SUCCESSFUL) {
        VMM_ASSERT(0);
        goto destroy_hpa_to_hva_mapping_exit;
    }

    if (!mam_insert_not_existing_range(hva_to_hpa, 0, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
        VMM_LOG(mask_anonymous, level_trace,"Failed to remove mapping of first page\n");
        goto destroy_hpa_to_hva_mapping_exit;
    }

    VMM_LOG(mask_anonymous, level_trace,"HMM: Successfully unmapped first virtual page HVA(%P) (which was mapped to HPA(%P))\n", 0, first_page_hpa);

    if (!hmm_allocate_free_virtual_page(&first_page_new_hva)) {
        VMM_ASSERT(0);
        goto destroy_hpa_to_hva_mapping_exit;
    }

    if (!mam_insert_range(hva_to_hpa, first_page_new_hva, first_page_hpa, PAGE_4KB_SIZE, final_mapping_attrs)) {
        VMM_LOG(mask_anonymous, level_trace,"Failed to remap first page\n");
        goto destroy_hpa_to_hva_mapping_exit;
    }

    if (!mam_insert_range(hpa_to_hva, first_page_hpa, first_page_new_hva, PAGE_4KB_SIZE, MAM_NO_ATTRIBUTES)) {
        VMM_LOG(mask_anonymous, level_trace,"Failed to remap first page\n");
        goto destroy_hpa_to_hva_mapping_exit;
    }

    VMM_LOG(mask_anonymous, level_trace,"HMM: Successfully remapped HPA(%P) to HVA(%P)\n", first_page_hpa, first_page_new_hva);

    // Unmap the last page of each stack.
    VMM_ASSERT(vmm_stack_is_initialized());
    VMM_LOG(mask_anonymous, level_trace,"HMM: Remapping the exception stacks:\n");

    for (i = 0; i < startup_struct->number_of_processors_at_boot_time; i++) {
        HVA page;
        HPA page_hpa;
        UINT32 exception_stack_index;
        UINT64 page_to_assign_hva;

        HVA page_hva_tmp;
        HPA page_hpa_tmp;

        for (exception_stack_index = 0; exception_stack_index < idt_get_extra_stacks_required(); exception_stack_index++) {
            UINT64 current_extra_stack_hva;

            if (!vmm_stacks_get_exception_stack_for_cpu(i, exception_stack_index, &page)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to retrieve page to guard from the stack\n");
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }

            if (!hmm_hva_to_hpa(page, &page_hpa)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to map HVA (%P) -> HPA\n", page);
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }


            if (!mam_insert_not_existing_range(hva_to_hpa, page, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to remove HVA -> HPA mapping\n");
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }

            if (!mam_insert_not_existing_range(hpa_to_hva, page_hpa, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to remove HPA -> HVA mapping\n");
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }


            VMM_LOG(mask_anonymous, level_trace,"\tRemoved the map for HVA (%P) <--> HPA (%P).\n", page, page_hpa);

            // Make sure the mapping for page doesn't exist
            // BEFORE_VMLAUNCH
            VMM_ASSERT(!hmm_hva_to_hpa(page, &page_hpa_tmp));
            // BEFORE_VMLAUNCH
            VMM_ASSERT(!hmm_hpa_to_hva(page_hpa, &page_hva_tmp));

            if (!hmm_allocate_continuous_free_virtual_pages(3, &current_extra_stack_hva)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to allocate pages for extra stacks\n");
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }


            // Make sure the mapping for pages doesn't exist
            // BEFORE_VMLAUNCH
            VMM_ASSERT(!hmm_hva_to_hpa(current_extra_stack_hva, &page_hpa_tmp));
            // BEFORE_VMLAUNCH
            VMM_ASSERT(!hmm_hva_to_hpa(current_extra_stack_hva + PAGE_4KB_SIZE, &page_hpa_tmp));
            VMM_ASSERT(!hmm_hva_to_hpa(current_extra_stack_hva + (PAGE_4KB_SIZE*2), &page_hpa_tmp));

            if (!mam_insert_not_existing_range(hva_to_hpa, current_extra_stack_hva, PAGE_4KB_SIZE, HMM_VIRT_MEMORY_NOT_FOR_USE)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to mark HVA (%P) as 'not for use'.\n", current_extra_stack_hva);
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }

            page_to_assign_hva = current_extra_stack_hva + PAGE_4KB_SIZE;

            if (!mam_insert_range(hva_to_hpa, page_to_assign_hva, page_hpa, PAGE_4KB_SIZE, final_mapping_attrs)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to remap HVA (%P) to HPA (%P).\n", page_to_assign_hva, page_hpa);
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }

            if (!mam_insert_range(hpa_to_hva, page_hpa, page_to_assign_hva, PAGE_4KB_SIZE, MAM_NO_ATTRIBUTES)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to remap HPA (%P) to HVA (%P).\n", page_hpa, page_to_assign_hva);
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }

            if (!mam_insert_not_existing_range(hva_to_hpa, current_extra_stack_hva + (PAGE_4KB_SIZE*2), PAGE_4KB_SIZE, HMM_VIRT_MEMORY_NOT_FOR_USE)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to mark HVA (%P) as 'not for use'.\n", current_extra_stack_hva + (PAGE_4KB_SIZE*2));
                // BEFORE_VMLAUNCH
                VMM_ASSERT(0);
                goto destroy_hpa_to_hva_mapping_exit;
            }

            // Make sure the mapping for page doesn't exist
            // BEFORE_VMLAUNCH
            VMM_ASSERT(hmm_hva_to_hpa(page_to_assign_hva, &page_hpa_tmp) && (page_hpa_tmp == page_hpa));
            // BEFORE_VMLAUNCH
            VMM_ASSERT(hmm_hpa_to_hva(page_hpa, &page_hva_tmp) && (page_hva_tmp == page_to_assign_hva));

            VMM_LOG(mask_anonymous, level_trace,"\tRemapped HVA (%P) <--> HPA (%P)\n", page_to_assign_hva, page_hpa);

            // The lower and higher pages should remain unmapped in order to track stack overflow and underflow
            hw_gdt_set_ist_pointer((CPU_ID)i, (UINT8)exception_stack_index, (ADDRESS)page_to_assign_hva + PAGE_4KB_SIZE);
            VMM_LOG(mask_anonymous, level_trace,"\tPage %P (HVA) is set as exception stack#%d for cpu %d.\n", page_to_assign_hva, exception_stack_index, i);
            VMM_LOG(mask_anonymous, level_trace,"\tPages %P and %P (HVA) remain unmapped - protecting exception stack#%d of cpu %d from overflow and underflow.\n", page_to_assign_hva - PAGE_4KB_SIZE, page_to_assign_hva + PAGE_4KB_SIZE, exception_stack_index, i);
        }
    }

    // For late launch support additional heap 
    // Patch the MAM to build non-contiguous pa memory to a contiguous va for the heap
    if (g_is_post_launch) {
        if (g_additional_heap_pa) {
            BOOLEAN ret;
            
            //hmm_remap_physical_pages_to_continuous_wb_virtal_addr(
                        ret = hmm_alloc_continuous_wb_virtual_buffer_for_pages(
                (UINT64 *)g_additional_heap_pa,
                g_heap_pa_num,
                TRUE,
                FALSE,
                &g_additional_heap_base);
            VMM_LOG(mask_anonymous, level_trace,"HMM: Additional heap is mapped to VA = %p\n", 
                       (void *)g_additional_heap_base);
            if ((!ret) || (g_additional_heap_base == 0))
                VMM_DEADLOOP();
            

                        if (!remove_initial_hva_to_hpa_mapping_for_extended_heap())
                                VMM_DEADLOOP();
        }
    }

    // Make the HVA -> HPA mapping hardware compliant, i.e. create vmm page tables
    if (!mam_convert_to_64bit_page_tables(hva_to_hpa, &vmm_page_tables_hpa)) {
        VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to VMM page tables\n");
        goto destroy_hpa_to_hva_mapping_exit;
    }

    hmm_set_current_vmm_page_tables(g_hmm, vmm_page_tables_hpa);

    return TRUE;


destroy_hpa_to_hva_mapping_exit:
    mam_destroy_mapping(hpa_to_hva);
destroy_hva_to_hpa_mapping_exit:
    mam_destroy_mapping(hva_to_hpa);
no_destroy_exit:
    return FALSE;
}
#pragma warning(default : 4710)

HPA hmm_get_vmm_page_tables(void) {
    UINT64 curr_page_tables = hmm_get_current_vmm_page_tables(g_hmm);
    // BEFORE_VMLAUNCH. Should not fail.
    VMM_ASSERT(efer_msr_is_nxe_bit_set(efer_msr_read_reg()));
    return *((HPA*)(&curr_page_tables));
}

BOOLEAN hmm_hva_to_hpa(IN HVA hva, OUT HPA* hpa) {
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    UINT64 hpa_tmp;
    MAM_ATTRIBUTES attrs_tmp;
    UINT64 hva_tmp = (UINT64)hva;

        //Before hpa/hva mapping is setup, assume 1:1 mapping
        if (hva_to_hpa == MAM_INVALID_HANDLE) {
        *hpa = (HPA) hva;
        return TRUE;
        }

    if (mam_get_mapping(hva_to_hpa, hva_tmp, &hpa_tmp, &attrs_tmp) == MAM_MAPPING_SUCCESSFUL) {
        *hpa = *((HPA*)(&hpa_tmp));
        return TRUE;
    }

    return FALSE;
}

BOOLEAN hmm_hpa_to_hva(IN HPA hpa, OUT HVA* hva) {
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    UINT64 hva_tmp;
    MAM_ATTRIBUTES attrs_tmp;
    UINT64 hpa_tmp = (UINT64)hpa;

        //Before hpa/hva mapping is setup, assume 1:1 mapping
        if (hpa_to_hva == MAM_INVALID_HANDLE) {
        *hva = (HVA) hpa;
        return TRUE;
        }

    if (mam_get_mapping(hpa_to_hva, hpa_tmp, &hva_tmp, &attrs_tmp) == MAM_MAPPING_SUCCESSFUL) {
        *hva = *((HVA*)(&hva_tmp));
        return TRUE;
    }

    return FALSE;
}

BOOLEAN hmm_is_new_pat_value_consistent(UINT64 pat_value) {
    UINT32 new_wb_index = pat_mngr_get_earliest_pat_index_for_mem_type(VMM_PHYS_MEM_WRITE_BACK, pat_value);
    UINT32 new_uc_index = pat_mngr_get_earliest_pat_index_for_mem_type(VMM_PHYS_MEM_UNCACHABLE, pat_value);

    if ((new_wb_index != hmm_get_wb_pat_index(g_hmm)) ||
        (new_uc_index != hmm_get_uc_pat_index(g_hmm))) {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN hmm_unmap_hpa(IN HPA hpa, UINT64 size, BOOLEAN flush_tlbs_on_all_cpus) {
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    HVA hva;
    BOOLEAN result = TRUE;

    HPA hpa_tmp;

    lock_acquire(hmm_get_update_lock(g_hmm));

    if ((ALIGN_BACKWARD(hpa, PAGE_4KB_SIZE) != hpa) ||
        (ALIGN_FORWARD(size, PAGE_4KB_SIZE) != size)) {
        result = FALSE;
        goto out;
    }

    while (size != 0) {

        if (hmm_hpa_to_hva(hpa, &hva)) {

            // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
            VMM_ASSERT(hmm_hva_to_hpa(hva, &hpa_tmp) && (hpa_tmp == hpa));
            // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
            VMM_ASSERT(ALIGN_BACKWARD(hva, PAGE_4KB_SIZE) == hva);

            if (!mam_insert_not_existing_range(hpa_to_hva, hpa, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to unmap HPA (%P) mapping\n", hpa);
                result = FALSE;
                goto out;
            }

            if (!mam_insert_not_existing_range(hva_to_hpa, hva, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
                VMM_LOG(mask_anonymous, level_trace,"HMM ERROR: Failed to unmap HPA (%P) mapping\n", hpa);
                result = FALSE;
                goto out;
            }
        }

        size -= PAGE_4KB_SIZE;
        hpa += PAGE_4KB_SIZE;
    }

    hw_flash_tlb();

    if (flush_tlbs_on_all_cpus) {
        IPC_DESTINATION dest;

        dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        dest.addr = 0;
        ipc_execute_handler(dest, hmm_flash_tlb_callback, NULL);
    }

out:

    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}


VMM_PHYS_MEM_TYPE hmm_get_hpa_type(IN HPA hpa) {
    return mtrrs_abstraction_get_memory_type(hpa);
}

BOOLEAN hmm_does_memory_range_have_specified_memory_type(IN HPA start_hpa, IN UINT64 size, VMM_PHYS_MEM_TYPE mem_type) {
    UINT64 checked_size = 0;
    HPA curr_hpa = ALIGN_BACKWARD(start_hpa, PAGE_4KB_SIZE);

    if (mem_type == VMM_PHYS_MEM_UNDEFINED) {
        return FALSE;
    }

    while ((curr_hpa + checked_size) < (start_hpa + size)) {
        if (hmm_get_hpa_type(curr_hpa) != mem_type) {
            return FALSE;
        }
        curr_hpa += PAGE_4KB_SIZE;
        checked_size += PAGE_4KB_SIZE;
    }

    return TRUE;
}

#ifdef INCLUDE_UNUSED_CODE
VMM_PHYS_MEM_TYPE hmm_get_final_memory_type_after_hva_access(IN HVA hva) {
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    VMM_PHYS_MEM_TYPE mtrr_mem_type;
    VMM_PHYS_MEM_TYPE pat_memory_type;
    UINT32 pat_index = 0;
    HPA hpa;
    MAM_ATTRIBUTES attrs;

    if (mam_get_mapping(hva_to_hpa, hva, &hpa, &attrs) != MAM_MAPPING_SUCCESSFUL) {
        return VMM_PHYS_MEM_UNDEFINED;
    }

    mtrr_mem_type = mtrrs_abstraction_get_memory_type(hpa);
    if (mtrr_mem_type == VMM_PHYS_MEM_UNDEFINED) {
        return VMM_PHYS_MEM_UNDEFINED;
    }

    VMM_ASSERT(mtrr_mem_type <= VMM_PHYS_MEM_LAST_TYPE);

    pat_index = attrs.paging_attr.pat_index;

    pat_memory_type = pat_mngr_retrieve_current_pat_mem_type(pat_index);
    VMM_ASSERT(pat_memory_type <= VMM_PHYS_MEM_LAST_TYPE);

    return (g_hmm->mem_types_table[mtrr_mem_type][pat_index]);
}
#endif


void hmm_disable_page_level_write_protection(void) {
    // Clear WP bit
    UINT64 cr0 = hw_read_cr0();
    VMM_ASSERT((cr0 & HMM_WP_BIT_MASK) != 0);
    cr0 &= (~HMM_WP_BIT_MASK);
    hw_write_cr0(cr0);
}

void hmm_enable_page_level_write_protection(void) {
    // Clear WP bit
    UINT64 cr0 = hw_read_cr0();
    VMM_ASSERT((cr0 & HMM_WP_BIT_MASK) == 0);
    cr0 |= HMM_WP_BIT_MASK;
    hw_write_cr0(cr0);
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN hmm_is_page_level_write_protected(void) {
    UINT64 cr0 = hw_read_cr0();

    return ((cr0 & HMM_WP_BIT_MASK) != 0);
}
#endif

void hmm_set_required_values_to_control_registers(void) {
    hw_write_cr0(hw_read_cr0() | HMM_WP_BIT_MASK);
    efer_msr_set_nxe(); // Make sure EFER.NXE is set
}
#ifdef INCLUDE_UNUSED_CODE
BOOLEAN hmm_disable_update_of_page(HVA page, BOOLEAN invlpg_on_all_cpus) {
    BOOLEAN res;
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_ATTRIBUTES attrs_to_remove;

    lock_acquire(hmm_get_update_lock(g_hmm));

#ifdef DEBUG
    {
        HPA page_hpa;
        MAM_ATTRIBUTES attrs;
        MAM_MAPPING_RESULT mapping_res;

        mapping_res = mam_get_mapping(hva_to_hpa, page, &page_hpa, &attrs);
        VMM_ASSERT(mapping_res == MAM_MAPPING_SUCCESSFUL);
        VMM_ASSERT(attrs.paging_attr.writable != 0);
    }
#endif

    VMM_ASSERT(ALIGN_BACKWARD(page, PAGE_4KB_SIZE) == page);
    attrs_to_remove.uint32 = 0;
    attrs_to_remove.paging_attr.writable = 1;
    res = mam_remove_permissions_from_existing_mapping(hva_to_hpa, page, PAGE_4KB_SIZE, attrs_to_remove);

    hw_invlpg((void*)page);
    if (invlpg_on_all_cpus) {
        IPC_DESTINATION dest;

        dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        dest.addr = 0;
        ipc_execute_handler(dest, hmm_invlpg_callback, (void*)page);
    }

#ifdef DEBUG
    {
        HPA page_hpa;
        MAM_ATTRIBUTES attrs;
        MAM_MAPPING_RESULT mapping_res;

        mapping_res = mam_get_mapping(hva_to_hpa, page, &page_hpa, &attrs);
        VMM_ASSERT(mapping_res == MAM_MAPPING_SUCCESSFUL);
        VMM_ASSERT(attrs.paging_attr.writable == 0);
    }
#endif

    lock_release(hmm_get_update_lock(g_hmm));
    return res;
}

BOOLEAN hmm_enable_update_of_page(HVA page) {
    BOOLEAN res;
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_ATTRIBUTES attrs_to_add;

    lock_acquire(hmm_get_update_lock(g_hmm));

#ifdef DEBUG
    {
        HPA page_hpa;
        MAM_ATTRIBUTES attrs;
        MAM_MAPPING_RESULT mapping_res;

        mapping_res = mam_get_mapping(hva_to_hpa, page, &page_hpa, &attrs);
        VMM_ASSERT(mapping_res == MAM_MAPPING_SUCCESSFUL);
        VMM_ASSERT(attrs.paging_attr.writable == 0);
    }
#endif

    VMM_ASSERT(ALIGN_BACKWARD(page, PAGE_4KB_SIZE) == page);
    attrs_to_add.uint32 = 0;
    attrs_to_add.paging_attr.writable = 1;
    res = mam_add_permissions_to_existing_mapping(hva_to_hpa, page, PAGE_4KB_SIZE, attrs_to_add);

#ifdef DEBUG
    {
        HPA page_hpa;
        MAM_ATTRIBUTES attrs;
        MAM_MAPPING_RESULT mapping_res;

        mapping_res = mam_get_mapping(hva_to_hpa, page, &page_hpa, &attrs);
        VMM_ASSERT(mapping_res == MAM_MAPPING_SUCCESSFUL);
        VMM_ASSERT(attrs.paging_attr.writable != 0);
    }
#endif

    lock_release(hmm_get_update_lock(g_hmm));
    return res;
}
#endif

BOOLEAN hmm_map_uc_physical_page(IN HPA page_hpa, IN BOOLEAN is_writable, IN BOOLEAN is_executable,
                                 IN BOOLEAN flash_all_tlbs_if_needed, OUT HVA* page_hva) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = (is_writable) ? 1 : 0;
    attrs.paging_attr.executable = (is_executable) ? 1 : 0;
    attrs.paging_attr.pat_index = hmm_get_uc_pat_index(g_hmm);
    return hmm_map_phys_page_full_attrs(page_hpa, attrs, flash_all_tlbs_if_needed, page_hva);
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN hmm_map_wb_physical_page(IN HPA page_hpa, IN BOOLEAN is_writable, IN BOOLEAN is_executable,
                                 IN BOOLEAN flash_all_tlbs_if_needed, OUT HVA* page_hva) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = (is_writable) ? 1 : 0;
    attrs.paging_attr.executable = (is_executable) ? 1 : 0;
    attrs.paging_attr.pat_index = hmm_get_wb_pat_index(g_hmm);
    return hmm_map_phys_page_full_attrs(page_hpa, attrs, flash_all_tlbs_if_needed, page_hva);
}

BOOLEAN hmm_map_physical_page(IN HPA page_hpa,
                              IN BOOLEAN is_writable,
                              IN BOOLEAN is_executable,
                              IN UINT32 pat_index,
                              IN BOOLEAN flash_all_tlbs_if_needed,
                              OUT HVA* page_hva) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = (is_writable) ? 1 : 0;
    attrs.paging_attr.executable = (is_executable) ? 1 : 0;
    attrs.paging_attr.pat_index = pat_index;

    return hmm_map_phys_page_full_attrs(page_hpa, attrs, flash_all_tlbs_if_needed, page_hva);
}

BOOLEAN hmm_alloc_continuous_virtual_buffer_for_pages(IN UINT64* hpas_array, IN UINT32 num_of_pages,
                                                      IN BOOLEAN is_writable, IN BOOLEAN is_executable,
                                                      IN UINT32 pat_index, OUT UINT64* hva) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = is_writable ? 1 : 0;
    attrs.paging_attr.executable = is_executable ? 1 : 0;
    attrs.paging_attr.pat_index = pat_index;

    return hmm_map_continuous_virtual_buffer_for_pages_internal(hpas_array, num_of_pages, TRUE, attrs, FALSE, hva);
}

BOOLEAN hmm_free_continuous_virtual_buffer(UINT64 buffer_hva,
                                           UINT32 num_of_pages) {
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    BOOLEAN result = TRUE;
    UINT32 i;
    IPC_DESTINATION dest;

    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    UINT64 page_hpa_tmp;
    UINT64 page_hva_tmp;
    MAM_ATTRIBUTES attrs_tmp;

    lock_acquire(hmm_get_update_lock(g_hmm));

    for (i = 0; i < num_of_pages; i++) {
        UINT64 page_hva;

        // Just invalidate mapping created in "hmm_assemble_continuous_virtual_buffer_for_pages" function
        page_hva = buffer_hva + (i * PAGE_4KB_SIZE);

        // Mapping HPA->HVA must exist but to different HVA than removed one
        VMM_ASSERT((mam_get_mapping(hva_to_hpa, page_hva, &page_hpa_tmp, &attrs_tmp) == MAM_MAPPING_SUCCESSFUL) &&
                   (mam_get_mapping(hpa_to_hva, page_hpa_tmp, &page_hva_tmp, &attrs_tmp) == MAM_MAPPING_SUCCESSFUL) &&
                   (page_hva_tmp != page_hva));

        if (!mam_insert_not_existing_range(hva_to_hpa, page_hva, PAGE_4KB_SIZE, HMM_INVALID_MEMORY_TYPE)) {
            result = FALSE;
            break;
        }
    }

    dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
    dest.addr = 0;
    ipc_execute_handler(dest, hmm_flash_tlb_callback, NULL);
    hw_flash_tlb();

    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}

BOOLEAN hmm_make_phys_page_uncachable(UINT64 page_hpa) {
    MAM_HANDLE hpa_to_hva = hmm_get_hpa_to_hva_mapping(g_hmm);
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    UINT64 page_hva;
    UINT64 page_hpa_tmp;
    MAM_ATTRIBUTES attrs;
    BOOLEAN result = TRUE;
    UINT32 curr_uc_pat_index;

    lock_acquire(hmm_get_update_lock(g_hmm));

    VMM_ASSERT(ALIGN_BACKWARD(page_hpa, PAGE_4KB_SIZE) == page_hpa);

    if (mam_get_mapping(hpa_to_hva, page_hpa, &page_hva, &attrs) != MAM_MAPPING_SUCCESSFUL) {
        result = FALSE;
        goto out;
    }

    if (mam_get_mapping(hva_to_hpa, page_hva, &page_hpa_tmp, &attrs) != MAM_MAPPING_SUCCESSFUL) {
        result = FALSE;
        goto out;
    }

    VMM_ASSERT(page_hpa == page_hpa_tmp);

    curr_uc_pat_index = hmm_get_uc_pat_index(g_hmm);
    if (attrs.paging_attr.pat_index != curr_uc_pat_index) {
        IPC_DESTINATION dest;

        attrs.paging_attr.pat_index = curr_uc_pat_index;
        if (!mam_insert_range(hva_to_hpa, page_hva, page_hpa, PAGE_4KB_SIZE, attrs)) {
            result = FALSE;
            goto out;
        }
        dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        dest.addr = 0;
        ipc_execute_handler(dest, hmm_flash_tlb_callback, NULL);
        hw_flash_tlb();
    }

out:
    lock_release(hmm_get_update_lock(g_hmm));
    return result;
}

BOOLEAN hmm_remap_virtual_memory_no_attr_change(HVA from_hva, HVA to_hva, UINT32 size,
                                                BOOLEAN flash_tlbs) {
    return hmm_remap_virtual_memory_internal(from_hva, to_hva, size, FALSE, MAM_NO_ATTRIBUTES, flash_tlbs);
}

BOOLEAN hmm_remap_virtual_memory(HVA from_hva,
                                 HVA to_hva,
                                 UINT32 size,
                                 BOOLEAN is_writable,
                                 BOOLEAN is_executable,
                                 UINT32 pat_index,
                                 BOOLEAN flash_tlbs) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = (is_writable) ? 1 : 0;
    attrs.paging_attr.executable = (is_executable) ? 1 : 0;
    attrs.paging_attr.pat_index = pat_index;
    return hmm_remap_virtual_memory_internal(from_hva, to_hva, size, TRUE, attrs, flash_tlbs);
}

BOOLEAN hmm_remap_wb_virtual_memory(HVA from_hva,
                                    HVA to_hva,
                                    UINT32 size,
                                    BOOLEAN is_writable,
                                    BOOLEAN is_executable,
                                    BOOLEAN flash_tlbs) {
    UINT32 wb_index = hmm_get_wb_pat_index(g_hmm);
    return hmm_remap_virtual_memory(from_hva, to_hva, size, is_writable, is_executable, wb_index, flash_tlbs);
}

BOOLEAN hmm_alloc_additional_continuous_virtual_buffer_no_attr_change(IN UINT64 current_hva,
                                                                      IN UINT64 additional_hva,
                                                                      IN UINT32 num_of_pages) {

    return hmm_alloc_additional_continuous_virtual_buffer_internal(current_hva, additional_hva, num_of_pages, FALSE, MAM_NO_ATTRIBUTES);
}

BOOLEAN hmm_alloc_additional_continuous_virtual_buffer(IN UINT64 current_hva, IN UINT64 additional_hva,
                                                       IN UINT32 num_of_pages, IN BOOLEAN is_writable,
                                                       IN BOOLEAN is_executable, IN UINT32 pat_index) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = (is_writable) ? 1 : 0;
    attrs.paging_attr.executable = (is_executable) ? 1 : 0;
    attrs.paging_attr.pat_index = pat_index;

    return hmm_alloc_additional_continuous_virtual_buffer_internal(current_hva, additional_hva, num_of_pages, TRUE, attrs);
}

BOOLEAN hmm_alloc_additional_continuous_wb_virtual_buffer(IN UINT64 current_hva,
                                                          IN UINT64 additional_hva,
                                                          IN UINT32 num_of_pages,
                                                          IN BOOLEAN is_writable,
                                                          IN BOOLEAN is_executable) {
    UINT32 wb_index = hmm_get_wb_pat_index(g_hmm);
    return hmm_alloc_additional_continuous_virtual_buffer(current_hva, additional_hva, num_of_pages, is_writable, is_executable, wb_index);
}

BOOLEAN hmm_hva_to_hpa_with_attr(IN HVA hva, OUT HPA* hpa, OUT BOOLEAN* is_writable,
                                 OUT BOOLEAN* is_executable, OUT UINT32* pat_index) {
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    UINT64 hpa_tmp;
    MAM_ATTRIBUTES attrs_tmp;
    UINT64 hva_tmp = (UINT64)hva;

    if (mam_get_mapping(hva_to_hpa, hva_tmp, &hpa_tmp, &attrs_tmp) == MAM_MAPPING_SUCCESSFUL) {
        *hpa = *((HPA*)(&hpa_tmp));
        *is_writable = attrs_tmp.paging_attr.writable;
        *is_executable = attrs_tmp.paging_attr.executable;
        *pat_index = attrs_tmp.paging_attr.pat_index;
        return TRUE;
    }

    return FALSE;
}

BOOLEAN hmm_remap_physical_pages_to_continuous_virtal_addr_copy_attrs(IN UINT64* hpas_array,
                                                                      IN UINT32 num_of_pages,
                                                                      OUT UINT64* hva) {
    return hmm_map_continuous_virtual_buffer_for_pages_internal(hpas_array, num_of_pages,
                                                                FALSE, /* do not change attributes */
                                                                MAM_NO_ATTRIBUTES, TRUE, /* remap hpa */
                                                                hva);
}

BOOLEAN hmm_remap_physical_pages_to_continuous_virtal_addr(IN UINT64* hpas_array, IN UINT32 num_of_pages,
                                                           IN BOOLEAN is_writable, IN BOOLEAN is_executable,
                                                           IN UINT32 pat_index, OUT UINT64* hva) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = (is_writable) ? 1 : 0;
    attrs.paging_attr.executable = (is_executable) ? 1 : 0;
    attrs.paging_attr.pat_index = pat_index;

    return hmm_map_continuous_virtual_buffer_for_pages_internal(hpas_array, num_of_pages,
                                                                TRUE, /* change attributes */
                                                                attrs, TRUE, /* remap hpa */ hva);
}
#endif

BOOLEAN hmm_remap_physical_pages_to_continuous_wb_virtal_addr(IN UINT64* hpas_array, IN UINT32 num_of_pages,
                                                              IN BOOLEAN is_writable, IN BOOLEAN is_executable,
                                                              OUT UINT64* hva) {
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.writable = (is_writable) ? 1 : 0;
    attrs.paging_attr.executable = (is_executable) ? 1 : 0;
    attrs.paging_attr.pat_index = hmm_get_wb_pat_index(g_hmm);

    return hmm_map_continuous_virtual_buffer_for_pages_internal(hpas_array, num_of_pages,
                                                                TRUE, /* change attributes */
                                                                attrs, TRUE, /* remap hpa */ hva);
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN change_teardown_thunk_executable_in_hmm(IN UINT64 start_hva, IN UINT64 size) {
    MAM_HANDLE hva_to_hpa = hmm_get_hva_to_hpa_mapping(g_hmm);
    MAM_ATTRIBUTES attrs;

    attrs.uint32 = 0;
    attrs.paging_attr.executable = 1;

    return (mam_add_permissions_to_existing_mapping(hva_to_hpa, start_hva, size, attrs));
}
#endif
#pragma warning (default : 4101 4189)

