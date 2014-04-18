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

#include <vmm_defs.h>
#include <gpm_api.h>
#include <memory_address_mapper_api.h>
#include <host_memory_manager_api.h>
#include <e820_abstraction.h>
#include <heap.h>
#include <vmm_dbg.h>
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GPM_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GPM_C, __condition)

#define GPM_INVALID_MAPPING (MAM_MAPPING_SUCCESSFUL + 1)
#define GPM_MMIO            (MAM_MAPPING_SUCCESSFUL + 2)


typedef struct GPM_S {
        MAM_HANDLE gpa_to_hpa;
        MAM_HANDLE hpa_to_gpa;
} GPM;

static
BOOLEAN gpm_get_range_details_and_advance_mam_iterator(IN MAM_HANDLE mam_handle,
                                                       IN OUT MAM_MEMORY_RANGES_ITERATOR* mem_ranges_iter,
                                                       OUT UINT64* range_start,
                                                       OUT UINT64* range_size) {
    MAM_MEMORY_RANGES_ITERATOR iter = *mem_ranges_iter;
    MAM_MAPPING_RESULT res;

    VMM_ASSERT(*mem_ranges_iter != MAM_INVALID_MEMORY_RANGES_ITERATOR);

    do {
        UINT64 tgt_addr;
        MAM_ATTRIBUTES attrs;

        iter = mam_get_range_details_from_iterator(mam_handle, iter, range_start, range_size);

        res = mam_get_mapping(mam_handle, *range_start, &tgt_addr, &attrs);
    } while ((res != MAM_MAPPING_SUCCESSFUL) &&
             (res != GPM_MMIO) &&
             (iter != MAM_INVALID_MEMORY_RANGES_ITERATOR));

    *mem_ranges_iter = iter;

    if (iter != MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        return TRUE;
    }

    if ((res == MAM_MAPPING_SUCCESSFUL) || (res == GPM_MMIO)) {
        return TRUE;
    }

    return FALSE;
}

// static
BOOLEAN gpm_remove_all_relevant_hpa_to_gpa_mapping(GPM* gpm, GPA gpa, UINT64 size) {
    MAM_HANDLE gpa_to_hpa;
    MAM_HANDLE hpa_to_gpa;
    UINT64 gpa_tmp;
    gpa_to_hpa = gpm->gpa_to_hpa;
    hpa_to_gpa = gpm->hpa_to_gpa;

    // Remove all hpa mappings
    for (gpa_tmp = gpa; gpa_tmp < gpa + size; gpa_tmp += PAGE_4KB_SIZE) {
        UINT64 hpa;
        MAM_ATTRIBUTES attrs;

        if (mam_get_mapping(gpa_to_hpa, gpa_tmp, &hpa, &attrs) == MAM_MAPPING_SUCCESSFUL) {
            if (!mam_insert_not_existing_range(hpa_to_gpa, hpa, PAGE_4KB_SIZE, GPM_INVALID_MAPPING)) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

GPM_HANDLE gpm_create_mapping(void) {
    GPM* gpm;
    MAM_HANDLE gpa_to_hpa;
    MAM_HANDLE hpa_to_gpa;

    gpm = (GPM*)vmm_memory_alloc(sizeof(GPM));
    if (gpm == NULL) {
                goto failed_to_allocated_gpm;
        }

    gpa_to_hpa = mam_create_mapping(MAM_NO_ATTRIBUTES);
    if (gpa_to_hpa == MAM_INVALID_HANDLE) {
        goto failed_to_allocate_gpa_to_hpa_mapping;
    }

    hpa_to_gpa = mam_create_mapping(MAM_NO_ATTRIBUTES);
    if (hpa_to_gpa == MAM_INVALID_HANDLE) {
        goto failed_to_allocate_hpa_to_gpa_mapping;
    }

    gpm->gpa_to_hpa = gpa_to_hpa;
    gpm->hpa_to_gpa = hpa_to_gpa;
    return (GPM_HANDLE)gpm;

failed_to_allocate_hpa_to_gpa_mapping:
        mam_destroy_mapping(gpa_to_hpa);
failed_to_allocate_gpa_to_hpa_mapping:
        vmm_memory_free(gpm);
failed_to_allocated_gpm:
        return GPM_INVALID_HANDLE;
}

BOOLEAN gpm_add_mapping(IN GPM_HANDLE gpm_handle, IN GPA gpa, IN HPA hpa, IN UINT64 size, MAM_ATTRIBUTES attrs) {
        GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;
    MAM_HANDLE hpa_to_gpa;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

    gpa_to_hpa = gpm->gpa_to_hpa;
    hpa_to_gpa = gpm->hpa_to_gpa;

    if (!mam_insert_range(gpa_to_hpa, (UINT64)gpa, (UINT64)hpa, size, attrs)) {
        return FALSE;
    }

#ifdef USE_HPA_TO_GPA
    if (!mam_insert_range(hpa_to_gpa, (UINT64)hpa, (UINT64)gpa, size, attrs)) {
        return FALSE;
    }
#endif
    return TRUE;
}

BOOLEAN gpm_remove_mapping(IN GPM_HANDLE gpm_handle, IN GPA gpa, IN UINT64 size) {
        GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

#ifdef USE_HPA_TO_GPA
    // Remove all hpa mappings
    if (!gpm_remove_all_relevant_hpa_to_gpa_mapping(gpm, gpa, size)) {
        return FALSE;
    }
#endif

    gpa_to_hpa = gpm->gpa_to_hpa;
    return (BOOLEAN)mam_insert_not_existing_range(gpa_to_hpa, (UINT64)gpa, size, GPM_INVALID_MAPPING);
}

BOOLEAN gpm_add_mmio_range(IN GPM_HANDLE gpm_handle, IN GPA gpa, IN UINT64 size) {
    GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

#ifdef USE_HPA_TO_GPA
    // Remove all hpa mappings
    if (!gpm_remove_all_relevant_hpa_to_gpa_mapping(gpm, gpa, size)) {
        return FALSE;
    }
#endif

    gpa_to_hpa = gpm->gpa_to_hpa;
    return (BOOLEAN)mam_insert_not_existing_range(gpa_to_hpa,
                          (UINT64)gpa, size, GPM_MMIO);
}

BOOLEAN gpm_is_mmio_address(IN GPM_HANDLE gpm_handle, IN GPA gpa) {
    GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;
    UINT64 hpa_tmp;
    MAM_MAPPING_RESULT res;
    MAM_ATTRIBUTES attrs;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

    gpa_to_hpa = gpm->gpa_to_hpa;
    res = (BOOLEAN)mam_get_mapping(gpa_to_hpa, (UINT64)gpa, &hpa_tmp, &attrs);
    if (res != GPM_MMIO) {
        return FALSE;
    }
    return TRUE;
}


BOOLEAN gpm_gpa_to_hpa(IN GPM_HANDLE gpm_handle, IN GPA gpa, OUT HPA* hpa, OUT MAM_ATTRIBUTES *hpa_attrs) {
    GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;
    UINT64 hpa_tmp;
    MAM_MAPPING_RESULT res;
    MAM_ATTRIBUTES attrs;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

    gpa_to_hpa = gpm->gpa_to_hpa;
    res = mam_get_mapping(gpa_to_hpa, (UINT64)gpa, &hpa_tmp, &attrs);
    if (res != MAM_MAPPING_SUCCESSFUL) {
        return FALSE;
    }

    *hpa = *((HPA*)(&hpa_tmp));
        *hpa_attrs = *((MAM_ATTRIBUTES*)(&attrs));
    return TRUE;
}

BOOLEAN gpm_gpa_to_hva(IN GPM_HANDLE gpm_handle, IN GPA gpa, OUT HVA* hva) {
        GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;
    UINT64 hpa_tmp;
    UINT64 hva_tmp;
    HPA hpa;
    MAM_MAPPING_RESULT res;
    MAM_ATTRIBUTES attrs;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

    gpa_to_hpa = gpm->gpa_to_hpa;
    res = (BOOLEAN)mam_get_mapping(gpa_to_hpa, (UINT64)gpa, &hpa_tmp, &attrs);
    if (res != MAM_MAPPING_SUCCESSFUL) {
        return FALSE;
    }

    hpa = *((HPA*)(&hpa_tmp));
    res = hmm_hpa_to_hva(hpa, &hva_tmp);
    if (res) {
        *hva = *((HVA*)(&hva_tmp));
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,"Warning!!! Failed Translation Host Physical to Host Virtual\n");
    }
    return res;
}

BOOLEAN gpm_hpa_to_gpa(IN GPM_HANDLE gpm_handle, IN HPA hpa, OUT GPA* gpa) {
        GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE hpa_to_gpa;
    UINT64 gpa_tmp;
    MAM_MAPPING_RESULT res;
    MAM_ATTRIBUTES attrs;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

    hpa_to_gpa = gpm->hpa_to_gpa;
    res = mam_get_mapping(hpa_to_gpa, (UINT64)hpa, &gpa_tmp, &attrs);
    if (res != MAM_MAPPING_SUCCESSFUL) {
        return FALSE;
    }

    *gpa = *((GPA*)(&gpa_tmp));
    return TRUE;
}

BOOLEAN gpm_create_e820_map(IN GPM_HANDLE gpm_handle,
                            OUT E820_HANDLE* e820_handle) {
    GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;
    E820_HANDLE e820_map;
    E820_ABSTRACTION_RANGE_ITERATOR e820_iter;
    MAM_MEMORY_RANGES_ITERATOR mem_ranges_iter;
    GPA range_start;
    UINT64 range_size;
    GPA addr;
    UINT64 size;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return FALSE;
    }

    gpa_to_hpa = gpm->gpa_to_hpa;
    if (!e820_abstraction_create_new_map(&e820_map)) {
        return FALSE;
    }

    e820_iter = e820_abstraction_iterator_get_first(E820_ORIGINAL_MAP);
    mem_ranges_iter = mam_get_memory_ranges_iterator(gpa_to_hpa);

    if ((mem_ranges_iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) ||
        (e820_iter == E820_ABSTRACTION_NULL_ITERATOR)) {
        return FALSE;
    }

    if(!gpm_get_range_details_and_advance_mam_iterator(gpa_to_hpa, &mem_ranges_iter, &range_start, &range_size)) {
        // No appropriate ranges exist
        return FALSE;
    }

    while (e820_iter != E820_ABSTRACTION_NULL_ITERATOR) {
        const INT15_E820_MEMORY_MAP_ENTRY_EXT* orig_map_entry = e820_abstraction_iterator_get_range_details(e820_iter);

        if (((UINT64)range_start >= orig_map_entry->basic_entry.base_address) &&
            ((UINT64)range_start + range_size <= orig_map_entry->basic_entry.base_address + orig_map_entry->basic_entry.length)) {
            BOOLEAN encountered_non_contigues_regions = FALSE;

            while ((mem_ranges_iter != MAM_INVALID_MEMORY_RANGES_ITERATOR) &&
                   ((UINT64)range_start + range_size <= orig_map_entry->basic_entry.base_address + orig_map_entry->basic_entry.length)) {


                if(!gpm_get_range_details_and_advance_mam_iterator(gpa_to_hpa, &mem_ranges_iter, &addr, &size)) {
                    // There are no more ranges
                    break;
                }

                if (addr > (range_start + range_size)) {

                    if (!e820_abstraction_add_new_range(e820_map, range_start, range_size, orig_map_entry->basic_entry.address_range_type, orig_map_entry->extended_attributes)) {
                        goto failed_to_fill;
                    }

                    range_start = addr;
                    range_size = size;
                    encountered_non_contigues_regions = TRUE;
                    break;
                }
                else {
                    VMM_ASSERT(addr == (range_start + range_size));
                    range_size += size;
                }
            }

            if (encountered_non_contigues_regions) {
                continue; // resume outer loop iterations.
            }

            if ((UINT64)range_start + range_size > orig_map_entry->basic_entry.base_address + orig_map_entry->basic_entry.length) {
                continue; // There are global_case for it
            }

            VMM_ASSERT(mem_ranges_iter == MAM_INVALID_MEMORY_RANGES_ITERATOR);
            if (!e820_abstraction_add_new_range(e820_map, range_start, range_size, orig_map_entry->basic_entry.address_range_type, orig_map_entry->extended_attributes)) {
                goto failed_to_fill;
            }

            break; // There are no more gpm ranges

        }
        else if ((range_start + range_size) <= orig_map_entry->basic_entry.base_address) {
            // Skip the range
            if (mem_ranges_iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) {
                break; // No more valid ranges
            }
            if (!gpm_get_range_details_and_advance_mam_iterator(gpa_to_hpa, &mem_ranges_iter, &range_start, &range_size)) {
                break;
            }
            continue;
        }
        else if (orig_map_entry->basic_entry.base_address + orig_map_entry->basic_entry.length <= range_start) {
            e820_iter = e820_abstraction_iterator_get_next(E820_ORIGINAL_MAP, e820_iter);
            continue;
        }
        else if ((range_start < orig_map_entry->basic_entry.base_address) &&
                 (range_start + range_size > orig_map_entry->basic_entry.base_address)) {
            range_size = range_start + range_size - orig_map_entry->basic_entry.base_address;
            range_start = orig_map_entry->basic_entry.base_address;
            continue;
        }
        else {
            UINT64 new_size = orig_map_entry->basic_entry.base_address + orig_map_entry->basic_entry.length - range_start;
            VMM_ASSERT(range_start >= orig_map_entry->basic_entry.base_address);
            VMM_ASSERT(range_start + range_size > orig_map_entry->basic_entry.base_address + orig_map_entry->basic_entry.length);
            VMM_ASSERT(new_size > 0);

            if (!e820_abstraction_add_new_range(e820_map, range_start, new_size, orig_map_entry->basic_entry.address_range_type, orig_map_entry->extended_attributes)) {
                goto failed_to_fill;
            }
            range_start += new_size;
            range_size -= new_size;
            continue;
        }
    }

    *e820_handle = e820_map;

//    VMM_DEBUG_CODE(
//        VMM_LOG(mask_anonymous, level_trace,"Guest Memory Map\n");
//        e820_abstraction_print_memory_map(e820_map);
//    )

    return TRUE;

failed_to_fill:
    e820_abstraction_destroy_map(e820_map);
    return FALSE;
}

void gpm_destroy_e820_map(IN E820_HANDLE e820_handle) {
    e820_abstraction_destroy_map(e820_handle);
}


MAM_MEMORY_RANGES_ITERATOR gpm_advance_mam_iterator_to_appropriate_range(MAM_HANDLE mam_handle, MAM_MEMORY_RANGES_ITERATOR iter) {
    UINT64 src_addr;
    UINT64 tgt_addr;
    MAM_ATTRIBUTES attr;
    MAM_MAPPING_RESULT res;
    UINT64 size;

    src_addr = mam_get_range_start_address_from_iterator(mam_handle, iter);

    res = mam_get_mapping(mam_handle, src_addr, &tgt_addr, &attr);
    while ((res != MAM_MAPPING_SUCCESSFUL) &&
           (res != GPM_MMIO) &&
           (iter != MAM_INVALID_MEMORY_RANGES_ITERATOR)) {

        iter = mam_get_range_details_from_iterator(mam_handle, iter, &src_addr, &size);
        src_addr = mam_get_range_start_address_from_iterator(mam_handle, iter);
        res = mam_get_mapping(mam_handle, src_addr, &tgt_addr, &attr);
    }

    return iter;
}

GPM_RANGES_ITERATOR gpm_get_ranges_iterator(IN GPM_HANDLE gpm_handle) {
    GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;
    MAM_MEMORY_RANGES_ITERATOR iter;

    if (gpm_handle == GPM_INVALID_HANDLE) {
        return GPM_INVALID_RANGES_ITERATOR;
    }

    gpa_to_hpa = gpm->gpa_to_hpa;

    iter = mam_get_memory_ranges_iterator(gpa_to_hpa);

    if (iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        return GPM_INVALID_RANGES_ITERATOR;
    }

    iter = gpm_advance_mam_iterator_to_appropriate_range(gpa_to_hpa, iter);
    if (iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        return GPM_INVALID_RANGES_ITERATOR;
    }

    return (GPM_RANGES_ITERATOR)iter;
}

GPM_RANGES_ITERATOR gpm_get_range_details_from_iterator(IN GPM_HANDLE gpm_handle,
                                 IN GPM_RANGES_ITERATOR iter, OUT GPA* gpa_out,
                                 OUT UINT64* size_out) {
    GPM* gpm = (GPM*)gpm_handle;
    MAM_HANDLE gpa_to_hpa;
    MAM_MEMORY_RANGES_ITERATOR mam_iter = (MAM_MEMORY_RANGES_ITERATOR)iter;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(gpm_handle != GPM_INVALID_HANDLE);

    if (iter == GPM_INVALID_RANGES_ITERATOR) {
        *gpa_out = ~((UINT64)0);
        *size_out = 0;
        return GPM_INVALID_RANGES_ITERATOR;
    }

    gpa_to_hpa = gpm->gpa_to_hpa;
    mam_iter = mam_get_range_details_from_iterator(gpa_to_hpa, mam_iter, gpa_out, size_out);
    mam_iter = gpm_advance_mam_iterator_to_appropriate_range(gpa_to_hpa, mam_iter);

    if (mam_iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        return GPM_INVALID_RANGES_ITERATOR;
    }
    return (GPM_RANGES_ITERATOR)mam_iter;
}

#pragma warning (disable : 4100)
#pragma warning (disable : 4189)

void gpm_print(GPM_HANDLE gpm_handle USED_IN_DEBUG_ONLY)
{

VMM_DEBUG_CODE(

    E820_HANDLE guest_e820 = NULL;
    GPM_RANGES_ITERATOR gpm_iter = GPM_INVALID_RANGES_ITERATOR;
    BOOLEAN status = FALSE;
    GPA guest_range_addr = 0;
    UINT64 guest_range_size = 0;
    HPA host_range_addr = 0;
        MAM_ATTRIBUTES attrs;

    VMM_LOG(mask_anonymous, level_trace,"GPM ranges:\r\n");
    gpm_iter = gpm_get_ranges_iterator(gpm_handle);
    while(GPM_INVALID_RANGES_ITERATOR != gpm_iter) {
        gpm_iter = gpm_get_range_details_from_iterator(gpm_handle,
                                 gpm_iter, &guest_range_addr, &guest_range_size);
        status = gpm_gpa_to_hpa(gpm_handle, guest_range_addr, &host_range_addr, &attrs);
        if(FALSE == status) {
            VMM_LOG(mask_anonymous, level_trace,"GPM no mapping for gpa %p\r\n", guest_range_addr);
        }
        else {
            VMM_LOG(mask_anonymous, level_trace,"  base %p size %p\r\n", guest_range_addr, guest_range_size);
        }
    }

    gpm_create_e820_map(gpm_handle, &guest_e820);
    e820_abstraction_print_memory_map(guest_e820);
    )
}

BOOLEAN gpm_copy(GPM_HANDLE src, GPM_HANDLE dst, BOOLEAN override_attrs, MAM_ATTRIBUTES set_attrs)
{
    GPM_RANGES_ITERATOR src_iter = GPM_INVALID_RANGES_ITERATOR;
    GPA guest_range_addr = 0;
    UINT64 guest_range_size = 0;
    HPA host_range_addr = 0;
    BOOLEAN status = FALSE;
    MAM_ATTRIBUTES attrs;

    src_iter = gpm_get_ranges_iterator(src);

    while(GPM_INVALID_RANGES_ITERATOR != src_iter) {
        src_iter = gpm_get_range_details_from_iterator(src,
                                 src_iter, &guest_range_addr,
                                 &guest_range_size);
        status = gpm_gpa_to_hpa(src, guest_range_addr, &host_range_addr, &attrs);
        if(FALSE == status) {  // no mapping - is it mmio?
            if(gpm_is_mmio_address(src, guest_range_addr)){
                status = gpm_add_mmio_range(dst, guest_range_addr, guest_range_size);
                if(FALSE == status) {
                    goto failure;
                }
            }
            else {
                // normal memory - should not fail the mapping translation
                goto failure;
            }
        }
        else {
            if (override_attrs) {
                status = gpm_add_mapping(dst, guest_range_addr, host_range_addr, guest_range_size, set_attrs);
            }
            else {
                status = gpm_add_mapping(dst, guest_range_addr, host_range_addr, guest_range_size, attrs);
            }
            if(FALSE == status) {
                goto failure;
            }
        }
    }

    return TRUE;

failure:
    return FALSE;
}

