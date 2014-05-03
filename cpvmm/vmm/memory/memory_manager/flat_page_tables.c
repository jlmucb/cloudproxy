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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(FLAT_PAGE_TABLES_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(FLAT_PAGE_TABLES_C, __condition)
#include <vmm_defs.h>
#include <guest.h>
#include <guest_cpu.h>
#include <gpm_api.h>
#include <vmm_dbg.h>
#include <memory_address_mapper_api.h>
#include <vmm_phys_mem_types.h>
#include <pat_manager.h>
#include <flat_page_tables.h>
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define FTP_INVALID_RANGE (MAM_MAPPING_SUCCESSFUL+1)

typedef struct {
    MAM_HANDLE mapping;
    MAM_ATTRIBUTES default_attrs;
    UINT32 padding;
} FPT;

FPT*    save_fpt_32 = NULL;
UINT32  save_first_table_32 = 0;
FPT*    save_fpt_64 = NULL;
UINT64  save_first_table_64 = 0;


static
BOOLEAN fpt_create_flat_page_tables(IN GUEST_CPU_HANDLE gcpu,
                  IN BOOLEAN is_32_bit, IN VMM_PHYS_MEM_TYPE mem_type,
                  OUT FPT** flat_tables_handle, OUT UINT64* first_table) {
    GUEST_HANDLE guest;
    GPM_HANDLE gpm;
    GPM_RANGES_ITERATOR iter;
    MAM_HANDLE flat_tables;
    MAM_ATTRIBUTES attrs_full_perm, attrs;
    UINT64 pat;
    UINT32 pat_index;
    FPT* fpt = NULL;
    
    if (is_32_bit) {
        if (save_fpt_32 != NULL) {
            *flat_tables_handle = save_fpt_32;
            *first_table = save_first_table_32;
            return TRUE;
        }
    }
    else {
        if (save_fpt_64 != NULL) {
            *flat_tables_handle = save_fpt_64;
            *first_table        = save_first_table_64;
            return TRUE;
        }
    }    

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(gcpu != NULL);

    guest = gcpu_guest_handle(gcpu);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(guest != NULL);

    gpm = gcpu_get_current_gpm(guest);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(gpm != NULL);

    if (gpm == GPM_INVALID_HANDLE) {
        return FALSE;
    }

    fpt = (FPT*)vmm_malloc(sizeof(FPT));
    if (fpt == NULL) {
        return FALSE;
    }

    pat = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_PAT);
    pat_index = pat_mngr_get_earliest_pat_index_for_mem_type(mem_type, pat);
    if (pat_index == PAT_MNGR_INVALID_PAT_INDEX) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Failed to retrieve PAT index for mem_type=%d\n", __FUNCTION__, mem_type);
        VMM_DEADLOOP();
        goto failed_to_retrieve_pat_index;
    }

    attrs_full_perm.uint32 = 0;
    attrs_full_perm.paging_attr.writable = 1;
    attrs_full_perm.paging_attr.user = 1;
    attrs_full_perm.paging_attr.executable = 1;
    attrs_full_perm.paging_attr.pat_index = pat_index;

    fpt->default_attrs = attrs_full_perm;
    flat_tables = mam_create_mapping(attrs_full_perm);
    if (flat_tables == MAM_INVALID_HANDLE) {
        goto failed_to_create_flat_page_tables;
    }
    fpt->mapping = flat_tables;
    iter = gpm_get_ranges_iterator(gpm);
    if (iter == GPM_INVALID_RANGES_ITERATOR) {
        goto failed_to_get_iterator;
    }

    while (iter != GPM_INVALID_RANGES_ITERATOR) {
        GPA curr_gpa;
        UINT64 curr_size;
        HPA curr_hpa;

        iter = gpm_get_range_details_from_iterator(gpm, iter, (UINT64*)&curr_gpa, 
                        &curr_size);
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT(curr_size != 0);

        if (is_32_bit) {
            if (curr_gpa >= (UINT64) 4 GIGABYTES) {
                break; // no more mappings
            }
            if ((curr_gpa + curr_size) > (UINT64) 4 GIGABYTES) {
                curr_size = ((UINT64) 4 GIGABYTES) - curr_gpa;
            }
        }

        if (gpm_gpa_to_hpa(gpm, curr_gpa, &curr_hpa, &attrs)) {
            if (!mam_insert_range(flat_tables, curr_gpa, curr_hpa, curr_size, attrs_full_perm)) {
                goto inset_to_flat_tables_failed;
            }
        }
    }
    if (is_32_bit) {
        UINT32 first_table_tmp;
        if (!mam_convert_to_32bit_pae_page_tables(flat_tables, &first_table_tmp)) {
            goto failed_to_get_hardware_compliant_tables;
        }
        *first_table = first_table_tmp;
        
        save_fpt_32 = fpt;
        save_first_table_32 = first_table_tmp;
    }
    else {
        if (!mam_convert_to_64bit_page_tables(flat_tables, first_table)) {
            goto failed_to_get_hardware_compliant_tables;
        }
        save_fpt_64 = fpt;
        save_first_table_64 = *first_table;        
    }
    *flat_tables_handle = fpt;
    return TRUE;

failed_to_get_hardware_compliant_tables:
inset_to_flat_tables_failed:
failed_to_get_iterator:
    mam_destroy_mapping(flat_tables);
failed_to_create_flat_page_tables:
failed_to_retrieve_pat_index:
    vmm_mfree(fpt);
    *flat_tables_handle = (FPT*)FPT_INVALID_HANDLE;
    *first_table = ~((UINT64)0);
    return FALSE;
}


// allocate 32bit FPTs in physical memory under 4G
// used only in NO-UG machines, after S3.
// assumptions:
// 1) the memory type is VMM_PHYS_MEM_WRITE_BACK
// 2) the GPA<->HPA is identity map at the OS S3 resume time.
// 
// we made this assumptions since:
// 1) when this function is called, the handles of data structures, e.g. gcpu, guest, gpm are not ready.
// 2) and we cannot call gpm_gpa_to_hpa to convert GPA to HPA.
// 3) we also assume all the processors use the same 32bit FPT tables.
BOOLEAN fpt_create_32_bit_flat_page_tables_under_4G(UINT64 highest_address)
{
    MAM_HANDLE flat_tables;
    MAM_ATTRIBUTES attrs_full_perm;
    FPT* fpt = NULL;
    UINT32 first_table_tmp;
    GPA    curr_gpa = 0;  // start from zero.
    UINT64 curr_size;
    HPA    curr_hpa;
    GPA    max_physical_addr = highest_address < (UINT64) 4 GIGABYTES ? highest_address : (UINT64)4 GIGABYTES ;

    fpt = (FPT*)vmm_memory_alloc(sizeof(FPT));
    if (fpt == NULL) {
        return FALSE;
    }

    attrs_full_perm.uint32 = 0;
    attrs_full_perm.paging_attr.writable   = 1;
    attrs_full_perm.paging_attr.user       = 1;
    attrs_full_perm.paging_attr.executable = 1;
    attrs_full_perm.paging_attr.pat_index  = 0; // assume -- VMM_PHYS_MEM_WRITE_BACK 
    fpt->default_attrs = attrs_full_perm;
    flat_tables = mam_create_mapping(attrs_full_perm);
    if (flat_tables == MAM_INVALID_HANDLE) {
        goto failed_to_create_flat_page_tables;
    }
    fpt->mapping = flat_tables;

    // align to the 4K
    max_physical_addr = ALIGN_FORWARD(max_physical_addr, PAGE_4KB_SIZE);
    // make sure the max_physical_addr is less than 4G.
    if(max_physical_addr > (UINT64)4 GIGABYTES)
        max_physical_addr -= PAGE_4KB_SIZE;
    curr_size = max_physical_addr - curr_gpa;

    // assume GPA=HPA
    // we cannot use gpa_to_hpa() function since its mapping structure is not ready 
    curr_hpa = curr_gpa;

    if (!mam_insert_range(flat_tables, curr_gpa, curr_hpa, curr_size, attrs_full_perm)) {
        goto inset_to_flat_tables_failed;
    }  
    if (!mam_convert_to_32bit_pae_page_tables(flat_tables, &first_table_tmp)) {
        goto failed_to_get_hardware_compliant_tables;
    }
    //cache them
    save_fpt_32  = fpt;
    save_first_table_32 = first_table_tmp;
    return TRUE;

failed_to_get_hardware_compliant_tables:
inset_to_flat_tables_failed:
    mam_destroy_mapping(flat_tables);
    flat_tables = MAM_INVALID_HANDLE;
failed_to_create_flat_page_tables:
    vmm_memory_free(fpt);
    fpt = NULL;
    return FALSE;
}


BOOLEAN fpt_create_32_bit_flat_page_tables(IN GUEST_CPU_HANDLE gcpu,
                     OUT FPT_FLAT_PAGE_TABLES_HANDLE* flat_page_tables_handle,
                     OUT UINT32* pdpt) {
    UINT64 pdpt_tmp = *pdpt;
    BOOLEAN result;

    if (gcpu == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"%s: gcpu == NULL, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }

    result = fpt_create_flat_page_tables(gcpu, TRUE, VMM_PHYS_MEM_WRITE_BACK, (FPT**)flat_page_tables_handle, &pdpt_tmp);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(pdpt_tmp <= 0xffffffff);
    *pdpt = (UINT32)pdpt_tmp;
    return result;
}

BOOLEAN fpt_create_64_bit_flat_page_tables(IN GUEST_CPU_HANDLE gcpu,
                          OUT FPT_FLAT_PAGE_TABLES_HANDLE* flat_page_tables_handle,
                          OUT UINT64* pml4t) {
    if (gcpu == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"%s: gcpu == NULL, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    return fpt_create_flat_page_tables(gcpu, FALSE, VMM_PHYS_MEM_WRITE_BACK, (FPT**)flat_page_tables_handle, pml4t);
}


BOOLEAN fpt_destroy_flat_page_tables(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle) {
    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        return FALSE;
    }

    // do not destroy the FPTs, cache those page tables
    // to support S3 resume on NHM machine with x64 OS installed.
    return TRUE;
}

#ifdef INCLUDE_UNUSED_CODE

BOOLEAN fpt_destroy_flat_page_tables_cpu0(void) {
    VMM_LOG(mask_anonymous, level_trace,"%s\n", __FUNCTION__);

    if ((save_fpt_32 != NULL) && (save_fpt_32->mapping != MAM_INVALID_HANDLE)) {
        mam_destroy_mapping(save_fpt_32->mapping);
        vmm_mfree(save_fpt_32);
        save_fpt_32 = NULL;
        save_first_table_32 = 0;
    }
    if ((save_fpt_64 != NULL) && (save_fpt_64->mapping != MAM_INVALID_HANDLE)) {
        mam_destroy_mapping(save_fpt_64->mapping);
        vmm_mfree(save_fpt_64);
        save_fpt_64 = NULL;
        save_first_table_64 = 0;
    }
    return TRUE;
}


BOOLEAN fpt_insert_range(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                  IN UINT64 src_addr, IN UINT64 tgt_addr, IN UINT64 size) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_ATTRIBUTES attrs;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Invalid handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Something is wrong with handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    attrs.uint32 = fpt->default_attrs.uint32;
    return mam_insert_range(flat_tables_mapping, src_addr, tgt_addr, size, attrs);
}

BOOLEAN fpt_remove_range(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                    IN UINT64 src_addr, IN UINT64 size) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Invalid handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Something is wrong with handle, returning FALSE\n", __FUNCTION__);
        VMM_ASSERT(0);
        return FALSE;
    }
    return mam_insert_not_existing_range(flat_tables_mapping, src_addr, size, FTP_INVALID_RANGE);
}

BOOLEAN fpt_set_writable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                         IN UINT64 src_addr, IN UINT64 size) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_ATTRIBUTES attrs;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        return FALSE;
    }

    flat_tables_mapping = fpt->mapping;

    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Something is wrong with handle, returning FALSE\n", __FUNCTION__);
        VMM_ASSERT(0);
        return FALSE;
    }
    attrs.uint32 = 0;
    attrs.paging_attr.writable = 1;
    return mam_add_permissions_to_existing_mapping(flat_tables_mapping, src_addr, size, attrs);
}

BOOLEAN fpt_clear_writable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                           IN UINT64 src_addr, IN UINT64 size) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_ATTRIBUTES attrs;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Invalid handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        return FALSE;
    }

    attrs.uint32 = 0;
    attrs.paging_attr.writable = 1;
    return mam_remove_permissions_from_existing_mapping(flat_tables_mapping, src_addr, size, attrs);
}

BOOLEAN fpt_set_executable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                           IN UINT64 src_addr,
                           IN UINT64 size) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_ATTRIBUTES attrs;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Invalid handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Something is wrong with handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    attrs.uint32 = 0;
    attrs.paging_attr.executable = 1;
    return mam_add_permissions_to_existing_mapping(flat_tables_mapping, src_addr, size, attrs);
}


BOOLEAN fpt_clear_executable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                           IN UINT64 src_addr, IN UINT64 size) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_ATTRIBUTES attrs;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Invalid handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    flat_tables_mapping = fpt->mapping;

    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        return FALSE;
    }

    attrs.uint32 = 0;
    attrs.paging_attr.executable = 1;
    return mam_remove_permissions_from_existing_mapping(flat_tables_mapping, src_addr, size, attrs);
}


BOOLEAN fpt_is_mapped(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                      IN UINT64 src_addr, OUT BOOLEAN* is_writable) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    UINT64 tgt_addr;
    MAM_ATTRIBUTES attrs;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Invalid handle, returning FALSE\n", __FUNCTION__);
        return FALSE;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        return FALSE;
    }
    if (mam_get_mapping(flat_tables_mapping, src_addr, &tgt_addr, &attrs) != MAM_MAPPING_SUCCESSFUL) {
        return FALSE;
    }
    if (is_writable != NULL) {
        *is_writable = (attrs.paging_attr.writable != 0) ? TRUE : FALSE;
    }
    return TRUE;
}

FPT_RANGES_ITERATOR fpt_get_ranges_iterator(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_MEMORY_RANGES_ITERATOR mam_iter;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        return FPT_INVALID_ITERAROR;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        return FPT_INVALID_ITERAROR;
    }
    mam_iter = mam_get_memory_ranges_iterator(flat_tables_mapping);

    if (mam_iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        return FPT_INVALID_ITERAROR;
    }
    return (FPT_RANGES_ITERATOR)mam_iter;
}
#endif

BOOLEAN fpt_iterator_get_range(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
               IN FPT_RANGES_ITERATOR iter, OUT UINT64* src_addr, OUT UINT64* size) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_MEMORY_RANGES_ITERATOR mam_iter = (MAM_MEMORY_RANGES_ITERATOR)iter;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        return FALSE;
    }
    if (iter == FPT_INVALID_ITERAROR) {
        return FALSE;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        return FALSE;
    }
    VMM_ASSERT(mam_iter != MAM_INVALID_MEMORY_RANGES_ITERATOR);
    mam_get_range_details_from_iterator(flat_tables_mapping, mam_iter, src_addr, size);
    return TRUE;
}

#ifdef INCLUDE_UNUSED_CODE
FPT_RANGES_ITERATOR fpt_iterator_get_next(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                                          IN FPT_RANGES_ITERATOR iter) {
    FPT* fpt = (FPT*)flat_page_tables_handle;
    MAM_HANDLE flat_tables_mapping;
    MAM_MEMORY_RANGES_ITERATOR mam_iter = (MAM_MEMORY_RANGES_ITERATOR)iter;

    if (flat_page_tables_handle == FPT_INVALID_HANDLE) {
        return FPT_INVALID_ITERAROR;
    }
    if (iter == FPT_INVALID_ITERAROR) {
        return FPT_INVALID_ITERAROR;
    }
    flat_tables_mapping = fpt->mapping;
    if (flat_tables_mapping == MAM_INVALID_HANDLE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Something is wrong with handle, returning invalid iterator\n", __FUNCTION__);
        VMM_ASSERT(0);
        return FPT_INVALID_ITERAROR;
    }
    VMM_ASSERT(mam_iter != MAM_INVALID_MEMORY_RANGES_ITERATOR);
    mam_iter = mam_iterator_get_next(flat_tables_mapping, mam_iter);
    if (mam_iter == MAM_INVALID_MEMORY_RANGES_ITERATOR) {
        return FPT_INVALID_ITERAROR;
    }
    return (FPT_RANGES_ITERATOR)mam_iter;
}
#endif
