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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(PAGE_WALKER_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(PAGE_WALKER_C, __condition)
#include <vmm_defs.h>
#include <vmm_dbg.h>
#include <em64t_defs.h>
#include <gpm_api.h>
#include <host_memory_manager_api.h>
#include <guest.h>
#include <guest_cpu.h>
#include <hw_interlocked.h>
#include <page_walker.h>
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

extern INT32 hw_interlocked_compare_exchange(UINT32 volatile * destination,
					     INT32 expected, INT32 comperand);

typedef union PW_PAGE_ENTRY_U {
    union {
        struct {
            UINT32
            present:1,
            writable:1,
            user:1,
            pwt:1,
            pcd:1,
            accessed:1,
            dirty:1,
            page_size:1,
            global:1,
            available:3,
            addr_base:20;
        } bits;
        UINT32 uint32;
    } non_pae_entry;
    union {
        struct {
            UINT32
                present        :1,
                writable       :1,
                user           :1,
                pwt            :1,
                pcd            :1,
                accessed       :1,
                dirty          :1,
                page_size      :1,
                global         :1,
                available      :3,
                addr_base_low  :20;
            UINT32
                addr_base_high :20,
                avl_or_res     :11,
                exb_or_res     :1;
        } bits;
        UINT64 uint64;
    } pae_lme_entry;
} PW_PAGE_ENTRY;

typedef union PW_PFEC_U {
    struct {
        UINT32
            present     :1,
            is_write    :1,
            is_user     :1,
            is_reserved :1,
            is_fetch    :1,
            reserved    :27;
        UINT32 reserved_high;
    } bits;
    UINT64 uint64;
} PW_PFEC;


#define PW_NUM_OF_TABLE_ENTRIES_IN_PAE_MODE 512
#define PW_NUM_OF_TABLE_ENTRIES_IN_NON_PAE_MODE 1024
#define PW_INVALID_INDEX ((UINT32)(~(0)));
#define PW_PAE_ENTRY_INCREMENT PW_SIZE_OF_PAE_ENTRY
#define PW_NON_PAE_ENTRY_INCREMENT 4
#define PW_PDPTE_INDEX_MASK_IN_32_BIT_ADDR (0xc0000000)
#define PW_PDPTE_INDEX_SHIFT  30
#define PW_PDPTE_INDEX_MASK_IN_64_BIT_ADDR ((UINT64)0x0000007fc0000000)
#define PW_PML4TE_INDEX_MASK ((UINT64)0x0000ff8000000000)
#define PW_PML4TE_INDEX_SHIFT 39
#define PW_PDE_INDEX_MASK_IN_PAE_MODE (0x3fe00000)
#define PW_PDE_INDEX_SHIFT_IN_PAE_MODE 21
#define PW_PDE_INDEX_MASK_IN_NON_PAE_MODE (0xffc00000)
#define PW_PDE_INDEX_SHIFT_IN_NON_PAE_MODE 22
#define PW_PTE_INDEX_MASK_IN_PAE_MODE  (0x1ff000)
#define PW_PTE_INDEX_MASK_IN_NON_PAE_MODE (0x3ff000)
#define PW_PTE_INDEX_SHIFT  12
#define PW_PDPT_ALIGNMENT 32
#define PW_TABLE_SHIFT 12
#define PW_HIGH_ADDRESS_SHIFT 32
#define PW_2M_PAE_PDE_RESERVED_BITS_IN_ENTRY_LOW_MASK ((UINT32)0x1fe000)
#define PW_4M_NON_PAE_PDE_RESERVED_BITS_IN_ENTRY_LOW_MASK ((UINT32)0x3fe000)
#define PW_1G_PAE_PDPTE_RESERVED_BITS_IN_ENTRY_LOW_MASK ((UINT32)0x3fffe000)

UINT32 pw_reserved_bits_high_mask;

INLINE BOOLEAN pw_gpa_to_hpa(GPM_HANDLE gpm_handle, UINT64 gpa, UINT64* hpa) {
	MAM_ATTRIBUTES attrs;
    return gpm_gpa_to_hpa(gpm_handle, gpa, hpa, &attrs);
}

INLINE BOOLEAN pw_hpa_to_hva(IN UINT64 hpa, OUT UINT64* hva) {
    return (hmm_hpa_to_hva(hpa, hva));
}

INLINE void* pw_hva_to_ptr(IN UINT64 hva) {
    return (void*)hva;
}

INLINE UINT64 pw_retrieve_table_from_cr3(UINT64 cr3,
                     BOOLEAN is_pae, BOOLEAN is_lme) {
    if ((!is_pae) || is_lme) {
        return ALIGN_BACKWARD(cr3, PAGE_4KB_SIZE);
    }
    return ALIGN_BACKWARD(cr3, PW_PDPT_ALIGNMENT);
}

static void pw_retrieve_indices(IN UINT64 virtual_address, IN BOOLEAN is_pae, 
                IN BOOLEAN is_lme, OUT UINT32* pml4te_index, 
                OUT UINT32* pdpte_index, OUT UINT32* pde_index, 
                OUT UINT32* pte_index) {
    UINT32 virtual_address_low_32_bit = (UINT32)virtual_address;

    if (is_pae) {
        if (is_lme) {
            UINT64 pml4te_index_tmp = ((virtual_address & PW_PML4TE_INDEX_MASK) >> PW_PML4TE_INDEX_SHIFT);
            UINT64 pdpte_index_tmp = ((virtual_address & PW_PDPTE_INDEX_MASK_IN_64_BIT_ADDR) >> PW_PDPTE_INDEX_SHIFT);

            *pml4te_index = (UINT32)pml4te_index_tmp;
            *pdpte_index = (UINT32)pdpte_index_tmp;
        }
        else {
            *pml4te_index = PW_INVALID_INDEX;
            *pdpte_index = ((virtual_address_low_32_bit & PW_PDPTE_INDEX_MASK_IN_32_BIT_ADDR) >> PW_PDPTE_INDEX_SHIFT);
            VMM_ASSERT(*pdpte_index < PW_NUM_OF_PDPT_ENTRIES_IN_32_BIT_MODE);
        }
        *pde_index = ((virtual_address_low_32_bit & PW_PDE_INDEX_MASK_IN_PAE_MODE) >> PW_PDE_INDEX_SHIFT_IN_PAE_MODE);
        VMM_ASSERT(*pde_index < PW_NUM_OF_TABLE_ENTRIES_IN_PAE_MODE);
        *pte_index = ((virtual_address_low_32_bit & PW_PTE_INDEX_MASK_IN_PAE_MODE) >> PW_PTE_INDEX_SHIFT);
        VMM_ASSERT(*pte_index < PW_NUM_OF_TABLE_ENTRIES_IN_PAE_MODE);
    }
    else {
        *pml4te_index = PW_INVALID_INDEX;
        *pdpte_index = PW_INVALID_INDEX;
        *pde_index = ((virtual_address_low_32_bit & PW_PDE_INDEX_MASK_IN_NON_PAE_MODE) >> PW_PDE_INDEX_SHIFT_IN_NON_PAE_MODE);
        *pte_index = ((virtual_address_low_32_bit & PW_PTE_INDEX_MASK_IN_NON_PAE_MODE) >> PW_PTE_INDEX_SHIFT);
    }
}

static PW_PAGE_ENTRY* pw_retrieve_table_entry(GPM_HANDLE gpm_handle, 
            UINT64 table_gpa, UINT32 entry_index, BOOLEAN is_pae, 
            BOOLEAN use_host_page_tables) {
    UINT64 entry_hpa;
    UINT64 entry_hva;
    UINT64 table_hpa;

    if (use_host_page_tables) {
        table_hpa = table_gpa;
    }
    else if (!pw_gpa_to_hpa(gpm_handle, table_gpa, &table_hpa)) {
        return NULL;
    }
    if (is_pae) {
        entry_hpa = table_hpa + entry_index * PW_PAE_ENTRY_INCREMENT;
    }
    else {
        entry_hpa = table_hpa + entry_index * PW_NON_PAE_ENTRY_INCREMENT;
    }
    if (!pw_hpa_to_hva(entry_hpa, &entry_hva)) {
        return NULL;
    }
    return (PW_PAGE_ENTRY*)pw_hva_to_ptr(entry_hva);
}

static void pw_read_entry_value(PW_PAGE_ENTRY* fill_to, PW_PAGE_ENTRY* fill_from, 
                                BOOLEAN is_pae) {
    if (is_pae) {
        volatile UINT64* original_value_ptr = (volatile UINT64*)fill_from;
        UINT64 value1 = *original_value_ptr;
        UINT64 value2 = *original_value_ptr;

        while (value1 != value2) {
            value1 = value2;
            value2 = *original_value_ptr;
        }
        *fill_to = *((PW_PAGE_ENTRY*)(&value1));
    }
    else {
        fill_to->pae_lme_entry.uint64 = 0; // clear the whole entry;
        fill_to->non_pae_entry.uint32 = fill_from->non_pae_entry.uint32;
    }
}

static BOOLEAN pw_is_big_page_pde(PW_PAGE_ENTRY* entry, BOOLEAN is_lme, 
                BOOLEAN is_pae, BOOLEAN is_pse) {
    if (!entry->non_pae_entry.bits.page_size) { // doesn't matter which type "non_pae" or "pae_lme"
        return FALSE;
    }
    if (is_lme || is_pae) { // ignore pse bit in these cases
        return TRUE;
    }
    return is_pse;
}

INLINE BOOLEAN pw_is_1gb_page_pdpte(PW_PAGE_ENTRY* entry) {
    return (entry->pae_lme_entry.bits.page_size);
}

static BOOLEAN pw_are_reserved_bits_in_pml4te_cleared(PW_PAGE_ENTRY* entry, 
                        BOOLEAN is_nxe) {
    if (entry->pae_lme_entry.bits.addr_base_high & pw_reserved_bits_high_mask) {
        return FALSE;
    }
    if ((!is_nxe) && entry->pae_lme_entry.bits.exb_or_res) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN pw_are_reserved_bits_in_pdpte_cleared(PW_PAGE_ENTRY* entry, 
                                            BOOLEAN is_nxe, BOOLEAN is_lme) {
    if (entry->pae_lme_entry.bits.addr_base_high & pw_reserved_bits_high_mask) {
        return FALSE;
    }
    if (!is_lme) {
        if (entry->pae_lme_entry.bits.avl_or_res ||
            entry->pae_lme_entry.bits.exb_or_res ||
            entry->pae_lme_entry.bits.writable || entry->pae_lme_entry.bits.user) {
            return FALSE;
        }
    }
    else {
        if ((!is_nxe) && entry->pae_lme_entry.bits.exb_or_res) {
            return FALSE;
        }
        if (pw_is_1gb_page_pdpte(entry)) {
            if (entry->pae_lme_entry.uint64 & PW_1G_PAE_PDPTE_RESERVED_BITS_IN_ENTRY_LOW_MASK)
                return FALSE;
        }
    }
    return TRUE;
}

static
BOOLEAN pw_are_reserved_bits_in_pde_cleared(PW_PAGE_ENTRY* entry, BOOLEAN is_nxe,
                                    BOOLEAN is_lme, BOOLEAN is_pae, BOOLEAN is_pse) {
    if (is_pae) {
        if (entry->pae_lme_entry.bits.addr_base_high & pw_reserved_bits_high_mask) {
            return FALSE;
        }
        if ((!is_nxe) && entry->pae_lme_entry.bits.exb_or_res) {
            return FALSE;
        }
        if ((!is_lme) && entry->pae_lme_entry.bits.avl_or_res) {
            return FALSE;
        }
        if (pw_is_big_page_pde(entry, is_lme, is_pae, is_pse)) {
            if (entry->pae_lme_entry.uint64 & PW_2M_PAE_PDE_RESERVED_BITS_IN_ENTRY_LOW_MASK) {
                return FALSE;
            }
        }
    }
    else {
        if (pw_is_big_page_pde(entry, is_lme, is_pae, is_pse) &&
            entry->non_pae_entry.uint32 & PW_4M_NON_PAE_PDE_RESERVED_BITS_IN_ENTRY_LOW_MASK) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN pw_are_reserved_bits_in_pte_cleared(PW_PAGE_ENTRY* pte, 
                    BOOLEAN is_nxe, BOOLEAN is_lme, BOOLEAN is_pae) {
    if (!is_pae) {
        return TRUE;
    }
    if (pte->pae_lme_entry.bits.addr_base_high & pw_reserved_bits_high_mask) {
        return FALSE;
    }
    if ((!is_lme) && (pte->pae_lme_entry.bits.avl_or_res)) {
        return FALSE;
    }
    if ((!is_nxe) && (pte->pae_lme_entry.bits.exb_or_res)) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN pw_is_write_access_permitted(PW_PAGE_ENTRY* pml4te, 
                    PW_PAGE_ENTRY* pdpte, PW_PAGE_ENTRY* pde,
                    PW_PAGE_ENTRY* pte, BOOLEAN is_user, BOOLEAN is_wp, 
                    BOOLEAN is_lme, BOOLEAN is_pae, BOOLEAN is_pse) {
    if ((!is_user) && (!is_wp)) {
        return TRUE;
    }
    if (is_lme) {
        VMM_ASSERT(pml4te != NULL);
        VMM_ASSERT(pdpte != NULL);
        VMM_ASSERT(pml4te->pae_lme_entry.bits.present);
        VMM_ASSERT(pdpte->pae_lme_entry.bits.present);
        if ((!pml4te->pae_lme_entry.bits.writable) ||
            (!pdpte->pae_lme_entry.bits.writable)) {
            return FALSE;
        }
    }
    if (pw_is_1gb_page_pdpte(pdpte)) {
        return TRUE;
    }
    VMM_ASSERT(pde != NULL);
    VMM_ASSERT(pde->non_pae_entry.bits.present);
    if (!pde->non_pae_entry.bits.writable) { // doesn't matter which entry "non_pae" or "pae_lme" is checked
        return FALSE;
    }
    if (pw_is_big_page_pde(pde, is_lme, is_pae, is_pse)) {
        return TRUE;
    }
    VMM_ASSERT(pte != NULL);
    VMM_ASSERT(pte->non_pae_entry.bits.present);
    return (pte->non_pae_entry.bits.writable); // doesn't matter which entry "non_pae" or "pae_lme" is checked
}

static BOOLEAN pw_is_user_access_permitted(PW_PAGE_ENTRY* pml4te, 
                    PW_PAGE_ENTRY* pdpte, PW_PAGE_ENTRY* pde, PW_PAGE_ENTRY* pte, 
                    BOOLEAN is_lme, BOOLEAN is_pae, BOOLEAN is_pse) {
    if (is_lme) {
        VMM_ASSERT(pml4te != NULL);
        VMM_ASSERT(pdpte != NULL);
        VMM_ASSERT(pml4te->pae_lme_entry.bits.present);
        VMM_ASSERT(pdpte->pae_lme_entry.bits.present);
        if ((!pml4te->pae_lme_entry.bits.user) ||
            (!pdpte->pae_lme_entry.bits.user)) {

            return FALSE;
        }
    }
    if (pw_is_1gb_page_pdpte(pdpte)) {
        return TRUE;
    }
    VMM_ASSERT(pde != NULL);
    VMM_ASSERT(pde->non_pae_entry.bits.present);
    if (!pde->non_pae_entry.bits.user) { //doesn't matter which entry "non_pae" or "pae_lme" is checked
        return FALSE;
    }
    if (pw_is_big_page_pde(pde, is_lme, is_pae, is_pse)) {
        return TRUE;
    }
    VMM_ASSERT(pte != NULL);
    VMM_ASSERT(pte->non_pae_entry.bits.present);
    return (pte->non_pae_entry.bits.user); //doesn't matter which entry "non_pae" or "pae_lme" is checked
}

static BOOLEAN pw_is_fetch_access_permitted(PW_PAGE_ENTRY* pml4te, 
                    PW_PAGE_ENTRY* pdpte, PW_PAGE_ENTRY* pde, PW_PAGE_ENTRY* pte,
                    BOOLEAN is_lme, BOOLEAN is_pae, BOOLEAN is_pse) {
    if (is_lme) {
        VMM_ASSERT(pml4te != NULL);
        VMM_ASSERT(pdpte != NULL);
        VMM_ASSERT(pml4te->pae_lme_entry.bits.present);
        VMM_ASSERT(pdpte->pae_lme_entry.bits.present);

        if ((pml4te->pae_lme_entry.bits.exb_or_res) ||
            (pdpte->pae_lme_entry.bits.exb_or_res)) {
            return FALSE;
        }
    }
    if (pw_is_1gb_page_pdpte(pdpte)) {
        return TRUE;
    }
    VMM_ASSERT(pde != NULL);
    VMM_ASSERT(pde->pae_lme_entry.bits.present);
    if (pde->pae_lme_entry.bits.exb_or_res) {
        return FALSE;
    }
    if (pw_is_big_page_pde(pde, is_lme, is_pae, is_pse)) {
        return TRUE;
    }
    VMM_ASSERT(pte != NULL);
    VMM_ASSERT(pte->pae_lme_entry.bits.present);
    return (!pte->pae_lme_entry.bits.exb_or_res);
}


static UINT64 pw_retrieve_phys_addr(PW_PAGE_ENTRY* entry, BOOLEAN is_pae) {
    VMM_ASSERT(entry->non_pae_entry.bits.present);
    if (is_pae) {
        UINT32 addr_low = entry->pae_lme_entry.bits.addr_base_low << PW_TABLE_SHIFT;
        UINT32 addr_high = entry->pae_lme_entry.bits.addr_base_high;
        return ((UINT64)addr_high << PW_HIGH_ADDRESS_SHIFT) | addr_low;
    }
    else {
        return entry->non_pae_entry.bits.addr_base << PW_TABLE_SHIFT;
    }
}

static UINT64 pw_retrieve_big_page_phys_addr(PW_PAGE_ENTRY* entry, BOOLEAN is_pae, 
                    BOOLEAN is_1gb) {
    UINT64 base = pw_retrieve_phys_addr(entry, is_pae);

    // Clean offset bits
    if (is_pae) {
        if (is_1gb) {
            return ALIGN_BACKWARD(base, PAGE_1GB_SIZE);
        } else
            return ALIGN_BACKWARD(base, PAGE_2MB_SIZE);
    }
    // Non-PAE mode
    return ALIGN_BACKWARD(base, PAGE_4MB_SIZE);
}

static UINT32 pw_get_big_page_offset(UINT64 virtual_address, 
                    BOOLEAN is_pae, BOOLEAN is_1gb) {
    if (is_pae) {
        if (is_1gb) {
            // Take only 30 LSBs
            return (UINT32)(virtual_address & PAGE_1GB_MASK);
        } else
            // Take only 21 LSBs
            return (UINT32)(virtual_address & PAGE_2MB_MASK);
    }
    // Take 22 LSBs
    return (UINT32)(virtual_address & PAGE_4MB_MASK);
}

static void pw_update_ad_bits_in_entry(PW_PAGE_ENTRY* native_entry,
                     PW_PAGE_ENTRY* old_native_value,
                     PW_PAGE_ENTRY* new_native_value) {
  // UINT32 cmpxch_result = 0;

    VMM_ASSERT(native_entry != NULL);
    VMM_ASSERT(old_native_value->non_pae_entry.bits.present);
    VMM_ASSERT(new_native_value->non_pae_entry.bits.present);

    if (old_native_value->non_pae_entry.uint32 != new_native_value->non_pae_entry.uint32) {

      hw_interlocked_compare_exchange((UINT32 volatile *)native_entry, old_native_value->non_pae_entry.uint32, new_native_value->non_pae_entry.uint32);
        // The result is not checked. If the cmpxchg has failed,
        // it means that the guest entry was changed,
        // so it is wrong to set status bits on the updated entry
    }
}

static void pw_update_ad_bits(PW_PAGE_ENTRY* guest_space_pml4te, 
                PW_PAGE_ENTRY* pml4te, PW_PAGE_ENTRY* guest_space_pdpte,
                PW_PAGE_ENTRY* pdpte, PW_PAGE_ENTRY* guest_space_pde, 
                PW_PAGE_ENTRY* pde, PW_PAGE_ENTRY* guest_space_pte, 
                PW_PAGE_ENTRY* pte, BOOLEAN is_write_access,
                BOOLEAN is_lme, BOOLEAN is_pae, BOOLEAN is_pse) {
    PW_PAGE_ENTRY pde_before_update;
    PW_PAGE_ENTRY pte_before_update;

    if (is_lme) {
        PW_PAGE_ENTRY pml4te_before_update;
        PW_PAGE_ENTRY pdpte_before_update;

        VMM_ASSERT(guest_space_pml4te != NULL);
        VMM_ASSERT(pml4te != NULL);
        VMM_ASSERT(guest_space_pdpte != NULL);
        VMM_ASSERT(pdpte != NULL);

        pml4te_before_update = *pml4te;
        pml4te->pae_lme_entry.bits.accessed = 1;
        pw_update_ad_bits_in_entry(guest_space_pml4te, &pml4te_before_update, pml4te);

        pdpte_before_update = *pdpte;
        pdpte->pae_lme_entry.bits.accessed = 1;

        if (guest_space_pml4te == guest_space_pdpte) {
            pdpte_before_update.pae_lme_entry.bits.accessed = 1;
        }
        pw_update_ad_bits_in_entry(guest_space_pdpte, &pdpte_before_update, pdpte);
    }
    if (pw_is_1gb_page_pdpte(pdpte)) {
        return;
    }
    VMM_ASSERT(guest_space_pde != NULL);
    VMM_ASSERT(pde != NULL);
    pde_before_update = *pde;
    pde->non_pae_entry.bits.accessed = 1; // doesn't matter which field "non_pae" or "pae_lme" is used
    if ((guest_space_pml4te == guest_space_pde) ||
        (guest_space_pdpte == guest_space_pde)) {
        pde_before_update.non_pae_entry.bits.accessed = 1; // doesn't matter which field "non_pae" or "pae_lme" is used
    }
    if (pw_is_big_page_pde(pde, is_lme, is_pae, is_pse)) {
        if (is_write_access) {
            pde->non_pae_entry.bits.dirty = 1; // doesn't matter which field "non_pae" or "pae_lme" is used
        }
        pw_update_ad_bits_in_entry(guest_space_pde, &pde_before_update, pde);
        return;
    }
    pw_update_ad_bits_in_entry(guest_space_pde, &pde_before_update, pde);
    VMM_ASSERT(guest_space_pte != NULL);
    VMM_ASSERT(pte != NULL);
    pte_before_update = *pte;
    pte->non_pae_entry.bits.accessed = 1; // doesn't matter which field "non_pae" or "pae_lme" is used
    if ((guest_space_pml4te == guest_space_pte) ||
        (guest_space_pdpte == guest_space_pte) ||
        (guest_space_pde == guest_space_pte)) {
        pte_before_update.non_pae_entry.bits.accessed = 1; // doesn't matter which field "non_pae" or "pae_lme" is used
    }
    if (is_write_access) {
        pte->non_pae_entry.bits.dirty = 1; // doesn't matter which field "non_pae" or "pae_lme" is used
    }
    pw_update_ad_bits_in_entry(guest_space_pte, &pte_before_update, pte);
}


PW_RETVAL pw_perform_page_walk(IN GUEST_CPU_HANDLE gcpu, IN UINT64 virt_addr,
                     IN BOOLEAN is_write, IN BOOLEAN is_user, IN BOOLEAN is_fetch,
                     IN BOOLEAN set_ad_bits, OUT UINT64* gpa_out, OUT UINT64* pfec_out) {
    PW_RETVAL retval = PW_RETVAL_SUCCESS;
    PW_PFEC native_pfec;
    GUEST_HANDLE guest_handle = gcpu_guest_handle(gcpu);
    GPM_HANDLE gpm_handle = gcpu_get_current_gpm(guest_handle);
    UINT64 efer_value = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
    BOOLEAN is_nxe = ((efer_value & EFER_NXE) != 0);
    BOOLEAN is_lme = ((efer_value & EFER_LME) != 0);
    UINT64 cr0 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);
    UINT64 cr3 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR3);
    UINT64 cr4 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
    BOOLEAN is_wp = ((cr0 & CR0_WP) != 0);
    BOOLEAN is_pae = ((cr4 & CR4_PAE) != 0);
    BOOLEAN is_pse = ((cr4 & CR4_PSE) != 0);
    UINT64 gpa = PW_INVALID_GPA;
    UINT32 pml4te_index;
    UINT32 pdpte_index;
    UINT32 pde_index;
    UINT32 pte_index;
    UINT64 first_table;
    UINT64 pml4t_gpa;
    PW_PAGE_ENTRY* pml4te_ptr = NULL;
    PW_PAGE_ENTRY pml4te_val;
    UINT64 pdpt_gpa;
    PW_PAGE_ENTRY* pdpte_ptr = NULL;
    PW_PAGE_ENTRY pdpte_val;
    UINT64 pd_gpa;
    PW_PAGE_ENTRY* pde_ptr = NULL;
    PW_PAGE_ENTRY pde_val;
    UINT64 pt_gpa;
    PW_PAGE_ENTRY* pte_ptr = NULL;
    PW_PAGE_ENTRY pte_val;
    BOOLEAN use_host_pt = gcpu_uses_host_page_tables(gcpu);

    pml4te_val.pae_lme_entry.uint64 = 0;
    pdpte_val.pae_lme_entry.uint64 = 0;
    pde_val.pae_lme_entry.uint64 = 0;
    pte_val.pae_lme_entry.uint64 = 0;
    native_pfec.uint64 = 0;
    native_pfec.bits.is_write = (is_write) ? 1 : 0;
    native_pfec.bits.is_user = (is_user) ? 1 : 0;
    native_pfec.bits.is_fetch = (is_pae && is_nxe && is_fetch) ? 1 : 0;

    pw_retrieve_indices(virt_addr, is_pae, is_lme, &pml4te_index, &pdpte_index, &pde_index, &pte_index);

    first_table = pw_retrieve_table_from_cr3(cr3, is_pae, is_lme);
    if (is_pae) {
        if (is_lme) {
            pml4t_gpa = first_table;

            pml4te_ptr = pw_retrieve_table_entry(gpm_handle, pml4t_gpa, pml4te_index, is_pae, use_host_pt);
            if (pml4te_ptr == NULL) {
                retval = PW_RETVAL_PHYS_MEM_VIOLATION;
                goto out;
            }
            pw_read_entry_value(&pml4te_val, pml4te_ptr, is_pae);
            if (!pml4te_val.pae_lme_entry.bits.present) {
                retval = PW_RETVAL_PF;
                goto out;
            }
            if (!pw_are_reserved_bits_in_pml4te_cleared(&pml4te_val, is_nxe)) {
                native_pfec.bits.present = 1;
                native_pfec.bits.is_reserved = 1;
                retval = PW_RETVAL_PF;
                goto out;
            }
            pdpt_gpa = pw_retrieve_phys_addr(&pml4te_val, is_pae);
            pdpte_ptr = pw_retrieve_table_entry(gpm_handle, pdpt_gpa, pdpte_index, is_pae, use_host_pt);
            if (pdpte_ptr == NULL) {
                retval = PW_RETVAL_PHYS_MEM_VIOLATION;
                goto out;
            }
        }
        else {
            // TODO: read PDPT from VMCS
            pdpt_gpa = first_table;
            pdpte_ptr = pw_retrieve_table_entry(gpm_handle, pdpt_gpa, pdpte_index, is_pae, use_host_pt);
            if (pdpte_ptr == NULL) {
                retval = PW_RETVAL_PHYS_MEM_VIOLATION;
                goto out;
            }
        }
        pw_read_entry_value(&pdpte_val, pdpte_ptr, is_pae);
        if (!pdpte_val.pae_lme_entry.bits.present) {
            retval = PW_RETVAL_PF;
            goto out;
        }
        if (!pw_are_reserved_bits_in_pdpte_cleared(&pdpte_val, is_nxe, is_lme)) {
            native_pfec.bits.present = 1;
            native_pfec.bits.is_reserved = 1;
            retval = PW_RETVAL_PF;
            goto out;
        }
    }
    // 1GB page size
    if (pw_is_1gb_page_pdpte(&pdpte_val)) {
        UINT64 big_page_addr;
        UINT32 offset_in_big_page;

        // Retrieve address of the big page in guest space
        big_page_addr = pw_retrieve_big_page_phys_addr(&pdpte_val, is_pae, TRUE);
        // Retrieve offset in page
        offset_in_big_page = pw_get_big_page_offset(virt_addr, is_pae, TRUE);
        // Calculate full guest accessed physical address
        gpa = big_page_addr + offset_in_big_page;
        if ((is_write) &&
            (!pw_is_write_access_permitted(&pml4te_val, &pdpte_val, NULL, NULL, is_user, is_wp, is_lme, is_pae, is_pse))) {
            native_pfec.bits.present = 1;
            retval = PW_RETVAL_PF;
            goto out;
        }

        if (is_user &&
            (!pw_is_user_access_permitted(&pml4te_val, &pdpte_val, NULL, NULL, is_lme, is_pae, is_pse))) {
            native_pfec.bits.present = 1;
            retval = PW_RETVAL_PF;
            goto out;
        }
        if (is_pae && is_nxe && is_fetch &&
            (!pw_is_fetch_access_permitted(&pml4te_val, &pdpte_val, NULL, NULL, is_lme, is_pae, is_pse))) {
            native_pfec.bits.present = 1;
            retval = PW_RETVAL_PF;
            goto out;
        }
        if (set_ad_bits) {
            pw_update_ad_bits(pml4te_ptr, &pml4te_val, pdpte_ptr, &pdpte_val, NULL, NULL,
                              NULL, NULL, is_write, is_lme, is_pae, is_pse);
        }
        retval = PW_RETVAL_SUCCESS;
        goto out;
    }
    pd_gpa = (is_pae) ? pw_retrieve_phys_addr(&pdpte_val, is_pae) : first_table;
    pde_ptr = pw_retrieve_table_entry(gpm_handle, pd_gpa, pde_index, is_pae, use_host_pt);
    if (pde_ptr == NULL) {
        retval = PW_RETVAL_PHYS_MEM_VIOLATION;
        goto out;
    }
    pw_read_entry_value(&pde_val, pde_ptr, is_pae);
    if (!pde_val.non_pae_entry.bits.present) { // doesn't matter which entry "non_pae" or "pae" is checked
        retval = PW_RETVAL_PF;
        goto out;
    }
    if (!pw_are_reserved_bits_in_pde_cleared(&pde_val, is_nxe, is_lme, is_pae, is_pse)) {
        native_pfec.bits.present = 1;
        native_pfec.bits.is_reserved = 1;
        retval = PW_RETVAL_PF;
        goto out;
    }

    // 2MB, 4MB page size
    if (pw_is_big_page_pde(&pde_val, is_lme, is_pae, is_pse)) {
        UINT64 big_page_addr = PW_INVALID_GPA;
        UINT32 offset_in_big_page = 0;

        // Retrieve address of the big page in guest space
        big_page_addr = pw_retrieve_big_page_phys_addr(&pde_val, is_pae, FALSE);
        // Retrieve offset in page
        offset_in_big_page = pw_get_big_page_offset(virt_addr, is_pae, FALSE);
        // Calculate full guest accessed physical address
        gpa = big_page_addr + offset_in_big_page;

        if ((is_write) &&
            (!pw_is_write_access_permitted(&pml4te_val, &pdpte_val, &pde_val, NULL, is_user, is_wp, is_lme, is_pae, is_pse))) {

            native_pfec.bits.present = 1;
            retval = PW_RETVAL_PF;
            goto out;

        }

        if (is_user &&
            (!pw_is_user_access_permitted(&pml4te_val, &pdpte_val, &pde_val, NULL, is_lme, is_pae, is_pse))) {

            native_pfec.bits.present = 1;
            retval = PW_RETVAL_PF;
            goto out;
        }
        if (is_pae && is_nxe && is_fetch &&
            (!pw_is_fetch_access_permitted(&pml4te_val, &pdpte_val, &pde_val, NULL, is_lme, is_pae, is_pse))) {
            native_pfec.bits.present = 1;
            retval = PW_RETVAL_PF;
            goto out;
        }
        if (set_ad_bits) {
            pw_update_ad_bits(pml4te_ptr, &pml4te_val, pdpte_ptr, &pdpte_val, pde_ptr,
                              &pde_val, NULL, NULL, is_write, is_lme, is_pae, is_pse);
        }
        retval = PW_RETVAL_SUCCESS;
        goto out;
    }

    // 4KB page size
    pt_gpa = pw_retrieve_phys_addr(&pde_val, is_pae);
    pte_ptr = pw_retrieve_table_entry(gpm_handle, pt_gpa, pte_index, is_pae, use_host_pt);
    if (pte_ptr == NULL) {
        retval = PW_RETVAL_PHYS_MEM_VIOLATION;
        goto out;
    }

    pw_read_entry_value(&pte_val, pte_ptr, is_pae);

    if (!pte_val.non_pae_entry.bits.present) { // doesn't matter which field "non_pae" of "pae_lme" is used
        retval = PW_RETVAL_PF;
        goto out;
    }

    if (!pw_are_reserved_bits_in_pte_cleared(&pte_val, is_nxe, is_lme, is_pae)) {
        native_pfec.bits.present = 1;
        native_pfec.bits.is_reserved = 1;
        retval = PW_RETVAL_PF;
        goto out;
    }

    // Retrieve GPA of guest PT
    gpa = pw_retrieve_phys_addr(&pte_val, is_pae);

    if (is_write &&
        (!pw_is_write_access_permitted(&pml4te_val, &pdpte_val, &pde_val, &pte_val, is_user, is_wp, is_lme, is_pae, is_pse))) {
        native_pfec.bits.present = 1;
        retval = PW_RETVAL_PF;
        goto out;
    }

    if (is_user &&
        (!pw_is_user_access_permitted(&pml4te_val, &pdpte_val, &pde_val, &pte_val, is_lme, is_pae, is_pse))) {

        native_pfec.bits.present = 1;
        retval = PW_RETVAL_PF;
        goto out;
    }

    if (is_pae && is_nxe && is_fetch &&
        (!pw_is_fetch_access_permitted(&pml4te_val, &pdpte_val, &pde_val, &pte_val, is_lme, is_pae, is_pse))) {

        native_pfec.bits.present = 1;
        retval = PW_RETVAL_PF;
        goto out;
    }
    if (set_ad_bits) {
        pw_update_ad_bits(pml4te_ptr, &pml4te_val, pdpte_ptr, &pdpte_val, pde_ptr, 
                          &pde_val, pte_ptr, &pte_val, is_write, is_lme, is_pae, is_pse);
    }
    gpa |= (virt_addr & PAGE_4KB_MASK); // add offset
    retval = PW_RETVAL_SUCCESS; // page walk succeeded

out:
    if (gpa_out != NULL) {
        *gpa_out = gpa;
    }

    if ((retval == PW_RETVAL_PF) && (pfec_out != NULL)) {
        *pfec_out = native_pfec.uint64;
    }
    return retval;
}

BOOLEAN pw_is_pdpt_in_32_bit_pae_mode_valid(IN GUEST_CPU_HANDLE gcpu, IN void* pdpt_ptr) {
    UINT64 efer_value;
    BOOLEAN is_nxe;
    BOOLEAN is_lme;
    HVA pdpte_hva = (HVA)pdpt_ptr;
    HVA final_pdpte_hva = pdpte_hva + (PW_NUM_OF_PDPT_ENTRIES_IN_32_BIT_MODE * PW_PAE_ENTRY_INCREMENT);

    efer_value = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
    is_nxe = ((efer_value & EFER_NXE) != 0);
    is_lme = ((efer_value & EFER_LME) != 0);

    for (pdpte_hva = (HVA)pdpt_ptr; pdpte_hva < final_pdpte_hva;  pdpte_hva += PW_PAE_ENTRY_INCREMENT) {
        PW_PAGE_ENTRY* pdpte = (PW_PAGE_ENTRY*)pdpte_hva;
        if (!pdpte->pae_lme_entry.bits.present) {
            continue;
        }
        if (!pw_are_reserved_bits_in_pdpte_cleared(pdpte, is_nxe, is_lme)) {
           return FALSE;
        }
    }
    return TRUE;
}
