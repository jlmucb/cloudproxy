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

#ifndef HOST_MEMORY_MANAGER_API_H
#define HOST_MEMORY_MANAGER_API_H

#include <vmm_defs.h>
#include <vmm_startup.h>
#include <common_libc.h>
#include <vmm_phys_mem_types.h>

#define HMM_INVALID_VMM_PAGE_TABLES (~((UINT64)0x0))


/* Function: hmm_initialize
*  Description: This function should be called in order to
*               initialize Host Memory Manager. This function must be called first.
*  Input: startup_struct - pointer to startup data structure
*  Return Value: TRUE in case the initialization is successful.
*/
BOOLEAN hmm_initialize(const VMM_STARTUP_STRUCT* startup_struct);


/* Function: hmm_get_vmm_page_tables
*  Description: This function will create existing mapping to hardware compliant.
*               IMPORTANT: It will use its own existing HVA-->HPA mapping in order
*                          to create hardware compliant page tables, hence the
*                          mapping must already exist.
*  Return Value: Host Physical Address of VMM page tables. In case of failure
*                (tables weren't created) the HMM_INVALID_VMM_PAGE_TABLES value
*                will be returned.
*/
HPA hmm_get_vmm_page_tables(void);


/* Function: hmm_hva_to_hpa
*  Description: This function is used in order to convert Host Virtual Address
*               to Host Physical Address (HVA-->HPA).
*  Input: hva - host virtual address.
*  Output: hpa - host physical address.
*  Return Value: TRUE in case the mapping successful (it exists).
*/
BOOLEAN hmm_hva_to_hpa(IN HVA hva, OUT HPA* hpa);

#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_hva_to_hpa_with_attr
*  Description: This function is used in order to convert Host Virtual Address
*               to Host Physical Address (HVA-->HPA).
*  Input: hva - host virtual address.
*  Output: hpa - host physical address.
*          is_writable -
*          is_executable -
*          pat_index-
*  Return Value: TRUE in case the mapping successful (it exists).
*/
BOOLEAN hmm_hva_to_hpa_with_attr(IN HVA hva,
                                 OUT HPA* hpa,
                                 OUT BOOLEAN* is_writable,
                                 OUT BOOLEAN* is_executable,
                                 OUT UINT32* pat_index);
#endif


/* Function: hmm_hpa_to_hva
*  Description: This function is used in order to convert Host Physical Address
*               to Host Virtual Address (HPA-->HVA), i.e. converting physical address
*               to pointer.
*  Input: hpa - host physical address.
*  Output: hva - host virtual address.
*  Return Value: TRUE in case the mapping successful (it exists).
*/
BOOLEAN hmm_hpa_to_hva(IN HPA hpa, OUT HVA* hva);

/* Function: hmm_is_new_pat_value_consistent
*  Description: This function is used to check whether HMM could work with new PAT value.
*/
BOOLEAN hmm_is_new_pat_value_consistent(UINT64 pat_value);


/* Function: hmm_unmap_hpa
*  Description: This function is used in order to unmap HVA -> HPA references
*               to physical address
*  Input: hpa - host physical address - must be aligned on page
*         size - size in bytes, but must be alinged on page size (4K, 8K, ...)
*         flush_tlbs_on_all_cpus - TRUE in case when flush TLB on all cpus is required
*  Return Value: TRUE in case the unmap was successful
*                FALSE in case the operation failed. In this case the state of inner mappings is undefined.
*/
BOOLEAN hmm_unmap_hpa(IN HPA hpa, UINT64 size, BOOLEAN flush_tlbs_on_all_cpus);


/* Function: hmm_get_hpa_type
*  Description: returns the memory type of physical address (MTRR type)
*  Input: hpa - host physical address
*  Return Value: Memory type
*/
VMM_PHYS_MEM_TYPE hmm_get_hpa_type(IN HPA hpa);


/* Function: hmm_does_memory_range_have_specified_memory_type
*  Description: Checks whether the given physical address range has given memory type
*  Input: hpa - host physical address
*         size - size of the range,
*         mem_type - expected memory type.
*  Return Value: TRUE in case the memory range has given memory type
*                FALSE otherwise
*/
BOOLEAN hmm_does_memory_range_have_specified_memory_type(IN HPA start_hpa, IN UINT64 size, VMM_PHYS_MEM_TYPE mem_type);

#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_get_final_memory_type_after_hva_access
*  Description: returns the final memory type of address (combination of MTRR and PAT)
*  Input: hva - host virtual address
*  Return Value: Memory type
*/
VMM_PHYS_MEM_TYPE hmm_get_final_memory_type_after_hva_access(IN HVA hva);
#endif


#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_disable_page_level_write_protection
*  Description: Clears WP bit in CR0
*/
void hmm_disable_page_level_write_protection(void);


/* Function: hmm_disable_page_level_write_protection
*  Description: Sets WP bit in CR0
*/
void hmm_enable_page_level_write_protection(void);

/* Function: hmm_is_page_level_write_protected
*  Description: Checks whether WP in CR0 is set
*/
BOOLEAN hmm_is_page_level_write_protected(void);
#endif


/* Function: hmm_set_required_values_to_control_registers
*  Description: Sets required bits to CRs and EFER and must be called
*               on all cpus after HMM initialization
*               Currently the functions sets WP in CR0 and NXE in EFER
*/
void hmm_set_required_values_to_control_registers(void);

#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_disable_update_of_page
*  Description: Removes WRITABLE access permission for given page
*/
BOOLEAN hmm_disable_update_of_page(HVA page, BOOLEAN invlpg_on_all_cpus);


/* Function: hmm_enable_update_of_page
*  Description: Sets WRITABLE access permission for given page
*/
BOOLEAN hmm_enable_update_of_page(HVA page);


/* Function: hmm_map_physical_page
*  Description: Maps physical page to VMM page tables
*  Ret. value: TRUE in case of success. FALSE in case of insufficient memory
*              In case of failure the state of internal mappings may be inconsistent.
*/
BOOLEAN hmm_map_physical_page(IN HPA page_hpa,
                              IN BOOLEAN is_writable,
                              IN BOOLEAN is_executable,
                              IN UINT32 pat_index,
                              IN BOOLEAN flash_all_tlbs_if_needed,
                              OUT HVA* page_hva);
/* Function: hmm_map_physical_page
*  Description: Maps "write back" physical page to VMM page tables
*  Ret. value: TRUE in case of success. FALSE in case of insufficient memory
*              In case of failure the state of internal mappings may be inconsistent.
*/
BOOLEAN hmm_map_wb_physical_page(IN HPA page_hpa,
                                 IN BOOLEAN is_writable,
                                 IN BOOLEAN is_executable,
                                 IN BOOLEAN flash_all_tlbs_if_needed,
                                 OUT HVA* page_hva);
#endif

/* Function: hmm_map_physical_page
*  Description: Maps "uncachable" physical page to VMM page tables
*  Ret. value: TRUE in case of success. FALSE in case of insufficient memory
*              In case of failure the state of internal mappings may be inconsistent.
*/
BOOLEAN hmm_map_uc_physical_page(IN HPA page_hpa,
                                 IN BOOLEAN is_writable,
                                 IN BOOLEAN is_executable,
                                 IN BOOLEAN flash_all_tlbs_if_needed,
                                 OUT HVA* page_hva);

#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_alloc_continuous_virtual_buffer_for_pages
*  Description: Temporary maps continuous virtual buffer for the given array of HPAs.
*               Note, that the existing HPA <-> HVA mapping for the given tables are not updated,
*               just new mapping of HVA->HPA is added to virtual tables of HMM
*               In order to remove this temporary mapping use "hmm_free_continuous_virtual_buffer" function
*  Ret. value: TRUE in case of success. FALSE in case of insufficient memory
*              In case of failure the state of internal mappings may be inconsistent.
*/
BOOLEAN hmm_alloc_continuous_virtual_buffer_for_pages(IN UINT64* hpas_array,
                                                      IN UINT32 num_of_pages,
                                                      IN BOOLEAN is_writable,
                                                      IN BOOLEAN is_executable,
                                                      IN UINT32 pat_index,
                                                      OUT UINT64* hva);

/* Function: hmm_alloc_continuous_wb_virtual_buffer_for_pages
*  Description: Temporary maps continuous virtual buffer for the given array of HPAs with WB caching attributes.
*               Note, that the existing HPA <-> HVA mapping for the given tables are not updated,
*               just new mapping of HVA->HPA is added to virtual tables of HMM
*               In order to remove this temporary mapping use "hmm_free_continuous_virtual_buffer" function
*  Ret. value: TRUE in case of success. FALSE in case of insufficient memory
*              In case of failure the state of internal mappings may be inconsistent.
*/
BOOLEAN hmm_alloc_continuous_wb_virtual_buffer_for_pages(IN UINT64* hpas_array,
                                                         IN UINT32 num_of_pages,
                                                         IN BOOLEAN is_writable,
                                                         IN BOOLEAN is_executable,
                                                         OUT UINT64* hva);

/* Function: hmm_alloc_additional_continuous_virtual_buffer_no_attr_change
*  Description: Maps additional TEMPORARY virtual buffer to existing physical pages, the
*               buffer can be unmapped by using "hmm_free_continuous_virtual_buffer" function.
*               The attributes are copied from original mapping which MUST exist.
*               Note, that the existing HPA <-> HVA mapping for the given tables are not updated,
*               just new mapping of HVA->HPA is added to virtual tables of HMM.
*  Arguments:
*             current_hva - currently mapped HVA
*             additional_hva - additional address of virtual buffer
*             num_of_pages - size of the buffer in pages
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal DEADLOOP will occur.
*/
BOOLEAN hmm_alloc_additional_continuous_virtual_buffer_no_attr_change(IN UINT64 current_hva,
                                                                      IN UINT64 additional_hva,
                                                                      IN UINT32 num_of_pages);

#endif
/* Function: hmm_alloc_additional_continuous_virtual_buffer
*  Description: Maps additional temporary virtual buffer to existing physical pages, the
*               buffer can be unmapped by using "hmm_free_continuous_virtual_buffer" function.
*               Note, that the existing HPA <-> HVA mapping for the given tables are not updated,
*               just new mapping of HVA->HPA is added to virtual tables of HMM
*  Arguments:
*             current_hva - currently mapped HVA
*             additional_hva - additional address of virtual buffer
*             num_of_pages - size of the buffer in pages
*             is_writable - set buffer writable
*             is_executable - set buffer executable
*             pat_index - pat index
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal DEADLOOP will occur.
*/
BOOLEAN hmm_alloc_additional_continuous_virtual_buffer(IN UINT64 current_hva,
                                                       IN UINT64 additional_hva,
                                                       IN UINT32 num_of_pages,
                                                       IN BOOLEAN is_writable,
                                                       IN BOOLEAN is_executable,
                                                       IN UINT32 pat_index);

#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_alloc_additional_continuous_wb_virtual_buffer
*  Description: Maps additional TEMPORARY virtual buffer to existing physical pages with
*               "write back" caching attributes, the buffer can be unmapped by using
*               "hmm_free_continuous_virtual_buffer" function.
*               Note, that the existing HPA <-> HVA mapping for the given tables are not updated,
*               just new mapping of HVA->HPA is added to virtual tables of HMM
*  Arguments:
*             current_hva - currently mapped HVA
*             additional_hva - additional address of virtual buffer
*             num_of_pages - size of the buffer in pages
*             is_writable - set buffer writable
*             is_executable - set buffer executable
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal DEADLOOP will occur.
*/
BOOLEAN hmm_alloc_additional_continuous_wb_virtual_buffer(IN UINT64 current_hva,
                                                          IN UINT64 additional_hva,
                                                          IN UINT32 num_of_pages,
                                                          IN BOOLEAN is_writable,
                                                          IN BOOLEAN is_executable);
#endif

/* Function: hmm_free_continuous_virtual_buffer
*  Description: Removes mapping of TEMPORARY virtual buffer.
*  Ret. value: TRUE in case of success. FALSE in case of insufficient memory
*              In case of failure the state of internal mappings may be inconsistent.
*/
BOOLEAN hmm_free_continuous_virtual_buffer(UINT64 buffer_hva,
                                           UINT32 num_of_pages);


/* Function: hmm_make_phys_page_uncachable
*  Description: Updates VMM page tables, so that access to given physical page will be UC (Uncachable).
*  Ret. value: TRUE in case of success. FALSE in case of insufficient memory
*              In case of failure the state of internal mappings may be inconsistent.
*/
BOOLEAN hmm_make_phys_page_uncachable(UINT64 page_hpa);

#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_remap_virtual_memory_no_attr_change
*  Description: Remaps virtual memory buffer preserving existing attributes.
*  Arguments:
*             from_hva - currently mapped virtual address
*             to_hva - new virtual address
*             size - size of the buffer
*             flash_tlbs - flash all hardware TLBs
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal DEADLOOP will occur.
*/
BOOLEAN hmm_remap_virtual_memory_no_attr_change(HVA from_hva,
                                                HVA to_hva,
                                                UINT32 size,
                                                BOOLEAN flash_tlbs);
#endif

/* Function: hmm_remap_virtual_memory
*  Description: Remaps virtual memory buffer with newly given attributes.
*  Arguments:
*             from_hva - currently mapped virtual address
*             to_hva - new virtual address
*             size - size of the buffer
*             is_writable - set buffer "writable"
*             is_executable - set buffer "executable"
*             pat_index - pat index
*             flash_tlbs - flash all hardware TLBs
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal DEADLOOP will occur.
*/
BOOLEAN hmm_remap_virtual_memory(HVA from_hva,
                                 HVA to_hva,
                                 UINT32 size,
                                 BOOLEAN is_writable,
                                 BOOLEAN is_executable,
                                 UINT32 pat_index,
                                 BOOLEAN flash_tlbs);

#ifdef INCLUDE_UNUSED_CODE
/* Function: hmm_remap_wb_virtual_memory
*  Description: Remaps virtual memory buffer with newly given attributes and WB caching attributes.
*  Arguments:
*             from_hva - currently mapped virtual address
*             to_hva - new virtual address
*             size - size of the buffer
*             is_writable - set buffer "writable"
*             is_executable - set buffer "executable"
*             flash_tlbs - flash all hardware TLBs
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal DEADLOOP will occur.
*/
BOOLEAN hmm_remap_wb_virtual_memory(HVA from_hva,
                                    HVA to_hva,
                                    UINT32 size,
                                    BOOLEAN is_writable,
                                    BOOLEAN is_executable,
                                    BOOLEAN flash_tlbs);


/* Function: hmm_remap_physical_pages_to_continuous_virtal_addr_copy_attrs
*  Description: Remaps given physical pages to new continuous virtual buffer with HPA->HVA mapping udpate.
*               Note, that these pages must be mapped already in both directions HPA<->HVA and the mapping
*               attributes are copied from existing mapping.
*  Arguments:
*             hpas_array - array of HPAs
*             num_of_pages - number of array elements
*  Output:
*             hva - HVA of virtual buffer
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal ASSERT will occur.
*/
BOOLEAN hmm_remap_physical_pages_to_continuous_virtal_addr_copy_attrs(IN UINT64* hpas_array,
                                                                      IN UINT32 num_of_pages,
                                                                      OUT UINT64* hva);
/* Function: hmm_remap_physical_pages_to_continuous_virtal_addr
*  Description: Remaps given physical pages to new continuous virtual buffer with HPA->HVA mapping udpate.
*  Arguments:
*             hpas_array - array of HPAs
*             num_of_pages - number of array elements
*             is_writable - writable permission
*             is_executable - executable permission
*             pat_index - pat index
*  Output:
*             hva - HVA of virtual buffer
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal ASSERT will occur.
*/
BOOLEAN hmm_remap_physical_pages_to_continuous_virtal_addr(IN UINT64* hpas_array,
                                                           IN UINT32 num_of_pages,
                                                           IN BOOLEAN is_writable,
                                                           IN BOOLEAN is_executable,
                                                           IN UINT32 pat_index,
                                                           OUT UINT64* hva);
#endif


/* Function: hmm_remap_physical_pages_to_continuous_wb_virtal_addr
*  Description: Remaps given physical pages to new continuous virtual buffer with HPA->HVA mapping udpate.
*               The pages are mapped with WB caching attributes
*  Arguments:
*             hpas_array - array of HPAs
*             num_of_pages - number of array elements
*             is_writable - writable permission
*             is_executable - executable permission
*  Output:
*             hva - HVA of virtual buffer
*  Ret. value: TRUE in case of success. FALSE in case when mapping is impossible.
*  Remark: In case of insufficient memory internal ASSERT will occur.
*/
BOOLEAN hmm_remap_physical_pages_to_continuous_wb_virtal_addr(IN UINT64* hpas_array,
                                                              IN UINT32 num_of_pages,
                                                              IN BOOLEAN is_writable,
                                                              IN BOOLEAN is_executable,
                                                              OUT UINT64* hva);
#endif
