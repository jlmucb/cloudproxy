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

#ifndef FLAT_PAGE_TABLES_H
#define FLAT_PAGE_TABLES_H

#include <vmm_defs.h>

typedef void* FPT_FLAT_PAGE_TABLES_HANDLE;
#define FPT_INVALID_HANDLE ((FPT_FLAT_PAGE_TABLES_HANDLE)NULL)

/* Function: fpt_create_32_bit_flat_page_tables
*  Description: This function is used in order to create 32 bit PAE flat page tables for guest
*               according to information recording in GPM
*               with full write/user/execute permissions and WB caching.
*               The following bits must be set in the control registers: CR4.PAE, CR4.PSE, CR0.PG
*
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*  Output:
*        flat_page_table_handle - handle with which the destroying of flat tables will be possible
*        pdpt - host physical address of created flat page tables
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_create_32_bit_flat_page_tables(IN GUEST_CPU_HANDLE gcpu,
                                           OUT FPT_FLAT_PAGE_TABLES_HANDLE* flat_page_tables_handle,
                                           OUT UINT32* pdpt);
/* Function: fpt_create_32_bit_flat_page_tables_under_4G
*  Description: This function is used to create page tables for at most highest_address or 4G.
*               and the memory which holds those page tables is located under 4G physical RAM.
*/
BOOLEAN fpt_create_32_bit_flat_page_tables_under_4G(IN UINT64 highest_address);

/* Function: fpt_create_64_bit_flat_page_tables
*  Description: This function is used in order to create 64 bit flat page tables for guest
*               according to information recording in GPM
*               with full write/user/execute permissions and WB caching.
*               The following bits must be set in the control registers: CR4.PAE, EFER.LME, CR0.PG
*
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*  Output:
*        flat_page_table_handle - handle with which the destroying of flat tables will be possible
*        pml4t - host physical address of created flat page tables
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_create_64_bit_flat_page_tables(IN GUEST_CPU_HANDLE gcpu,
                                           OUT FPT_FLAT_PAGE_TABLES_HANDLE* flat_page_tables_handle,
                                           OUT UINT64* pml4t);



/* Function: fpt_destroy_flat_page_tables
*  Description: This function is used in order to destroy created flat page tables
*               by one of the functions "fpt_create_32_bit_flat_page_tables" or "fpt_create_64_bit_flat_page_tables"
*  Input:
*        flat_page_table_handle - handle received upon creation
*  Return Value: TRUE when operation is successful
*                FALSE when operation has failed
*/
BOOLEAN fpt_destroy_flat_page_tables(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle);

#ifdef INCLUDE_UNUSED_CODE

/* Function: fpt_destroy_flat_page_tables
*  Description: This function is used in order to destroy cached flat page tables
*  for cpu[0].
*  Input:
*        None
*  Return Value: TRUE when operation is successful
*                FALSE when operation has failed
*/
BOOLEAN fpt_destroy_flat_page_tables_cpu0(void);

/* Function: fpt_insert_range
*  Description: This function is used in order to add new ranges with default attributes
*               (Writable/Executable/User/PAT=WB) to existing mapping in
*               flat page tables.
*
*  Input:
*        flat_page_table_handle - returned in creation
*        src_addr - source address (GPA)
*        tgt_addr - target address (HPA)
*        size - size of the range
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_insert_range(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                         IN UINT64 src_addr,
                         IN UINT64 tgt_addr,
                         IN UINT64 size);

/* Function: fpt_remove_range
*  Description: This function is used in order to remove ranges from existing mapping in
*               flat page tables.
*
*  Input:
*        flat_page_table_handle - returned in creation
*        src_addr - source address (GPA)
*        size - size of the range
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_remove_range(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                         IN UINT64 src_addr,
                         IN UINT64 size);

/* Function: fpt_set_writable
*  Description: This function is used in order to add "writable" permission to range
*
*  Input:
*        flat_page_table_handle - returned in creation
*        src_addr - source address (GPA)
*        size - size of the range
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_set_writable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                         IN UINT64 src_addr,
                         IN UINT64 size);
/* Function: fpt_clear_writable
*  Description: This function is used in order to clear "writable" permission in range
*
*  Input:
*        flat_page_table_handle - returned in creation
*        src_addr - source address (GPA)
*        size - size of the range
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_clear_writable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                           IN UINT64 src_addr,
                           IN UINT64 size);

/* Function: fpt_set_executable
*  Description: This function is used in order to add "executable" permission to range
*
*  Input:
*        flat_page_table_handle - returned in creation
*        src_addr - source address (GPA)
*        size - size of the range
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_set_executable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                         IN UINT64 src_addr,
                         IN UINT64 size);

/* Function: fpt_clear_executable
*  Description: This function is used in order to clear "executable" permission in range
*               NOTE, that this function causes EXB bit to be set in page tables - this
*               means that NXE bit must be set in EFER MSR in order to avoid PF exception
*               due to reserved bits.
*
*  Input:
*        flat_page_table_handle - returned in creation
*        src_addr - source address (GPA)
*        size - size of the range
*  Return Value: TRUE when creation is successful
*                FALSE when creation has failed
*/
BOOLEAN fpt_clear_executable(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                           IN UINT64 src_addr,
                           IN UINT64 size);

/* Function: fpt_is_mapped
*  Description: Query whether given address is mapped and writable
*
*  Input:
*        flat_page_table_handle - returned in creation
*        src_addr - source address (GPA)
*  Output:
*        is_writable - in case the function return TRUE, this BOOLEAN value indicates
*                      whether the address has WRITE permissions (can be NULL)
*  Return Value: TRUE in case the address is mapped, FALSE otherwise
*/
BOOLEAN fpt_is_mapped(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                      IN UINT64 src_addr,
                      OUT BOOLEAN* is_writable);

/* Function: fpt_get_ranges_iterator
*  Description: This function returns the iterator, using which it is possible to iterate
*               over existing ranges.
*  Input: flat_page_tables_handle  - handle returned upon creation;
*  Ret value: - Iterator value. NULL iterator has value: FPT_INVALID_ITERAROR
*/
FPT_RANGES_ITERATOR fpt_get_ranges_iterator(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle);
#endif


typedef UINT64 FPT_RANGES_ITERATOR;
#define FPT_INVALID_ITERAROR (~((UINT64)0))


/* Function: fpt_iterator_get_range
*  Description: This function returns the information about range from iterator.
*  Input: flat_page_tables_handle  - handle returned upon creation;
*         iter - iterator
*  Output:
*         src_addr - start address of the range
*         size - size of the range
*  Ret value: - TRUE in case the query is successful, FALSE otherwise
*/
BOOLEAN fpt_iterator_get_range(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                               IN FPT_RANGES_ITERATOR iter,
                               OUT UINT64* src_addr,
                               OUT UINT64* size);

/* Function: fpt_iterator_get_next
*  Description: Advances the iterator to next range.
*  Input: flat_page_tables_handle  - handle returned upon creation;
*         iter - iterator
*  Ret value: - new iterator. In case there is no more ranges, FPT_INVALID_ITERAROR is returned
*/
FPT_RANGES_ITERATOR fpt_iterator_get_next(IN FPT_FLAT_PAGE_TABLES_HANDLE flat_page_tables_handle,
                                          IN FPT_RANGES_ITERATOR iter);

#endif
