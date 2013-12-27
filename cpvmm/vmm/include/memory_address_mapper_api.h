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
/*

  API description of Memory Address Mapper

*/

#ifndef MEMORY_ADDRESS_MAPPER_API_H
#define MEMORY_ADDRESS_MAPPER_API_H

#include <vmm_defs.h>


typedef void* MAM_HANDLE;
#define MAM_INVALID_HANDLE ((MAM_HANDLE)NULL)

typedef UINT64 MAM_MEMORY_RANGES_ITERATOR;
#define MAM_INVALID_MEMORY_RANGES_ITERATOR (~((UINT64)0x0))

typedef union MAM_ATTRIBUTES_U {

    UINT32 uint32;

    struct {
        UINT32
        writable   :1,
        user       :1,
        executable :1,
        global     :1,
        pat_index  :3,
        tmsl	   :1,
		noaccess   :1,
        reserved   :23; // must be zero
    } paging_attr;

    struct {
        UINT32
        readable   :1,
        writable   :1,
        executable :1,
        igmt       :1,
        emt        :3,
        suppress_ve:1,
        reserved   :24; // must be zero
    } ept_attr;

    struct {
        UINT32
        readable   :1,
        writable   :1,
        snoop      :1,
        tm         :1,
        reserved   :28; // must be zero
    } vtdpt_attr;

} MAM_ATTRIBUTES;

extern const MAM_ATTRIBUTES mam_no_attributes;
extern MAM_ATTRIBUTES mam_rwx_attrs;
extern MAM_ATTRIBUTES mam_rw_attrs;
extern MAM_ATTRIBUTES mam_ro_attrs;

#define EPT_NO_PERM 0x0 //no rwx
#define EPT_WO_PERM 0x2 //write only no rx
#define EPT_XO_PERM 0x4 //exec no rw
#define EPT_WX_PERM 0x6 //write exec no r

#define MAM_NO_ATTRIBUTES mam_no_attributes

typedef UINT32 MAM_MAPPING_RESULT;
#define MAM_MAPPING_SUCCESSFUL   ((MAM_MAPPING_RESULT)0x0)
#define MAM_UNKNOWN_MAPPING ((MAM_MAPPING_RESULT)0x7fffffff)


/* Function: mam_create_mapping
*  Description: This function should be called in order to
*               create new mapping.
*               Afterwards the mapping may be filled by using functions
*               "mam_insert_range" and "mam_insert_not_existing_range".
*  Input: inner_level_attributes - attributes for inner levels (relevant for
*                                  hardware compliant mappings)
*                                  If attributes are not relevant, use MAM_NO_ATTRIBUTES
*                                  as the value
*  Output: Handle which will be used in all other functions.
*/
MAM_HANDLE mam_create_mapping(MAM_ATTRIBUTES inner_level_attributes);


/* Function: mam_destroy_mapping
*  Description: Destroys all data structures relevant to particular
*               mapping.
*  Input: handle created by "mam_create_mapping".
*/
void mam_destroy_mapping(IN MAM_HANDLE mam_handle);

/* Function: mam_clone
*  Description: Clone the existing mapping.
*  Input: handle created by "mam_create_mapping".
*/
MAM_HANDLE mam_clone(IN MAM_HANDLE mam_handle);

/* Function: mam_get_mapping
*  Description: return the information inserted by "mam_insert_range" and
*               "mam_insert_not_existing_range" functions.
*  Input: mam_handle - handle created by "mam_create_mapping";
*         src_addr   - source address
*  Return Value:
*                - MAM_MAPPING_SUCCESSFUL in this case there are additional output parameters:
*                  tgt_addr and attrs
*                - MAM_UNKNOWN_MAPPING in case when query is performed and address
*                  that was never inserted neither by "mam_insert_range" nor by
*                  "mam_insert_not_existing_range" functions.
*                - other value of type MAM_MAPPING_RESULT in case when query is performed
*                  for address which was updated by "mam_insert_not_existing_range" before
*                  with this value as "reason" parameter.
*  Output:
*          - tgt_addr - mapped address in case when "Return Value" is MAM_MAPPING_SUCCESSFUL
*          - attrs    - attributes of mapped address when "Return Value" is MAM_MAPPING_SUCCESSFUL
*/
MAM_MAPPING_RESULT mam_get_mapping(IN MAM_HANDLE mam_handle,
                                   IN UINT64 src_addr,
                                   OUT UINT64* tgt_addr,
                                   OUT MAM_ATTRIBUTES* attrs);


/* Function: mam_insert_range
*  Description: Inserts new mapping into the data structures. It is
*               possible to overwrite existing mappings. For example,
*               create 4G of identical mapping:
*                           mam_insert_range(handle, 0, 0, 4G, attrs)
*               then overwrite some range in the middle:
*                           mam_insert_range(handle, src, tgt, 1M, other_attrs)
*  Input: mam_handle  - handle created by "mam_create_mapping";
*         src_addr    - source address
*         tgt_addr    - target address
*         size        - size of the range
*         attrs       - attributes
*  Return value: - TRUE in case of success, the query done by "mam_get_mapping" function
*                  on any src_addr inside the mapped range will be successful and return
*                  value will be MAM_MAPPING_SUCCESSFUL.
*                - FALSE when there was not enough memory to allocate for internal data
*                  structures, hence the mapping wasn't successful. In this case the internal
*                  mapping may be partial, i.e. only part of the requested range will be mapped,
*                  and the remaining part will remain with previous information.
*/
BOOLEAN mam_insert_range(IN MAM_HANDLE mam_handle,
                         IN UINT64 src_addr,
                         IN UINT64 tgt_addr,
                         IN UINT64 size,
                         IN MAM_ATTRIBUTES attrs);


/* Function: mam_insert_not_existing_range
*  Description: Inserts new information (reason) or overwrites existing
*               one: why the current range is unmapped. It is possible
*               to overwrite the existing information in a similar way
*               as with "mam_insert_range" function.
*  Input: mam_handle - handle created by "mam_create_mapping";
*         src_addr   - source address
*         size       - size of the range
*         reason     - this value will be returned by "mam_get_mapping" function
*                      on any query inside the range. This value should be defined
*                      by client and it mustn't be equal to one of the predefined
*                      values: "MAM_MAPPING_SUCCESSFUL" and "MAM_UNKNOWN_MAPPING"
*  Return value: - TRUE in case of success, the query done by "mam_get_mapping" function
*                  on any src_addr inside the mapped range will return the "reason".
*                - FALSE when there was not enough memory to allocate for internal data
*                  structures, hence the mapping wasn't successful. In this case the internal
*                  mapping may be partial, i.e. only part of the requested range will be mapped,
*                  and the remaining part will remain with previous information.
*/
BOOLEAN mam_insert_not_existing_range(IN MAM_HANDLE mam_handle,
                                      IN UINT64 src_addr,
                                      IN UINT64 size,
                                      IN MAM_MAPPING_RESULT reason);


/* Function: mam_add_permissions_to_existing_mapping
*  Description: This function enables adding permissions to already existing ones. If mapping doesn't exist
*               nothing will happen. Note that "pat_index" for page tables attributes and "emt" for ept attributes
*               should be "0" in added attributes. Otherwise the updated pat_index or "emt" will be updated in a way
*               that is not expected by the caller.
*  Input: mam_handle  - handle created by "mam_create_mapping";
*         src_addr    - source address
*         size        -
*         attrs       - attributes to add.
*  Return value: - TRUE in this case of success. In this case there is additional output parameter
*                - FALSE in case of insufficient memory.
*/
BOOLEAN mam_add_permissions_to_existing_mapping(IN MAM_HANDLE mam_handle,
                                                IN UINT64 src_addr,
                                                IN UINT64 size,
                                                IN MAM_ATTRIBUTES attrs);


/* Function: mam_remove_permissions_from_existing_mapping
*  Description: This function enables removing permissions to already existing mappings. If mapping doesn't exist
*               nothing will happen. Note that "pat_index" for page tables attributes and "emt" for ept attributes
*               should be "0" in removed attributes. Otherwise the updated pat_index or "emt" will be updated in a way
*               that is not expected by the caller.
*  Input: nam_handle  - handle created by "mam_create_mapping";
*         src_addr    - source address
*         size        -
*         attrs       - attributes to remove.
*  Return value: - TRUE in this case of success. In this case there is additional output parameter
*                  first_table_out - Host Physical Address of first table (PML4T).
*                - FALSE in case of insufficient memory.
*/
BOOLEAN mam_remove_permissions_from_existing_mapping(IN MAM_HANDLE mam_handle,
                                                     IN UINT64 src_addr,
                                                     IN UINT64 size,
                                                     IN MAM_ATTRIBUTES attrs);

/* Function: mam_convert_to_64bit_page_tables
*  Description: This functions converts internal optimized mapping to 64 bits page Tables.
*               From now on there is no way back to optimized mapping.
*               All the operations will be performed on unoptimized mapping.
*  Input: mam_handle - handle created by "mam_create_mapping";
*  Return value: - TRUE in this case of success. In this case there is additional output parameter
*                  first_table_out - Host Physical Address of first table (PML4T).
*                - FALSE in case of insufficient memory.
*/
BOOLEAN mam_convert_to_64bit_page_tables(IN MAM_HANDLE mam_handle,
                                         OUT UINT64* pml4t_hpa);

/* Function: mam_convert_to_32bit_pae_page_tables
*  Description: This functions converts internal optimized mapping to 32 bit PAE page tables.
*               From now on there is no way back to optimized mapping.
*               All the operations will be performed on unoptimized mapping.
*  Input: mam_handle - handle created by "gam_create_mapping";
*  Return value: - TRUE in this case of success. In this case there is additional output parameter
*                  first_table_out - Host Physical Address of first table (PDPT).
*                - FALSE in case of insufficient memory.
*/
BOOLEAN mam_convert_to_32bit_pae_page_tables(IN MAM_HANDLE mam_handle,
                                             OUT UINT32* pdpt_hpa);

/* Function: mam_get_memory_ranges_iterator
*  Description: This function returns the iterator, using which it is possible to iterate
*               over existing mappings.
*  Input: mam_handle  - handle created by "mam_create_mapping";
*  Ret value: - Iterator value. NULL iterator has value: MAM_INVALID_MEMORY_RANGES_ITERATOR
*/
MAM_MEMORY_RANGES_ITERATOR mam_get_memory_ranges_iterator(IN MAM_HANDLE mam_handle);


/* Function: mam_get_range_details_from_iterator
*  Description: Use this function in order to retrieve the details of memory range pointed by iterator.
*  Input: mam_handle  - handle created by "mam_create_mapping";
*         iter - iterator value
*  Output: src_addr - source address of the existing mapping range. In case
*                     the "iter" has MAM_INVALID_MEMORY_RANGES_ITERATOR value, src_addr will
*                     have 0xfffffffffffffff value.
*          size     - size of the range. In case the "iter" has MAM_INVALID_MEMORY_RANGES_ITERATOR
*                     value, size will be 0.
*  Ret value: - new iterator.
*/
MAM_MEMORY_RANGES_ITERATOR mam_get_range_details_from_iterator(IN MAM_HANDLE mam_handle,
                                                               IN MAM_MEMORY_RANGES_ITERATOR iter,
                                                               OUT UINT64* src_addr,
                                                               OUT UINT64* size);
#ifdef INCLUDE_UNUSED_CODE
/* Function: mam_iterator_get_next
*  Description: Use this function in order to advance iterator to the next range.
*  Input: mam_handle  - handle created by "mam_create_mapping";
*         iter - iterator value
*  Ret value: - new iterator.
*/
MAM_MEMORY_RANGES_ITERATOR mam_iterator_get_next(IN MAM_HANDLE mam_handle,
                                                 IN MAM_MEMORY_RANGES_ITERATOR iter);
#endif

/* Function: mam_get_range_start_address_from_iterator
*  Description: Use this function in order to retrieve the source address of the range pointed by iterator.
*  Input: mam_handle  - handle created by "mam_create_mapping";
*         iter - iterator value
*  Ret value: - address. In case when iterator has value MAM_INVALID_MEMORY_RANGES_ITERATOR, the 0xffffffffffffffff is
*               returned.
*/
UINT64 mam_get_range_start_address_from_iterator(IN MAM_HANDLE mam_handle,
                                                 IN MAM_MEMORY_RANGES_ITERATOR iter);

typedef UINT32 MAM_EPT_SUPER_PAGE_SUPPORT;
#define MAM_EPT_NO_SUPER_PAGE_SUPPORT 0x0
#define MAM_EPT_SUPPORT_2MB_PAGE 0x1
#define MAM_EPT_SUPPORT_1GB_PAGE 0x2
#define MAM_EPT_SUPPORT_512_GB_PAGE 0x4

typedef enum {
    MAM_EPT_21_BITS_GAW = 0,
    MAM_EPT_30_BITS_GAW,
    MAM_EPT_39_BITS_GAW,
    MAM_EPT_48_BITS_GAW
} MAM_EPT_SUPPORTED_GAW;


/* Function: mam_convert_to_ept
*  Description: This functions converts internal optimized mapping to ept.
*               From now on there is no way back to optimized mapping.
*               All the operations will be performed on unoptimized mapping.
*  Input: mam_handle - handle created by "mam_create_mapping";
*         ept_super_page_support - information of which super page can be supported by hardware (bitmask)
*         ept_supported_gaw - Information of how many internal level should there be.
*                             Note that this information should be compliant with one which will be
*                             recorded in EPTR!!!
*         ept_hw_ve_support - Hardware #VE support flag
*  Return value: - TRUE in this case of success. In this case there is additional output parameter
*                  first_table_out - Host Physical Address of first table.
*                - FALSE in case of insufficient memory.
*/
BOOLEAN mam_convert_to_ept(IN MAM_HANDLE mam_handle,
                           IN MAM_EPT_SUPER_PAGE_SUPPORT ept_super_page_support,
                           IN MAM_EPT_SUPPORTED_GAW ept_supported_gaw,
                           IN BOOLEAN ept_hw_ve_support,
                           OUT UINT64* first_table_hpa);

typedef UINT8 MAM_VTDPT_SUPER_PAGE_SUPPORT;
#define MAM_VTDPT_SUPPORT_2MB_PAGE 0x1
#define MAM_VTDPT_SUPPORT_1GB_PAGE 0x2
#define MAM_VTDPT_SUPPORT_512_GB_PAGE 0x4

typedef UINT8 MAM_VTDPT_SNOOP_BEHAVIOR;
typedef UINT8 MAM_VTDPT_TRANS_MAPPING;

typedef enum {
    MAM_VTDPT_21_BITS_GAW = 0,
    MAM_VTDPT_30_BITS_GAW,
    MAM_VTDPT_39_BITS_GAW,
    MAM_VTDPT_48_BITS_GAW
} MAM_VTDPT_SUPPORTED_GAW;

/* Function: mam_convert_to_vtdpt
*  Description: This functions converts internal optimized mapping to VT-d page table.
*               From now on there is no way back to optimized mapping.
*               All the operations will be performed on unoptimized mapping.
*  Input: mam_handle - handle created by "mam_create_mapping";
*         vtdpt_super_page_support - information of which super page can be supported by hardware (bitmask)
*         vtdpt_snoop_behavior - snoop behavior supported by the hardware, treated as reserved:
*                                1. Always in non-leaf entries
*                                2. In leaf entries, as hardware implementations reporting SC (Snoop Control)
*                                  as clear in the extended capability register 
*         vtdpt_trans_mapping - transient mapping supported by hardware, treated as reserved:
*                               1. Always in non-leaf entries
*                               2. In leaf entries, as hardware implementations reporting CH (Caching Hints)
*                                  and Device-IOTLB (DI) fields as clear in the extended capability register 
*         vtdpt_supported_gaw - Information of how many internal level supported by the hardware
*  Return value: - TRUE in this case of success. In this case there is additional output parameter
*                  first_table_out - Host Physical Address of first table.
*                - FALSE in case of insufficient memory.
*/
BOOLEAN mam_convert_to_vtdpt(IN MAM_HANDLE mam_handle,
                           IN MAM_VTDPT_SUPER_PAGE_SUPPORT vtdpt_super_page_support,
						   IN MAM_VTDPT_SNOOP_BEHAVIOR vtdpt_snoop_behavior,
						   IN MAM_VTDPT_TRANS_MAPPING vtdpt_trans_mapping,
                           IN UINT32 sagaw_index_bit,
                           OUT UINT64* first_table_hpa);

void mam_print_page_usage(IN MAM_HANDLE mam_handle);

#endif
