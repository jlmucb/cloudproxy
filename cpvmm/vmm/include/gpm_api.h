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

#ifndef GPM_API_H
#define GPM_API_H

#include <vmm_defs.h>
#include <common_libc.h>
#include <e820_abstraction.h>
#include <vmm_objects.h>
#include <memory_address_mapper_api.h>

typedef void* GPM_VM_HANDLE;
typedef void* GPM_VM_CPU_HANDLE;


// %VT% typedef void* GPM_HANDLE;
// %VT% typedef void* GPM_FLAT_PAGE_TABLES_HANDLE;
#define GPM_INVALID_HANDLE ((GPM_HANDLE)NULL)

typedef UINT64 GPM_RANGES_ITERATOR;
#define GPM_INVALID_RANGES_ITERATOR (~((UINT64)0x0))


/* Function: gpm_create_mapping
*  Description: This function should be called in order to
*               create new GPA -> HPA mapping.
*               Afterwards the mapping may be filled by using functions
*               "gpm_add_mapping" and "gpm_remove_mapping".
*  Return Value: Handle which will be used in all other functions. In case of
*                failure, GPM_INVALID_HANDLE will be returned;
*/
GPM_HANDLE gpm_create_mapping(void);


/* Function: gpm_add_mapping
*  Description: This function should be called in order to
*               create add new GPA -> HPA mapping. If the mapping intersects with
*               already existing one, the old data will be overwritten with new one
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*        gpa - guest physical address to map (must be aligned on page)
*        hpa - target host physical address (must be aligned on page)
*        size - size of the inserted range (must be aligned on page)
*  Return Value: TRUE in case of success
*                FALSE in case of failure. In this case the state of the remainging mapping is undefined;
*/
BOOLEAN gpm_add_mapping(IN GPM_HANDLE gpm_handle, IN GPA gpa, IN HPA hpa, IN UINT64 size, MAM_ATTRIBUTES attrs);


/* Function: gpm_remove_mapping
*  Description: This function should be called in order to
*               remove GPA -> HPA mapping. If the mapping doesn't exist
*               nothing wrong will occur.
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*        gpa - guest physical address (must be aligned on page)
*        size - size of the removed range (must be aligned on page)
*  Return Value: TRUE in case of success
*                FALSE in case of failure. In this case the state of the remainging mapping is undefined;
*/
BOOLEAN gpm_remove_mapping(IN GPM_HANDLE gpm_handle, IN GPA gpa, IN UINT64 size);

/* Function: gpm_add_mmio_range
*  Description: This function should be called in order to
*               insert MMIO range to mapping.
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*        gpa - guest physical address to map (must be aligned on page)
*        size - size of the inserted range (must be aligned on page)
*  Return Value: TRUE in case of success
*                FALSE in case of failure. In this case the state of the remainging mapping is undefined;
*/
BOOLEAN gpm_add_mmio_range(IN GPM_HANDLE gpm_handle, IN GPA gpa, IN UINT64 size);

/* Function: gpm_is_mmio_address
*  Description: This function gives an information whether given address is
*               in MMIO range.
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*        gpa - guest physical address to map (must be aligned on page)
*  Return Value: TRUE or FALSE
*/
BOOLEAN gpm_is_mmio_address(IN GPM_HANDLE gpm_handle, IN GPA gpa);


/* Function: gpm_gpa_to_hpa
*  Description: This function should be called in order to
*               retrieve information about GPA -> HPA mapping.
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*        gpa - guest physical address
*  Output:
*        hpa - host physical address
*  Return Value: TRUE when mapping exists
*                FALSE when mapping doesn't exist
*/
BOOLEAN gpm_gpa_to_hpa(IN GPM_HANDLE gpm_handle, IN GPA gpa, OUT HPA* hpa, OUT MAM_ATTRIBUTES *hpa_attrs);


/* Function: gpm_gpa_to_hva
*  Description: This function should be called as a shortcut
*               to GPA -> HPA, HPA -> HVA mapping.
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*        gpa - guest physical address
*  Output:
*        hva - host virtual address
*  Return Value: TRUE when mapping exists
*                FALSE when mapping doesn't exist
*/
BOOLEAN gpm_gpa_to_hva(IN GPM_HANDLE gpm_handle, IN GPA gpa, OUT HVA* hva);


/* Function: gpm_hpa_to_gpa
*  Description: This function should be called in order to
*               retrieve information about HPA -> GPA mapping.
*  Input:
*        gpm_handle - handle received from "gpm_create_mapping"
*        hpa - host physical address
*  Output:
*        gpa - guest physical address
*  Return Value: TRUE when mapping exists
*                FALSE when mapping doesn't exist
*/
BOOLEAN gpm_hpa_to_gpa(IN GPM_HANDLE gpm_handle, IN HPA hpa, OUT GPA* gpa);



/* Function: gpm_create_e820_map
*  Description: This function is used in order to create e820 memory map as merge between
*               original e820 map and existing GPA -> HPA mappings.
*  Input:
*        gpm_handle - handle received upon creation
*  Output:
*        e820_handle - e820 handle. It may be used as parameter for e820_abstraction module.
*  Return Value: TRUE when operation is successful
*                FALSE when operation has failed
*/
BOOLEAN gpm_create_e820_map(IN GPM_HANDLE gpm_handle,
                            OUT E820_HANDLE* e820_handle);



/* Function: gpm_destroy_e820_map
*  Description: This function is used in order to destroy e820 mapping created by
*               "gpm_create_e820_map" function
*  Input:
*        e820_handle - handle received from "gpm_create_e820_map" function
*/
void gpm_destroy_e820_map(IN E820_HANDLE e820_handle);


/* Function: gpm_get_ranges_iterator
*  Description: This function returns the iterator, using which it is possible to iterate
*               over existing mappings.
*  Input: mam_handle  - handle created by "gpm_create_mapping";
*  Ret value: - Iterator value. NULL iterator has value: GPM_INVALID_RANGES_ITERATOR
*/
GPM_RANGES_ITERATOR gpm_get_ranges_iterator(IN GPM_HANDLE gpm_handle);


/* Function: gpm_get_range_details_from_iterator
*  Description: Use this function in order to retrieve the details of memory range pointed by iterator.
*  Input: gpm_handle  - handle created by "gpm_create_mapping";
*         iter - iterator value
*  Output: src_addr - source address of the existing mapping range. In case
*                     the "iter" has GPM_INVALID_RANGES_ITERATOR value, src_addr will
*                     have 0xfffffffffffffff value.
*          size     - size of the range. In case the "iter" has GPM_INVALID_RANGES_ITERATOR
*                     value, size will be 0.
*  Ret value: - next iterator. Note that this is the only way to get next iterator value.
*/
GPM_RANGES_ITERATOR gpm_get_range_details_from_iterator(IN GPM_HANDLE gpm_handle,
                                                        IN GPM_RANGES_ITERATOR iter,
                                                        OUT GPA* gpa,
                                                        OUT UINT64* size);

void gpm_print(GPM_HANDLE gpm_handle);

BOOLEAN gpm_copy(GPM_HANDLE src, GPM_HANDLE dst, BOOLEAN override_attrs, MAM_ATTRIBUTES set_attrs);

#endif
