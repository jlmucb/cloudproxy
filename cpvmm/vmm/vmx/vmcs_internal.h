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

#ifndef VMCS_INTERNAL_H
#define VMCS_INTERNAL_H

#include <vmm_defs.h>

void vmcs_destroy_all_msr_lists_internal(struct _VMCS_OBJECT* vmcs,
                                         BOOLEAN addresses_are_in_hpa);

void vmcs_add_msr_to_list(struct _VMCS_OBJECT* vmcs,
                          UINT32 msr_index,
                          UINT64 value,
                          VMCS_FIELD list_address,
                          VMCS_FIELD list_count,
                          UINT32* max_msrs_counter,
                          BOOLEAN is_addres_hpa);

void vmcs_delete_msr_from_list(struct _VMCS_OBJECT*  vmcs,
                               UINT32                msr_index,
                               VMCS_FIELD            list_address,
                               VMCS_FIELD            list_count,
                               BOOLEAN               is_addres_hpa);


INLINE
void vmcs_add_msr_to_vmexit_store_list_internal(struct _VMCS_OBJECT* vmcs,
                                                UINT32 msr_index,
                                                UINT64 value,
                                                BOOLEAN is_msr_list_addr_hpa) {
    vmcs_add_msr_to_list(vmcs, msr_index, value, VMCS_EXIT_MSR_STORE_ADDRESS, VMCS_EXIT_MSR_STORE_COUNT, &vmcs->max_num_of_vmexit_store_msrs, is_msr_list_addr_hpa);
}

INLINE
void vmcs_add_msr_to_vmexit_load_list_internal(struct _VMCS_OBJECT* vmcs,
                                                UINT32 msr_index,
                                                UINT64 value,
                                                BOOLEAN is_msr_list_addr_hpa) {
    vmcs_add_msr_to_list(vmcs, msr_index, value, VMCS_EXIT_MSR_LOAD_ADDRESS, VMCS_EXIT_MSR_LOAD_COUNT, &vmcs->max_num_of_vmexit_load_msrs, is_msr_list_addr_hpa);
}

INLINE
void vmcs_add_msr_to_vmenter_load_list_internal(struct _VMCS_OBJECT* vmcs,
                                                UINT32 msr_index,
                                                UINT64  value,
                                                BOOLEAN is_msr_list_addr_hpa) {
    vmcs_add_msr_to_list(vmcs, msr_index, value, VMCS_ENTER_MSR_LOAD_ADDRESS, VMCS_ENTER_MSR_LOAD_COUNT, &vmcs->max_num_of_vmenter_load_msrs, is_msr_list_addr_hpa);
}


void vmcs_add_msr_to_vmexit_store_and_vmenter_load_lists_internal(struct _VMCS_OBJECT* vmcs,
                                                                  UINT32 msr_index,
                                                                  UINT64 value,
                                                                  BOOLEAN is_msr_list_addr_hpa);


INLINE
void vmcs_delete_msr_from_vmexit_store_list_internal(struct _VMCS_OBJECT* vmcs,
                                                     UINT32 msr_index,
                                                     BOOLEAN is_msr_list_addr_hpa)
{
    vmcs_delete_msr_from_list(vmcs, msr_index, VMCS_EXIT_MSR_STORE_ADDRESS, VMCS_EXIT_MSR_STORE_COUNT, is_msr_list_addr_hpa);
}


INLINE
void vmcs_delete_msr_from_vmexit_load_list_internal(struct _VMCS_OBJECT* vmcs,
                                                    UINT32 msr_index,
                                                    BOOLEAN is_msr_list_addr_hpa)
{
    vmcs_delete_msr_from_list(vmcs, msr_index,VMCS_EXIT_MSR_LOAD_ADDRESS, VMCS_EXIT_MSR_LOAD_COUNT, is_msr_list_addr_hpa);
}


INLINE
void vmcs_delete_msr_from_vmenter_load_list_internal(struct _VMCS_OBJECT* vmcs,
                                                     UINT32 msr_index,
                                                     BOOLEAN is_msr_list_addr_hpa)
{
    vmcs_delete_msr_from_list(vmcs, msr_index, VMCS_ENTER_MSR_LOAD_ADDRESS, VMCS_ENTER_MSR_LOAD_COUNT, is_msr_list_addr_hpa);
}


void vmcs_delete_msr_from_vmexit_store_and_vmenter_load_lists_internal(struct _VMCS_OBJECT*  vmcs,
                                                                       UINT32                msr_index,
                                                                       BOOLEAN               is_msr_list_addr_hpa);


typedef void (*VMCS_ADD_MSR_FUNC)(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
typedef void (*VMCS_CLEAR_MSR_LIST_FUNC)(struct _VMCS_OBJECT* vmcs);
typedef BOOLEAN (*VMCS_IS_MSR_IN_LIST_FUNC)(struct _VMCS_OBJECT* vmcs, UINT32 msr_index);

#endif
