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

#ifndef VMM_STACK_H
#define VMM_STACK_H

#ifdef DEBUG
#define VMM_STACK_DEBUG_CODE
#endif


typedef struct VMM_STACKS_INFO_S {
    UINT64 stacks_base;
    UINT32 size_of_single_stack;
    UINT32 max_allowed_cpus;
    UINT32 num_of_exception_stacks;
    BOOLEAN is_initialized;
} VMM_STACKS_INFO;

INLINE
UINT64 vmm_stacks_info_get_stacks_base(const VMM_STACKS_INFO* stacks_info) {
    return stacks_info->stacks_base;
}

INLINE
void vmm_stacks_info_set_stacks_base(VMM_STACKS_INFO* stacks_info, UINT64 base) {
    stacks_info->stacks_base = base;
}

INLINE
UINT32 vmm_stacks_info_get_size_of_single_stack(const VMM_STACKS_INFO* stacks_info) {
    return stacks_info->size_of_single_stack;
}

INLINE
void vmm_stacks_info_set_size_of_single_stack(VMM_STACKS_INFO* stacks_info, UINT32 size) {
    stacks_info->size_of_single_stack = size;
}

INLINE
UINT32 vmm_stacks_info_get_max_allowed_cpus(const VMM_STACKS_INFO* stacks_info) {
    return stacks_info->max_allowed_cpus;
}

INLINE
void vmm_stacks_info_set_max_allowed_cpus(VMM_STACKS_INFO* stacks_info, UINT32 cpus_num) {
    stacks_info->max_allowed_cpus = cpus_num;
}

INLINE
UINT32 vmm_stacks_info_get_num_of_exception_stacks(const VMM_STACKS_INFO* stacks_info) {
    return stacks_info->num_of_exception_stacks;
}

INLINE
void vmm_stacks_info_set_num_of_exception_stacks(VMM_STACKS_INFO* stacks_info, UINT32 num_of_stacks) {
    stacks_info->num_of_exception_stacks = num_of_stacks;
}

INLINE
BOOLEAN vmm_stacks_is_initialized(const VMM_STACKS_INFO* stacks_info) {
    return stacks_info->is_initialized;
}

INLINE
void vmm_stacks_set_initialized(VMM_STACKS_INFO* stacks_info) {
    stacks_info->is_initialized = TRUE;
}

#endif
