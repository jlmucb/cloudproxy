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

#ifndef _EPT_H
#define _EPT_H

#include "vmm_defs.h"
#include "vmm_objects.h"
#include "memory_address_mapper_api.h"
#include "ept_hw_layer.h"
#include "list.h"
#include "lock.h"

#define ANY_CPU_ID                                   ((CPU_ID) -1)

// internal data structures
typedef struct _EPT_INVEPT_CMD
{
    CPU_ID host_cpu_id;
    char padding[2];
    INVEPT_CMD_TYPE cmd;
    UINT64 eptp; // context
    UINT64 gpa;
} EPT_INVEPT_CMD;

typedef struct _EPT_SET_EPTP_CMD
{
    UINT64 ept_root_table_hpa;
    UINT32 gaw;
    GUEST_ID guest_id;
    UINT16 padding;
    EPT_INVEPT_CMD *invept_cmd;
} EPT_SET_EPTP_CMD;

typedef struct _EPT_CPU_STATE
{
    UINT64 cr0;
    UINT64 cr4;
    BOOLEAN is_initialized;
    BOOLEAN ept_enabled_save;
    UINT64 active_ept_root_table_hpa;
    UINT32 active_ept_gaw;
    UINT32 padding;
} EPT_GUEST_CPU_STATE;

typedef struct _EPT_GUEST_STATE
{
    MAM_HANDLE address_space;
    UINT64 ept_root_table_hpa;
    UINT32 gaw;
    GUEST_ID guest_id;
    UINT16 padding;
    EPT_GUEST_CPU_STATE **gcpu_state;
    LIST_ELEMENT list[1];
} EPT_GUEST_STATE;

typedef struct _EPT_STATE
{
    LIST_ELEMENT guest_state[1]; //EPT_GUEST_STATE
    UINT32 num_of_cpus;
    VMM_LOCK lock;
    UINT32 lock_count;
} EPT_STATE;

void ept_release_lock(void);
void ept_acquire_lock(void);

BOOLEAN ept_is_ept_supported(void);
BOOLEAN ept_is_ept_enabled(IN GUEST_CPU_HANDLE gcpu);
BOOLEAN ept_is_cpu_in_non_paged_mode(GUEST_ID guest_id);

MAM_HANDLE ept_create_guest_address_space(GPM_HANDLE gpm, BOOLEAN original_perms);
MAM_EPT_SUPER_PAGE_SUPPORT ept_get_mam_super_page_support(void);
MAM_EPT_SUPPORTED_GAW ept_get_mam_supported_gaw(UINT32 gaw);
UINT32 ept_get_guest_address_width(GPM_HANDLE gpm);

void ept_set_current_ept(GUEST_CPU_HANDLE gcpu, UINT64 ept_root_table_hpa, UINT32 ept_gaw);
void ept_get_default_ept(GUEST_HANDLE guest, UINT64 *ept_root_table_hpa, UINT32 *ept_gaw);

void ept_set_pdtprs(GUEST_CPU_HANDLE gcpu, UINT64 cr4_value);
UINT64 ept_get_eptp(GUEST_CPU_HANDLE gcpu);
BOOLEAN ept_set_eptp(GUEST_CPU_HANDLE gcpu, UINT64 ept_root_table_hpa, UINT32 gaw);
UINT64 ept_compute_eptp(GUEST_HANDLE guest, UINT64 ept_root_table_hpa, UINT32 gaw);
void ept_invalidate_ept(CPU_ID from, void* arg);

EPT_GUEST_STATE *ept_find_guest_state(GUEST_ID guest_id);

BOOLEAN ept_enable(GUEST_CPU_HANDLE gcpu);
void ept_disable(GUEST_CPU_HANDLE gcpu);

#ifdef DEBUG
void ept_print(IN GUEST_HANDLE guest, IN MAM_HANDLE address_space);
#endif

#endif
