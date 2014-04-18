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

#ifndef PAT_MANAGER_H
#define PAT_MANAGER_H

#include <vmm_defs.h>
#include <vmm_startup.h>
#include <vmm_phys_mem_types.h>
#include <guest_cpu.h>

#define PAT_MNGR_INVALID_PAT_INDEX 0xffffffff

UINT32 pat_mngr_get_earliest_pat_index_for_mem_type(VMM_PHYS_MEM_TYPE mem_type, 
                UINT64 pat_msr_value);

UINT32 pat_mngr_retrieve_current_earliest_pat_index_for_mem_type(
                VMM_PHYS_MEM_TYPE mem_type);

VMM_PHYS_MEM_TYPE pat_mngr_retrieve_current_pat_mem_type(UINT32 pat_index);

BOOLEAN pat_mngr_get_pat_information(GUEST_CPU_HANDLE gcpu,
                UINT64* guest_pat, UINT64* host_pat);
#endif
