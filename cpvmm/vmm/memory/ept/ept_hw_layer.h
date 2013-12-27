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

#ifndef _EPT_HW_LAYER_H
#define _EPT_HW_LAYER_H

#include "vmm_defs.h"
#include "vmm_objects.h"
#include "vmm_phys_mem_types.h"
#include "scheduler.h"

#pragma warning( disable : 4214 ) // enables UINT64 bitfield

#define EPT_LOG(...)        VMM_LOG(mask_ept, level_trace, __VA_ARGS__)
#define EPT_PRINTERROR(...) VMM_LOG(mask_ept, level_error, __VA_ARGS__)

#define EPT_NUM_PDPTRS      4

typedef union _EPTP
{
    struct {
        UINT32
            ETMT:3,
            GAW:3,
            Reserved:6,
            AddressSpaceRootLow:20;
        UINT32 AddressSpaceRootHigh;
    } Bits;
    UINT64 Uint64;
} EPTP;

typedef enum
{
    INVEPT_INDIVIDUAL_ADDRESS = 0,
    INVEPT_CONTEXT_WIDE,
    INVEPT_ALL_CONTEXTS
} INVEPT_CMD_TYPE;

typedef enum
{
    INVVPID_INDIVIDUAL_ADDRESS = 0,
    INVVPID_SINGLE_CONTEXT,
    INVVPID_ALL_CONTEXTS,
	INVVPID_SINGLE_CONTEXT_GLOBAL
} INVVPID_CMD_TYPE;

BOOLEAN ept_hw_is_ept_supported(void);
BOOLEAN ept_hw_is_ept_enabled(GUEST_CPU_HANDLE gcpu);

BOOLEAN ept_hw_enable_ept(GUEST_CPU_HANDLE gcpu);
void ept_hw_disable_ept(GUEST_CPU_HANDLE gcpu);

UINT64 ept_hw_get_eptp(GUEST_CPU_HANDLE gcpu);
BOOLEAN ept_hw_set_eptp(GUEST_CPU_HANDLE gcpu, HPA ept_root_hpa, UINT32 gaw);

VMM_PHYS_MEM_TYPE ept_hw_get_ept_memory_type(void);

UINT32 ept_hw_get_guest_address_width(UINT32 actual_gaw);
UINT32 ept_hw_get_guest_address_width_encoding(UINT32 width);
UINT32 ept_hw_get_guest_address_width_from_encoding(UINT32 gaw_encoding);

void ept_hw_set_pdtprs(GUEST_CPU_HANDLE gcpu, UINT64 pdptr[]);
#ifdef INCLUDE_UNUSED_CODE
void ept_hw_get_pdtprs(GUEST_CPU_HANDLE gcpu, UINT64 pdptr[]);
#endif

BOOLEAN ept_hw_is_invept_supported(void);
BOOLEAN ept_hw_invept_all_contexts(void);
BOOLEAN ept_hw_invept_context(UINT64 eptp);
BOOLEAN ept_hw_invept_individual_address(UINT64 eptp, ADDRESS gpa);
BOOLEAN ept_hw_invvpid_single_context(UINT64 vpid);
BOOLEAN ept_hw_invvpid_all_contexts(void);
BOOLEAN ept_hw_is_invvpid_supported(void);
BOOLEAN ept_hw_invvpid_individual_address(UINT64 vpid, ADDRESS gva);


#define CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu) \
    VMM_DEBUG_CODE (                            \
        {                                       \
        CPU_ID host_cpu_id = scheduler_get_host_cpu_id(gcpu);   \
                                                                \
        VMM_ASSERT(host_cpu_id == hw_cpu_id());                 \
        }                                                       \
    )                                                           \

#endif   //_EPT_HW_LAYER_H
