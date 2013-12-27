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

#include <vmm_defs.h>
#include <vmm_dbg.h>
#include <vmm_startup.h>
#include <hw_utils.h>
#include <guest_cpu.h>
#include <em64t_defs.h>
#include <scheduler.h>
#include <lock.h>
#include <vmm_phys_mem_types.h>
#include <pat_manager.h>
#include <host_memory_manager_api.h>
#include <vmm_events_data.h>
#include <event_mgr.h>
#include <host_cpu.h>
#include <flat_page_tables.h>
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(PAT_MANAGER_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(PAT_MANAGER_C, __condition)

#pragma warning (disable : 4100) // enable non-referenced formal parameters

//-------------------------------------------------------------------------------
#define PAT_MNGR_INVALID_PAT_MSR_VALUE (~((UINT64)0))
#define PAT_MNGR_NUM_OF_ATTRUBUTE_FIELDS 8

//-------------------------------------------------------------------------------
static
VMM_PHYS_MEM_TYPE pat_mngr_get_memory_type(UINT64 pat_value, UINT32 index) {
    UINT64 memory_type = ((pat_value >> (index*8)) & 0xff);
    return (VMM_PHYS_MEM_TYPE)memory_type;
}
#ifdef INCLUDE_UNUSED_CODE
static
BOOLEAN pat_mngr_is_memory_type_valid(VMM_PHYS_MEM_TYPE mem_type) {
    switch(mem_type) {
    case VMM_PHYS_MEM_UNCACHABLE:
    case VMM_PHYS_MEM_WRITE_COMBINING:
    case VMM_PHYS_MEM_WRITE_THROUGH:
    case VMM_PHYS_MEM_WRITE_PROTECTED:
    case VMM_PHYS_MEM_WRITE_BACK:
    case VMM_PHYS_MEM_UNCACHED:
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

UINT32 pat_mngr_get_earliest_pat_index_for_mem_type(VMM_PHYS_MEM_TYPE mem_type, UINT64 pat_msr_value) {
    UINT32 i;

    if (pat_msr_value == PAT_MNGR_INVALID_PAT_MSR_VALUE) {
        return PAT_MNGR_INVALID_PAT_INDEX;
    }

    for (i = 0; i < PAT_MNGR_NUM_OF_ATTRUBUTE_FIELDS; i++) {
        if (pat_mngr_get_memory_type(pat_msr_value, i) == mem_type) {
            return i;
        }
    }

    return PAT_MNGR_INVALID_PAT_INDEX;
}

UINT32 pat_mngr_retrieve_current_earliest_pat_index_for_mem_type(VMM_PHYS_MEM_TYPE mem_type) {
    UINT64 pat_msr_value = hw_read_msr(IA32_MSR_PAT);
    UINT32 result = 0;
 

    // assume that PAT MSR not used if its value is ZERO
    // then use compatibility setttings.
    if(pat_msr_value == 0){
        switch(mem_type)
        {
            case VMM_PHYS_MEM_WRITE_BACK:
                result = 0; // see IA32 SDM, table 11-11/12 
                break;
                
            case VMM_PHYS_MEM_UNCACHABLE:
                result = 3; // see IA32 SDM, table 11-11/12 
                break;

            default:
                result = PAT_MNGR_INVALID_PAT_INDEX;
                VMM_LOG(mask_uvmm, level_error,
    		                        "CPU%d: %s: Error: mem type(%d) currently not supported\n",
    		                        hw_cpu_id(), __FUNCTION__, mem_type);
                VMM_DEBUG_CODE(VMM_DEADLOOP();)
                break; 
        }
    }
    else{
        result = pat_mngr_get_earliest_pat_index_for_mem_type(mem_type, pat_msr_value);
    }
    

    return result;
}
#ifdef INCLUDE_UNUSED_CODE
VMM_PHYS_MEM_TYPE pat_mngr_retrieve_current_pat_mem_type(UINT32 pat_index) {
    UINT64 pat_msr_value = hw_read_msr(IA32_MSR_PAT);

    if (pat_index >= PAT_MNGR_NUM_OF_ATTRUBUTE_FIELDS) {
        VMM_ASSERT(0);
        return VMM_PHYS_MEM_UNDEFINED;
    }

    return pat_mngr_get_memory_type(pat_msr_value, pat_index);
}
#endif

#ifdef ENABLE_VTLB
BOOLEAN pat_mngr_get_pat_information(GUEST_CPU_HANDLE gcpu,
                                     UINT64* guest_pat,
                                     UINT64* actual_pat) {
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);

	*guest_pat = gcpu_get_msr_reg(gcpu,IA32_VMM_MSR_PAT);
	*actual_pat = vmcs_read(vmcs, VMCS_HOST_PAT);
	return TRUE;
}
#endif
