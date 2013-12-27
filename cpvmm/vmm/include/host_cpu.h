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

#ifndef _HOST_CPU_H_
#define _HOST_CPU_H_

#include "vmm_defs.h"
#include "vmm_objects.h"
#include "vmx_vmcs.h"

//******************************************************************************
//
// Host CPU model for VMCS
//
//******************************************************************************

//------------------------------------------------------------------------------
//
// Init
//
//------------------------------------------------------------------------------
void host_cpu_manager_init( UINT16 max_host_cpus );

//------------------------------------------------------------------------------
//
// Initialize current host cpu
//
//------------------------------------------------------------------------------
void host_cpu_init( void );

//------------------------------------------------------------------------------
//
// Init VMCS state host part for the specified host cpu
//
// Note: this function does not reguire to be called on the target_host_cpu
//
//------------------------------------------------------------------------------
void host_cpu_vmcs_init( GUEST_CPU_HANDLE gcpu);

//------------------------------------------------------------------------------
//
// Set/Get VMXON Region pointer for the current CPU
//
//------------------------------------------------------------------------------
void host_cpu_set_vmxon_region( HVA hva, HPA hpa, CPU_ID my_cpu_id );
HVA  host_cpu_get_vmxon_region( HPA* hpa );

//------------------------------------------------------------------------------
//
// Set/Get VMX state is active
//
//------------------------------------------------------------------------------
void host_cpu_set_vmx_state( BOOLEAN value );
BOOLEAN host_cpu_get_vmx_state( void );

//------------------------------------------------------------------------------
//
// Enable usage of XMM registers
//
//------------------------------------------------------------------------------
void host_cpu_enable_usage_of_xmm_regs( void );

void host_cpu_add_msr_to_level0_autoswap(CPU_ID cpu, UINT32 msr_index);
void host_cpu_delete_msr_from_level0_autoswap(CPU_ID cpu, UINT32 msr_index);
void host_cpu_init_vmexit_store_and_vmenter_load_msr_lists_according_to_vmexit_load_list(GUEST_CPU_HANDLE gcpu);

//
// Debug support
//
void host_cpu_store_vmexit_gcpu(CPU_ID cpu_id, GUEST_CPU_HANDLE gcpu);
GUEST_CPU_HANDLE host_cpu_get_vmexit_gcpu(CPU_ID cpu_id);

void host_cpu_save_dr7(CPU_ID cpu_id);
void host_cpu_restore_dr7(CPU_ID cpu_id);

#endif // _HOST_CPU_H_
