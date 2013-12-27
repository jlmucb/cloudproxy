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

#ifndef _VMM_BOOTSTRAP_UTILS_H_
#define _VMM_BOOTSTRAP_UTILS_H_

#include "vmm_startup.h"

//******************************************************************************
//*
//* Copy and destroy input structures
//*
//******************************************************************************
const VMM_STARTUP_STRUCT*
vmm_create_startup_struct_copy(
                const VMM_STARTUP_STRUCT* startup_struct_stack);

void vmm_destroy_startup_struct(const VMM_STARTUP_STRUCT* startup_struct);

const VMM_APPLICATION_PARAMS_STRUCT*
vmm_create_application_params_struct_copy(
                const VMM_APPLICATION_PARAMS_STRUCT* application_params_stack);

void vmm_destroy_application_params_struct(
                const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct);

//******************************************************************************
//*
//* Read input data structure and create all guests
//*
//******************************************************************************

//------------------------------------------------------------------------------
//
// Preform initialization of guests and guest CPUs, excluding host cpu parts
//
// Should be called on BSP only while all APs are stopped
//
// Return TRUE for success
//
//------------------------------------------------------------------------------
BOOLEAN initialize_all_guests(
                    UINT32 number_of_host_processors,
                    const VMM_MEMORY_LAYOUT* vmm_memory_layout,
                    const VMM_GUEST_STARTUP* primary_guest_startup_state,
                    UINT32 number_of_secondary_guests,
                    const VMM_GUEST_STARTUP* secondary_guests_startup_state_array,
                    const VMM_APPLICATION_PARAMS_STRUCT* application_params);

//------------------------------------------------------------------------------
//
// Run init routins of all addons
//
// Should be called on BSP only while all APs are stopped
//
//------------------------------------------------------------------------------
void start_addons( UINT32 num_of_cpus,
                   const VMM_STARTUP_STRUCT* startup_struct,
                   const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct);

//------------------------------------------------------------------------------
//
// Preform initialization of host cpu parts of all guest CPUs that run on specified
// host CPU.
//
// Should be called on the target host CPU
//------------------------------------------------------------------------------
void initialize_host_vmcs_regions( CPU_ID current_cpu_id );

//
// Debug print input structures
//
void print_startup_struct(const VMM_STARTUP_STRUCT* startup_struct);

#endif // _VMM_BOOTSTRAP_UTILS_H_

