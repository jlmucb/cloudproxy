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

#include "vmm_bootstrap_utils.h"
#include "policy_manager.h"
#include "vmm_addons.h"
#include "vmm_dbg.h"
#include <tscdt_emulator_api.h>
#ifdef TMSL_HANDLER_DEFINED
#include <tmsl_handler_external.h>
#endif
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(ADDONS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(ADDONS_C, __condition)

extern void xuvmm_initialize(UINT32 num_of_threads);

extern BOOLEAN legacy_scheduling_enabled;

#pragma warning (disable : 4100) // disable non-referenced formal parameters
void start_addons( UINT32 num_of_cpus,
                   const VMM_STARTUP_STRUCT* startup_struct,
                   const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct UNUSED)
{
    VMM_LOG(mask_anonymous, level_trace,"start addons\r\n");
#ifdef VTLB_IS_SUPPORTED
    if (global_policy_uses_vtlb())
    {
        init_vtlb_addon( num_of_cpus );
    } 
	else
#endif
    if (global_policy_uses_ept()){
        init_ept_addon( num_of_cpus );
    }
    else
    {
        VMM_LOG(mask_anonymous, level_error,"No supported addons\r\n");
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_DEADLOOP();
    }

    //gdb_stub_addon_initialize(num_of_cpus, &startup_struct->debug_params.aux_port);

//    tscdte_initialize(TSCDTE_MODE_OFF);
//    init_guest_create_addon();

#ifdef XUVMM_DEFINED
    xuvmm_initialize(num_of_cpus);
    legacy_scheduling_enabled = FALSE;
#endif
#ifdef TMSL_HANDLER_DEFINED
    tmsl_handler_initialize(num_of_cpus);
#endif
}

