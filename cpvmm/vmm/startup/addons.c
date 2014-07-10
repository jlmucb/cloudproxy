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

#include "vmm_bootstrap_utils.h"
#include "policy_manager.h"
#include "vmm_addons.h"
#include "vmm_dbg.h"
#ifdef TMSL_HANDLER_DEFINED
#include <tmsl_handler_external.h>
#endif
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(ADDONS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(ADDONS_C, __condition)

extern void xuvmm_initialize(UINT32 num_of_threads);

extern BOOLEAN legacy_scheduling_enabled;

void start_addons( UINT32 num_of_cpus,
                   const VMM_STARTUP_STRUCT* startup_struct,
                   const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct)
{
  (void)startup_struct;
  (void)application_params_struct;
    VMM_LOG(mask_anonymous, level_trace,"start addons\r\n");
#ifdef VTLB_IS_SUPPORTED
    if (global_policy_uses_vtlb()) {
        init_vtlb_addon( num_of_cpus );
    } 
	else
#endif
    if (global_policy_uses_ept()) {
        init_ept_addon( num_of_cpus );
    }
    else {
        VMM_LOG(mask_anonymous, level_error,"No supported addons\r\n");
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_DEADLOOP();
    }

    // gdb_stub_addon_initialize(num_of_cpus, &startup_struct->debug_params.aux_port);

    // init_guest_create_addon();

#ifdef XUVMM_DEFINED
    xuvmm_initialize(num_of_cpus);
    legacy_scheduling_enabled = FALSE;
#endif
#ifdef TMSL_HANDLER_DEFINED
    tmsl_handler_initialize(num_of_cpus);
#endif
}

