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

#include "vmm_defs.h"
#include "guest_cpu.h"
#include "hw_utils.h"
#include "scheduler.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_TRIPLE_fault_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_TRIPLE_fault_C, __condition)

VMEXIT_HANDLING_STATUS vmexit_triple_fault(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_anonymous, level_trace,"Triple Fault Occured on \n");
    PRINT_GCPU_IDENTITY(gcpu);
    VMM_LOG(mask_anonymous, level_trace,"  Reset the System.\n");
    VMM_DEBUG_CODE(VMM_DEADLOOP());
    hw_reset_platform();
    // TODO: Tear down the guest

    if (0) 
        gcpu = NULL;  // just to pass release compilation
    return VMEXIT_HANDLED;
}

