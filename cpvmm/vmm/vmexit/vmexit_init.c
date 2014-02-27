/*
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
 */

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_INIT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_INIT_C, __condition)
#include "vmm_defs.h"
#include "guest_cpu.h"
#include "guest.h"
#include "local_apic.h"
#include "vmm_dbg.h"
#include "hw_utils.h"
#include "vmcs_init.h"
#include "vmm_events_data.h"


/*-------------------------------------------------------------------------*
*  FUNCTION : vmexit_init_event()
*  PURPOSE  : reset CPU
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*  RETURNS  : void
*  NOTE     : Propagate INIT signal from primary guest to CPU
*-------------------------------------------------------------------------*/
VMEXIT_HANDLING_STATUS vmexit_init_event(GUEST_CPU_HANDLE gcpu)
{
    CPU_ID  cpu_id = hw_cpu_id();

    VMM_LOG(mask_anonymous, level_trace,"INIT signal in Guest#%d GuestCPU#%d HostCPU#%d\n",
        guest_vcpu(gcpu)->guest_id, guest_vcpu(gcpu)->guest_cpu_id, hw_cpu_id());

    VMM_ASSERT(guest_is_primary(gcpu_guest_handle(gcpu)));

    if (cpu_id == 0) { // If cpu is BSP
        VMM_LOG(mask_anonymous, level_trace,"[%d] Perform global reset\n", cpu_id);
        hw_reset_platform();                                                    // then preform cold reset.
        VMM_DEADLOOP();
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,"[%d] Switch to Wait for SIPI mode\n", cpu_id);

        // Switch to Wait for SIPI state.
        gcpu_set_activity_state(gcpu, Ia32VmxVmcsGuestSleepStateWaitForSipi);
    }
    return VMEXIT_HANDLED;
}


