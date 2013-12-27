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

#include "vmm_defs.h"
#include "guest_cpu.h"
#include "vmm_events_data.h"
#include "vmcs_api.h"
#include "hw_utils.h"
#include "emulator_if.h"
#include "vmm_callback.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_EPT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_EPT_C, __condition)

#pragma warning (push)
#pragma warning (disable : 4100) // disable non-referenced formal parameters
VMEXIT_HANDLING_STATUS vmexit_mtf(GUEST_CPU_HANDLE gcpu)
{
    if (!report_uvmm_event(UVMM_EVENT_MTF_VMEXIT, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), NULL)) {
        VMM_LOG(mask_uvmm, level_trace, "Report MTF VMExit failed.\n");
    }

    return VMEXIT_HANDLED;
}
#pragma warning (pop)

BOOLEAN ept_violation_vmexit(GUEST_CPU_HANDLE gcpu, void *pv);


VMEXIT_HANDLING_STATUS vmexit_ept_violation(GUEST_CPU_HANDLE gcpu)
{
    EVENT_GCPU_EPT_VIOLATION_DATA data;
    VMCS_OBJECT*                vmcs = gcpu_get_vmcs(gcpu);


    //vmm_memset(&data, 0, sizeof(data));
    data.qualification.Uint64 = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    data.guest_linear_address = vmcs_read(vmcs, VMCS_EXIT_INFO_GUEST_LINEAR_ADDRESS);
    data.guest_physical_address = vmcs_read(vmcs, VMCS_EXIT_INFO_GUEST_PHYSICAL_ADDRESS);
    data.processed = FALSE;

    ept_violation_vmexit( gcpu, &data );

    if (!data.processed)
    {
        VMM_LOG(mask_anonymous, level_trace,"Unsupported ept violation in \n");
        PRINT_GCPU_IDENTITY(gcpu);
        VMM_LOG(mask_anonymous, level_trace," Running %s emulator\n", emulator_is_running_as_guest() ? "inside" : "outside");
        //vmexit_handler_default(gcpu);
        VMM_DEADLOOP();
    }



    return VMEXIT_HANDLED;
}

VMEXIT_HANDLING_STATUS vmexit_ept_misconfiguration(GUEST_CPU_HANDLE gcpu)
{
    EVENT_GCPU_EPT_MISCONFIGURATION_DATA data;
    VMCS_OBJECT*                vmcs = gcpu_get_vmcs(gcpu);
    data.guest_physical_address = vmcs_read(vmcs, VMCS_EXIT_INFO_GUEST_PHYSICAL_ADDRESS);
    data.processed = FALSE;

    event_raise( EVENT_GCPU_EPT_MISCONFIGURATION, gcpu, &data );

    VMM_ASSERT(data.processed);

    if ( ! data.processed)
    {
        VMM_LOG(mask_anonymous, level_trace,"Unsupported ept misconfiguration in \n");
        PRINT_GCPU_IDENTITY(gcpu);
        VMM_LOG(mask_anonymous, level_trace," Running %s emulator\n", emulator_is_running_as_guest() ? "inside" : "outside");
        //vmexit_handler_default(gcpu);
        VMM_DEADLOOP();
    }

    return VMEXIT_HANDLED;
}

