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
//#include "vmcs_object.h"
#include "vmx_vmcs.h"
#include "vmcs_api.h"
#include "vmm_dbg.h"
#include "em64t_defs.h"
#include "vmm_events_data.h"
#include "guest_cpu.h"

VMEXIT_HANDLING_STATUS vmexit_invlpg(GUEST_CPU_HANDLE gcpu)
{
    EVENT_GCPU_INVALIDATE_PAGE_DATA data;
    IA32_VMX_EXIT_QUALIFICATION     qualification;
    VMCS_OBJECT*                    vmcs = gcpu_get_vmcs(gcpu);

    qualification.Uint64 = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    data.invlpg_addr = qualification.InvlpgInstruction.Address;
    // Return value of raising event is not important
    event_raise( EVENT_GCPU_INVALIDATE_PAGE, gcpu, &data );
    // Instruction will be skipped in upper "bottom-up" handler
    // gcpu_skip_guest_instruction(gcpu);
    return VMEXIT_HANDLED;
}

