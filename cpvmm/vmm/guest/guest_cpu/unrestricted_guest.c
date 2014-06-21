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

#include "vmcs_init.h"
#include "ept.h"
#include "ept_hw_layer.h"
#include "scheduler.h"
#include "vmx_ctrl_msrs.h"
#include "unrestricted_guest.h"
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(UNRESTRICTED_GUEST_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(UNRESTRICTED_GUEST_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


// Temporary external declarations
extern BOOLEAN ept_enable(GUEST_CPU_HANDLE gcpu);

void gcpu_clr_unrestricted_guest(GUEST_CPU_HANDLE gcpu)
{
    VMM_ASSERT( gcpu );
    CLR_UNRESTRICTED_GUEST_FLAG(gcpu);
    unrestricted_guest_disable(gcpu);
}

//Check whether Unrestricted guest is enabled 
BOOLEAN is_unrestricted_guest_enabled(GUEST_CPU_HANDLE gcpu)
{
    BOOLEAN res = FALSE;

    res =hw_is_unrestricted_guest_enabled(gcpu);
    return res;
}

BOOLEAN hw_is_unrestricted_guest_enabled(GUEST_CPU_HANDLE gcpu)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 proc_ctrls2;

    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    proc_ctrls2.Uint32 = (UINT32) vmcs_read(gcpu_get_vmcs(gcpu), VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS);
    return proc_ctrls2.Bits.UnrestrictedGuest;
}

void unrestricted_guest_hw_disable(GUEST_CPU_HANDLE gcpu)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 proc_ctrls2;
    VMEXIT_CONTROL vmexit_request;

    CHECK_EXECUTION_ON_LOCAL_HOST_CPU(gcpu);
    proc_ctrls2.Uint32 = 0;
    vmm_zeromem(&vmexit_request, sizeof(vmexit_request));
    proc_ctrls2.Bits.UnrestrictedGuest = 1;
    vmexit_request.proc_ctrls2.bit_mask    = proc_ctrls2.Uint32;
    vmexit_request.proc_ctrls2.bit_request = 0;
    gcpu_control2_setup( gcpu, &vmexit_request );
}


void unrestricted_guest_disable(GUEST_CPU_HANDLE gcpu)
{
    unrestricted_guest_hw_disable(gcpu);
}


// Function Name:  unrestricted_guest_enable
// Arguments: gcpu: the guest cpu handle. Function assumes the input is validated by caller functions.
void unrestricted_guest_enable(GUEST_CPU_HANDLE gcpu)
{
    UINT64 cr4;
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 proc_ctrls2;
    VMEXIT_CONTROL vmexit_request;

    SET_UNRESTRICTED_GUEST_FLAG(gcpu);
#ifdef JLMDEBUG1
    bprint("unrestricted_guest_enable, acquiring lock, ");
#endif
    ept_acquire_lock();
#ifdef JLMDEBUG1
    bprint("lock acquired\n");
#endif
    proc_ctrls2.Uint32 = 0;
    vmm_zeromem(&vmexit_request, sizeof(vmexit_request));
    proc_ctrls2.Bits.UnrestrictedGuest = 1;
    vmexit_request.proc_ctrls2.bit_mask= proc_ctrls2.Uint32;
    vmexit_request.proc_ctrls2.bit_request = UINT64_ALL_ONES;
    gcpu_control2_setup( gcpu, &vmexit_request );
    VMM_ASSERT(is_unrestricted_guest_enabled(gcpu));
    if(!ept_is_ept_enabled(gcpu)) {
        ept_enable(gcpu);
        cr4 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
        ept_set_pdtprs(gcpu, cr4);
    }
    VMM_ASSERT(ept_is_ept_enabled(gcpu));
    ept_release_lock();
#ifdef JLMDEBUG1
    bprint("unrestricted_guest_enable, lock released\n");
#endif
}
