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

#ifndef _UNRESTRICTED_GUEST_H
#define _UNRESTRICTED_GUEST_H

#include "vmm_defs.h"
#include "vmcs_init.h"
#include "guest_cpu_internal.h"


#define IS_MODE_UNRESTRICTED_GUEST(gcpu)  (GET_UNRESTRICTED_GUEST_FLAG( gcpu ) == 1)
#define SET_MODE_UNRESTRICTED_GUEST(gcpu) SET_UNRESTRICTED_GUEST_FLAG( gcpu )
#define SET_UNRESTRICTED_GUEST_FLAG(gcpu) BIT_SET( (gcpu)->state_flags, GCPU_UNRESTRICTED_GUEST_FLAG)
#define CLR_UNRESTRICTED_GUEST_FLAG(gcpu) BIT_CLR( (gcpu)->state_flags, GCPU_UNRESTRICTED_GUEST_FLAG)
#define GET_UNRESTRICTED_GUEST_FLAG(gcpu) BIT_GET( (gcpu)->state_flags, GCPU_UNRESTRICTED_GUEST_FLAG)

// Counter to run emulator initially and then switch to unrestricted guest.
#define UNRESTRICTED_GUEST_EMU_COUNTER 1

BOOLEAN is_unrestricted_guest_enabled(GUEST_CPU_HANDLE gcpu);
BOOLEAN hw_is_unrestricted_guest_enabled(GUEST_CPU_HANDLE gcpu);
void unrestricted_guest_hw_disable(GUEST_CPU_HANDLE gcpu);
void gcpu_clr_unrestricted_guest(GUEST_CPU_HANDLE gcpu);
void unrestricted_guest_disable(GUEST_CPU_HANDLE gcpu);
void unrestricted_guest_enable(GUEST_CPU_HANDLE gcpu);

//Check whether Unrestricted guest is supported 
INLINE BOOLEAN is_unrestricted_guest_supported(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();
    return (hw_constraints->unrestricted_guest_supported);
}


void make_segreg_hw_compliant(
    GUEST_CPU_HANDLE             gcpu ,
    UINT16              selector,
    UINT64              base,
    UINT32              limit,
    UINT32              attr,
    VMM_IA32_SEGMENT_REGISTERS  reg_id);

void make_segreg_hw_real_mode_compliant(
    GUEST_CPU_HANDLE             gcpu ,
    UINT16              selector,
    UINT64              base,
    UINT32              limit,
    UINT32              attr,
    VMM_IA32_SEGMENT_REGISTERS  reg_id);
#endif  // _UNRESTRICTED_GUEST_H

