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
#include "isr.h"
#include "guest_cpu.h"
#include "guest_cpu_vmenter_event.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_VMX_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_VMX_C, __condition)

extern BOOLEAN gcpu_inject_invalid_opcode_exception(GUEST_CPU_HANDLE    gcpu);

#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter

VMEXIT_HANDLING_STATUS vmexit_vmxon_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
   gcpu_inject_invalid_opcode_exception(gcpu);
#endif
   return VMEXIT_HANDLED;
}


VMEXIT_HANDLING_STATUS vmexit_vmxoff_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}


VMEXIT_HANDLING_STATUS vmexit_vmread_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}

VMEXIT_HANDLING_STATUS vmexit_vmwrite_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}

VMEXIT_HANDLING_STATUS vmexit_vmptrld_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}

VMEXIT_HANDLING_STATUS vmexit_vmptrst_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}



VMEXIT_HANDLING_STATUS vmexit_vmlaunch_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}

VMEXIT_HANDLING_STATUS vmexit_vmresume_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}


VMEXIT_HANDLING_STATUS vmexit_vmclear_instruction(GUEST_CPU_HANDLE gcpu)
{
    VMM_LOG(mask_uvmm, level_trace,"%s\n", __FUNCTION__);
#ifdef DEBUG
    VMM_DEADLOOP();
#else
    gcpu_inject_invalid_opcode_exception(gcpu);
#endif
    return VMEXIT_HANDLED;
}

#pragma warning( pop )


