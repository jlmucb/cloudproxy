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

#include "vmm_defs.h"
#include "isr.h"
#include "guest_cpu.h"
#include "guest_cpu_vmenter_event.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_VMX_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_VMX_C, __condition)

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


