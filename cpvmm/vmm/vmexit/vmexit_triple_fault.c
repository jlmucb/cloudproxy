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

    if (0) gcpu = NULL;  // just to pass release compilation
    return VMEXIT_HANDLED;
}

