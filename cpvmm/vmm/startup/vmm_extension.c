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
#include "vmm_callback.h"

#pragma warning(push)
#pragma warning(disable : 4100) // disable non-referenced formal parameters

BOOLEAN report_uvmm_event(UVMM_EVENT event, VMM_IDENTIFICATION_DATA gcpu, const GUEST_VCPU *vcpu_id, void *event_specific_data)
{
    BOOLEAN status = TRUE;

    switch(event) {
        case UVMM_EVENT_INITIALIZATION_BEFORE_APS_STARTED:
            break;
        case UVMM_EVENT_INITIALIZATION_AFTER_APS_STARTED:
            break;
        case UVMM_EVENT_EPT_VIOLATION:
            break;
        case UVMM_EVENT_MTF_VMEXIT:
            break;
        case UVMM_EVENT_CR_ACCESS:
            status = FALSE;
            break;
        case UVMM_EVENT_DR_LOAD_ACCESS:
            break;
        case UVMM_EVENT_LDTR_LOAD_ACCESS:
            break;
        case UVMM_EVENT_GDTR_IDTR_ACCESS:
            break;
        case UVMM_EVENT_MSR_READ_ACCESS:
            break;
        case UVMM_EVENT_MSR_WRITE_ACCESS:
            break;
        case UVMM_EVENT_SET_ACTIVE_EPTP:
            break;
        case UVMM_EVENT_INITIAL_VMEXIT_CHECK:
            status = FALSE;
            break;
        case UVMM_EVENT_SINGLE_STEPPING_CHECK:
            break;
        case UVMM_EVENT_VMM_TEARDOWN:
            break;
        case UVMM_EVENT_INVALID_FAST_VIEW_SWITCH:
            break;
        case UVMM_EVENT_VMX_PREEMPTION_TIMER:
            break;
        case UVMM_EVENT_HALT_INSTRUCTION:
            break;
        case UVMM_EVENT_LOG:
            break;
    }

    return status;
}
#pragma warning(pop)
