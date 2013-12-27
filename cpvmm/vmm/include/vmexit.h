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

#ifndef _VMEXIT_H_
#define _VMEXIT_H_

#include "vmx_vmcs.h"

typedef enum {
    VMEXIT_NOT_HANDLED,
    VMEXIT_HANDLED,
    VMEXIT_HANDLED_RESUME_LEVEL2
} VMEXIT_HANDLING_STATUS;

typedef VMEXIT_HANDLING_STATUS (*VMEXIT_HANDLER)(GUEST_CPU_HANDLE);


/*-----------------------------------------------------------------------------*
*  FUNCTION : vmexit_initialize()
*  PURPOSE  : Perform basic vmexit initialization common for all guests
*  ARGUMENTS: void
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void vmexit_initialize(void);

/*-----------------------------------------------------------------------------*
*  FUNCTION : vmexit_guest_initialize()
*  PURPOSE  : Populate guest table, containing specific VMEXIT handlers with
*           : default handlers
*  ARGUMENTS: GUEST_ID guest_id
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void vmexit_guest_initialize(GUEST_ID guest_id);

/*-----------------------------------------------------------------------------*
*  FUNCTION : vmexit_common_handler()
*  PURPOSE  : Called by vmexit_func() upon each VMEXIT
*  ARGUMENTS: void
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void vmexit_common_handler(void);


/*-----------------------------------------------------------------------------*
*  FUNCTION : vmexit_install_handler
*  PURPOSE  : Install specific VMEXIT handler
*  ARGUMENTS: GUEST_ID        guest_id
*           : VMEXIT_HANDLER  handler
*           : UINT32          reason
*  RETURNS  : VMM_STATUS
*-----------------------------------------------------------------------------*/
VMM_STATUS vmexit_install_handler(
    GUEST_ID        guest_id,
    VMEXIT_HANDLER  handler,
    UINT32          reason);


VMEXIT_HANDLING_STATUS vmexit_handler_default(GUEST_CPU_HANDLE); // should not be here


/*-----------------------------------------------------------------------------*
*  FUNCTION : vmentry_failure_function
*  PURPOSE  : Called upon VMENTER failure
*  ARGUMENTS: ADDRESS flag - value of processor flags register
*  RETURNS  : void
*  NOTES    : is not VMEXIT
*-----------------------------------------------------------------------------*/
void vmentry_failure_function(ADDRESS flags);


/*-----------------------------------------------------------------------------*
*  FUNCTION : vmexit_direct_call_top_down_handler
*  PURPOSE  : Used for specific case. Normally should never be called.
*  ARGUMENTS: self described
*  RETURNS  : void
*-----------------------------------------------------------------------------*/
void vmexit_direct_call_handler(GUEST_CPU_HANDLE gcpu);


//------------------------------------------------------------------------------
// Guest/Guest CPU vmexits control
//
// request vmexits for given gcpu or guest
//
// Receives 2 bitmasks:
//    For each 1bit in mask check the corresponding request bit. If request bit
//    is 1 - request the vmexit on this bit change, else - remove the
//    previous request for this bit.
//------------------------------------------------------------------------------
typedef struct _VMEXIT_CONTROL_FIELD {
    UINT64 bit_request;
    UINT64 bit_mask;
} VMEXIT_CONTROL_FIELD;

typedef struct _VMEXIT_CONTROL {
    VMEXIT_CONTROL_FIELD cr0;
    VMEXIT_CONTROL_FIELD cr4;
    VMEXIT_CONTROL_FIELD exceptions;
    VMEXIT_CONTROL_FIELD pin_ctrls;
    VMEXIT_CONTROL_FIELD proc_ctrls;
    VMEXIT_CONTROL_FIELD proc_ctrls2;
    VMEXIT_CONTROL_FIELD vm_enter_ctrls;
    VMEXIT_CONTROL_FIELD vm_exit_ctrls;
} VMEXIT_CONTROL;



#endif // _VMEXIT_H_

