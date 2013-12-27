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

#ifndef _VMDB_H_
#define _VMDB_H_


typedef enum {
    VMDB_BREAK_ON_EXE = 0,
    VMDB_BREAK_ON_WO  = 1,   // break on memory write only
    VMDB_BREAK_ON_IO  = 2,   // break on IO read/write
    VMDB_BREAK_ON_RW  = 3,   // break on memory read/write
    VMDB_BREAK_TYPE_FIRST = 0,
    VMDB_BREAK_TYPE_LAST = 3
} VMDB_BREAKPOINT_TYPE;

typedef enum {
    VMDB_BREAK_LENGTH_1 = 0, // used for exe breaks
    VMDB_BREAK_LENGTH_2 = 1,
    VMDB_BREAK_LENGTH_8 = 2,
    VMDB_BREAK_LENGTH_4 = 3,
    VMDB_BREAK_LENGTH_FIRST = 0,
    VMDB_BREAK_LENGTH_LAST = 3
} VMDB_BREAK_LENGTH_TYPE;


#define VMDB_INCLUDE

#ifdef VMDB_INCLUDE

void        vmdb_initialize(void);
VMM_STATUS  vmdb_guest_initialize(GUEST_ID);
VMM_STATUS vmdb_thread_attach(GUEST_CPU_HANDLE gcpu);
VMM_STATUS vmdb_thread_detach(GUEST_CPU_HANDLE gcpu);

BOOLEAN     vmdb_exception_handler(GUEST_CPU_HANDLE gcpu);
VMM_STATUS  vmdb_breakpoint_info(
    GUEST_CPU_HANDLE        gcpu,
    UINT32                  bp_id,
    ADDRESS                 *linear_address,
    VMDB_BREAKPOINT_TYPE    *bp_type,
    VMDB_BREAK_LENGTH_TYPE  *bp_len,
    UINT16                  *skip_counter
    );
VMM_STATUS  vmdb_breakpoint_add(
    GUEST_CPU_HANDLE        gcpu,
    ADDRESS                 linear_address,
    VMDB_BREAKPOINT_TYPE    bp_type,
    VMDB_BREAK_LENGTH_TYPE  bp_len,
    UINT16                  skip_counter
    );
VMM_STATUS  vmdb_breakpoint_delete(GUEST_CPU_HANDLE gcpu, ADDRESS linear_address);
VMM_STATUS  vmdb_breakpoint_delete_all(GUEST_CPU_HANDLE gcpu);
VMM_STATUS  vmdb_single_step_enable(GUEST_CPU_HANDLE gcpu, BOOLEAN enable);
VMM_STATUS  vmdb_single_step_info(GUEST_CPU_HANDLE gcpu, BOOLEAN *enable);
void        vmdb_settings_apply_to_hw(GUEST_CPU_HANDLE gcpu);

#else
#define vmdb_initialize()
#define vmdb_guest_initialize(guest_id)             VMM_OK
#define vmdb_thread_attach(gcpu)                    VMM_ERROR
#define vmdb_thread_detach(gcpu)                    VMM_ERROR
#define vmdb_exception_handler(gcpu) (FALSE /* exception NOT handled */)
#define vmdb_breakpoint_add(gcpu,linear_address,bp_type,bp_len,skip_counter) VMM_OK
#define vmdb_breakpoint_delete(gcpu,linear_address) VMM_OK
#define vmdb_breakpoint_delete_all(gcpu)            VMM_OK
#define vmdb_settings_apply_to_hw(gcpu)
#define vmdb_single_step_enable(gcpu, enable)       VMM_OK

#endif // VMDB_INCLUDE

#endif // _VMDB_H_

