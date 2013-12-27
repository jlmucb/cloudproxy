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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_CONTROL_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_CONTROL_C, __condition)
#include "guest_internal.h"
#include "guest_cpu.h"
#include "vmm_dbg.h"
#include "vmm_globals.h"
#include "ipc.h"
#include "scheduler.h"

//******************************************************************************
//*
//* Main implementatuion idea:
//*    at boot stage just iterate through all gcpus and immediately apply
//*    at run stage use IPC to apply
//*
//******************************************************************************

// -------------------------- types -----------------------------------------
typedef struct _IPC_COMM_GUEST_STRUCT {
    GUEST_HANDLE    guest;
    volatile UINT32 executed;
    UINT8           pad1[4];
} IPC_COMM_GUEST_STRUCT;

// ---------------------------- globals -------------------------------------
// ---------------------------- internal funcs  -----------------------------

#pragma warning (push)
#pragma warning (disable : 4100)

// apply vmexit config to the gcpu that are allocated for the current host cpu
static
void apply_vmexit_config(CPU_ID from UNUSED, void* arg)
{
    GUEST_GCPU_ECONTEXT ctx;
    GUEST_CPU_HANDLE    gcpu;
    CPU_ID              this_hcpu_id = hw_cpu_id();

    IPC_COMM_GUEST_STRUCT* ipc = (IPC_COMM_GUEST_STRUCT*)arg;
    GUEST_HANDLE        guest = ipc->guest;
    volatile UINT32*    p_executed_count = &(ipc->executed);

    VMM_ASSERT( guest );

    for( gcpu = guest_gcpu_first( guest, &ctx ); gcpu; gcpu = guest_gcpu_next( &ctx ))
    {
        if (this_hcpu_id == scheduler_get_host_cpu_id( gcpu ))
        {
            gcpu_control_apply_only( gcpu );
        }
    }

    // mark as done
    hw_interlocked_increment( (INT32*)p_executed_count );
}

#pragma warning (pop)

// ---------------------------- APIs  ---------------------------------------
void guest_control_setup( GUEST_HANDLE guest, const VMEXIT_CONTROL* request )
{
    GUEST_GCPU_ECONTEXT ctx;
    GUEST_CPU_HANDLE    gcpu;
    VMM_STATE           vmm_state;
    CPU_ID              this_hcpu_id = hw_cpu_id();

    VMM_ASSERT( guest );

    // setup vmexit requests without applying
    for( gcpu = guest_gcpu_first( guest, &ctx ); gcpu; gcpu = guest_gcpu_next( &ctx ))
    {
        gcpu_control_setup_only( gcpu, request );
    }

    // now apply
    vmm_state = vmm_get_state();

    if (VMM_STATE_BOOT == vmm_state)
    {
        // may be run on BSP only
        VMM_ASSERT( 0 == this_hcpu_id );

        // single thread mode with all APs yet not init
        for( gcpu = guest_gcpu_first( guest, &ctx ); gcpu; gcpu = guest_gcpu_next( &ctx ))
        {
            gcpu_control_apply_only( gcpu );
        }
    }
    else if (VMM_STATE_RUN == vmm_state)
    {
        IPC_COMM_GUEST_STRUCT ipc;
        UINT32                wait_for_ipc_count = 0;
        IPC_DESTINATION       ipc_dst;

        vmm_memset( &ipc, 0, sizeof(ipc) );
        vmm_memset( &ipc_dst, 0, sizeof(ipc_dst) );

        // multi-thread mode with all APs ready and running or in Wait-For-SIPI state
        // on behalf of guest

        ipc.guest = guest;

        // first apply for gcpus allocated for this hw cpu
        apply_vmexit_config( this_hcpu_id, &ipc );

        // reset executed counter and flush memory
        hw_assign_as_barrier( &(ipc.executed), 0);

        // send for execution
        ipc_dst.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
        wait_for_ipc_count = ipc_execute_handler( ipc_dst, apply_vmexit_config, &ipc );

        // wait for execution finish
        while (wait_for_ipc_count != ipc.executed)
        {
            // avoid deadlock - process one IPC if exist
            ipc_process_one_ipc();
            hw_pause();
        }
    }
    else
    {
        // not supported mode
        VMM_LOG(mask_anonymous, level_trace,"Unsupported global vmm_state=%d in guest_request_vmexit_on()\n", vmm_state);
        VMM_DEADLOOP();
    }
}

