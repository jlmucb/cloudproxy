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

#ifndef _IPC_H
#define _IPC_H

#include "local_apic.h"
#include "vmm_objects.h"
#include "common_types.h"

/// %VT% typedef struct _GUEST_CPU       *GUEST_CPU_HANDLE;

typedef struct _IPC_DESTINATION
{
    LOCAL_APIC_IPI_DESTINATION_SHORTHAND addr_shorthand;
    UINT8 addr;
    UINT8 padding[3];
    UINT64 CoreBitMap[CPU_BITMAP_MAX];
} IPC_DESTINATION;

typedef enum
{
    IPC_TYPE_NORMAL,
    IPC_TYPE_START,
    IPC_TYPE_STOP,
    IPC_TYPE_SYNC,
    IPC_TYPE_LAST
} IPC_MESSAGE_TYPE;


// FUNCTION:        ipc_initialize
// DESCRIPTION:     Initialize IPC engine. Must be called before any IPCs can be generated.
// RETURN VALUE:    TRUE for success, FALSE for failure
BOOLEAN ipc_initialize(UINT16 number_of_host_processors);

// FUNCTION:        ipc_guest_initialize
// DESCRIPTION:     Initialize stop/start context and initialize IPC engine for a guest. Must be called when new guest is added.
// RETURN VALUE:    TRUE for success, FALSE for failure
BOOLEAN ipc_guest_initialize(GUEST_ID guest_id);

// FUNCTION:        ipc_finalize
// DESCRIPTION:     Destroy IPC engine. ipc_initialize must be called before any IPCs can be generated.
void ipc_finalize(void);

// FUNCTION:        ipc_change_state_to_active
// DESCRIPTION:     CPU cannot receive IPC if in Wait-for-SIPI state.
//                  This function marks the CPU on which it is executed
//                  as capable of receiving IPCs after leaving Wait-for-SIPI state.
void ipc_change_state_to_active(GUEST_CPU_HANDLE gcpu);

// FUNCTION:        ipc_change_state_to_sipi
// DESCRIPTION:     CPU cannot receive IPC if in Wait-for-SIPI state.
//                  This function marks the CPU on which it is executed
//                  as NOT capable of receiving IPCs due to transitioning to Wait-for-SIPI state.
void ipc_change_state_to_sipi(GUEST_CPU_HANDLE gcpu);

// FUNCTION:        ipc_process_one_ipc
// DESCRIPTION:     Process single IPC from this CPU's IPC queue.
// RETURN VALUE:    TRUE if a message was processed, FALSE if the queue was empty
BOOLEAN ipc_process_one_ipc(void);

// IPC_HANDLER_FN -- type of function that is executed on other CPUs
typedef void (*IPC_HANDLER_FN)(CPU_ID from, void* arg);

// FUNCTION:        ipc_execute_handler
// DESCRIPTION:     Execute handler on other CPUs. This function returns when all destination
//                  CPUs are about to execute the handler
// ARGUMENTS:       dst -- destination CPU(s)
//                  handler -- handler for execution
//                  arg -- argument to pass to the handler
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_execute_handler(IPC_DESTINATION dst, IPC_HANDLER_FN handler, void* arg);

// FUNCTION:        ipc_execute_handler
// DESCRIPTION:     Execute handler on other CPUs. This function returns when all destination
//                  CPUs finished to execute the handler
// ARGUMENTS:       dst -- destination CPU(s)
//                  handler -- handler for execution
//                  arg -- argument to pass to the handler
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_execute_handler_sync(IPC_DESTINATION dst, IPC_HANDLER_FN handler, void* arg);

// FUNCTION:        stop_all_cpus
// DESCRIPTION:     Stop all other CPUs. Other CPUs will be executing the busy loop until
//                  they are resumed by calling start_all_cpus()
// RETURN VALUE:    TRUE if all processors has stopped, FALSE in case of failure
BOOLEAN stop_all_cpus(void);

// FUNCTION:        start_all_cpus
// DESCRIPTION:     Start all other CPUs previously stopped by stop_all_cpus().
//                  Execute handler upon start.
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 start_all_cpus(IPC_HANDLER_FN handler, void* arg);

// FUNCTION:        stop_all_guest_cpus
// DESCRIPTION:     Stop all CPUs running given guest. These CPUs will be executing the busy loop until
//                  they are resumed by calling start_all_guest_cpus()
// RETURN VALUE:    TRUE if CPUs running guest has stopped, FALSE in case of failure
BOOLEAN stop_all_guest_cpus(GUEST_HANDLE guest);

// FUNCTION:        start_all_guest_cpus
// DESCRIPTION:     Start all CPUs running given guest, previously stopped by stop_all_guest_cpus().
//                  Execute handler upon start.
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 start_all_guest_cpus(GUEST_HANDLE guest, IPC_HANDLER_FN handler, void* arg);

// FUNCTION:        ipc_mni_injection_failed
// DESCRIPTION:     Called when NMI injection to guest failed and should be performed once more later.
void ipc_mni_injection_failed(void);

// FUNCTION:        ipc_send_message
// DESCRIPTION:     Send IPC to destination CPUs. Returns just before handlers are about to execute.
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_send_message(IPC_DESTINATION dst, IPC_MESSAGE_TYPE type, IPC_HANDLER_FN handler, void* arg);

// FUNCTION:        ipc_send_message_sync
// DESCRIPTION:     Send IPC to destination CPUs. Returns after handlers finished their execution
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_send_message_sync(IPC_DESTINATION dst, IPC_MESSAGE_TYPE type, IPC_HANDLER_FN handler, void* arg);

// FUNCTION:        ipc_nmi_vmexit_handler
// DESCRIPTION:     NMI Vmexit handler.
// RETURN VALUE:    TRUE, if NMI handled by handler, FALSE if it should be handled by guest.
BOOLEAN ipc_nmi_vmexit_handler(GUEST_CPU_HANDLE gcpu);

// FUNCTION:        ipc_nmi_window_vmexit_handler
// DESCRIPTION:     NMI Window Vmexit handler.
// RETURN VALUE:    TRUE, if NMI handled by handler, FALSE if it should be handled by guest.
BOOLEAN ipc_nmi_window_vmexit_handler(GUEST_CPU_HANDLE gcpu);

// FUNCTION:        ipc_sipi_vmexit_handler
// DESCRIPTION:     Handle IPC if SIPI was due to IPC.
// RETURN VALUE:    TRUE, if SIPI was due to IPC, FALSE otherwise.
BOOLEAN ipc_sipi_vmexit_handler(GUEST_CPU_HANDLE gcpu);

void ipc_print_cpu_context(CPU_ID cpu_id, BOOLEAN use_lock);

#endif
