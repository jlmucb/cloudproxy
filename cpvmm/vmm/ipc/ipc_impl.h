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

#ifndef _IPC_IMPL_H
#define _IPC_IMPL_H

#include "vmm_defs.h"
#include "isr.h"
#include "list.h"
#include "ipc.h"
#include "lock.h"


#define IPC_ALIGNMENT                         ARCH_ADDRESS_WIDTH


#define IPC_CPU_ID()                          hw_cpu_id()

#define NMI_VECTOR                            2

#define NMIS_WAITING_FOR_PROCESSING(ipc)      (ipc->num_received_nmi_interrupts - ipc->num_processed_nmi_interrupts)
#define IPC_NMIS_WAITING_FOR_PROCESSING(ipc)  (ipc->num_of_sent_ipc_nmi_interrupts - ipc->num_of_processed_ipc_nmi_interrupts)

// %VT% typedef struct _ARRAY_LIST      *ARRAY_LIST_HANDLE;
// %VT% typedef struct _IPC_CPU_CONTEXT IPC_CPU_CONTEXT;
// %VT% typedef struct _ARRAY_LIST ARRAY_LIST;
// %VT% typedef struct _IPC_MESSAGE IPC_MESSAGE;

typedef struct _IPC_MESSAGE
{
    IPC_MESSAGE_TYPE  type;
    CPU_ID            from;
    char              padding[2];
    IPC_HANDLER_FN    handler;
    void              *arg;
    volatile UINT32   *before_handler_ack;
    volatile UINT32   *after_handler_ack;
} IPC_MESSAGE;

typedef enum
{
    IPC_CPU_NOT_ACTIVE = 0,
    IPC_CPU_ACTIVE,
	IPC_CPU_SIPI
} IPC_CPU_ACTIVITY_STATE;

typedef struct _IPC_CPU_CONTEXT
{
    volatile UINT64    num_received_nmi_interrupts;
    UINT64             num_processed_nmi_interrupts;
    
    UINT64             num_of_sent_ipc_nmi_interrupts;
    UINT64             num_of_processed_ipc_nmi_interrupts;
    
    volatile UINT64    num_blocked_nmi_injections_to_guest;
    volatile UINT64    num_start_messages;
    volatile UINT64    num_stop_messages;

    ARRAY_LIST_HANDLE  message_queue;
    UINT64             num_of_sent_ipc_messages;
    UINT64             num_of_received_ipc_messages;

    VMM_LOCK           data_lock;
} IPC_CPU_CONTEXT;

BOOLEAN ipc_state_init(UINT16 number_of_host_processors);

BOOLEAN ipc_guest_state_init(GUEST_ID guest_id);


#endif
