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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(IPC_API_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(IPC_API_C, __condition)
#include "vmm_defs.h"
#include "ipc_impl.h"
#include "lock.h"
#include "heap.h"
#include "vmm_objects.h"
#include "guest.h"
#include "hw_utils.h"
#include "scheduler.h"
#include "vmm_dbg.h"
#include "list.h"
#include "memory_allocator.h"

#pragma warning( disable : 4100)        // unreferenced formal parameter

#define STOP_ALL_CONTEXT_ID      INVALID_GUEST_ID

// callback to check if current CPU is destination for IPC
typedef BOOLEAN (*is_destination_fn)(void* arg);
static BOOLEAN all_cpus(void *arg);
static BOOLEAN is_cpu_running_guest(void *arg);

// Context for start/stop IPCs.
// Send Stop IPC:
//      -- context->stop = true;
//      -- send IPC
// Handle Stop IPC:
//      -- busy-loop while context->stop == true
// Send Start IPC (finish the busy loop):
//      -- context->stop = false;
// Timestamps are used in order not to miss change of the context->stop (fast start/stop)
typedef struct _STOP_CPU_CONTEXT
{
    volatile BOOLEAN         stop;                      // variable to busy-loop
    UINT32                   timestamp;                 // timestamp of the stop command
    volatile UINT32          current_timestamp;         // latest assigned timestamp.
                                                        // Can differ from timestamp (fast start/stop).
    UINT32                   num_stopped_cpus;          // number of CPUs stopped by CPU command
    volatile IPC_HANDLER_FN  on_start_handler;          // handler to execute when start command arrives
    volatile void            *on_start_handler_arg;     // argument to the start handler
    is_destination_fn        is_destination;            // function to check if current CPU is destination for IPC
    void                     *is_destination_arg;       // argument for is_destination()
    GUEST_ID                 guest_id;
    char                     padding[6];
    LIST_ELEMENT             list[1];
} STOP_CPU_CONTEXT;

static BOOLEAN execute_stop(STOP_CPU_CONTEXT *context, is_destination_fn is_destination, void* is_destination_arg);
static UINT32 execute_start(STOP_CPU_CONTEXT *context, IPC_HANDLER_FN handler, void* arg);
static STOP_CPU_CONTEXT *ipc_find_stop_guest_cpus_context(GUEST_ID guest_id);

// Context for stop/start IPCs -- one context per guest to support start/stop guest CPUs
// plus one context to support stop/start all CPUs
typedef struct _IPC_START_STOP_CONTEXT
{
    LIST_ELEMENT         ipc_stop_context[1];
//    VMM_READ_WRITE_LOCK  context_lock[1];               // lock for context list
    VMM_LOCK             stop_lock[1];                  // lock for exclusive start/stop execution
} IPC_START_STOP_CONTEXT;

IPC_START_STOP_CONTEXT ipc_start_stop_context;

// FUNCTION:        ipc_execute_handler
// DESCRIPTION:     Execute handler on other CPUs. This function returns when all destination
//                  CPUs are about to execute the handler
// ARGUMENTS:       dst -- destination CPU(s)
//                  handler -- handler for execution
//                  arg -- argument to pass to the handler
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_execute_handler(IPC_DESTINATION dst, IPC_HANDLER_FN handler, void* arg)
{
    return ipc_send_message(dst, IPC_TYPE_NORMAL, handler, arg);
}

// FUNCTION:        ipc_execute_handler
// DESCRIPTION:     Execute handler on other CPUs. This function returns when all destination
//                  CPUs finished to execute the handler
// ARGUMENTS:       dst -- destination CPU(s)
//                  handler -- handler for execution
//                  arg -- argument to pass to the handler
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_execute_handler_sync(IPC_DESTINATION dst, IPC_HANDLER_FN handler, void* arg)
{
    return ipc_send_message_sync(dst, IPC_TYPE_NORMAL, handler, arg);
}

// FUNCTION:        stop_all_cpus
// DESCRIPTION:     Stop all other CPUs. Other CPUs will be executing the busy loop until
//                  they are resumed by calling start_all_cpus()
// RETURN VALUE:    TRUE if all processors has stopped, FALSE in case of failure
BOOLEAN stop_all_cpus(void)
{
    STOP_CPU_CONTEXT *context = ipc_find_stop_guest_cpus_context(STOP_ALL_CONTEXT_ID);

    return execute_stop(context, all_cpus, NULL);
}

// FUNCTION:        start_all_cpus
// DESCRIPTION:     Start all other CPUs previously stopped by stop_all_cpus()
// RETURN VALUE:    TRUE if all processors has resumed, FALSE in case of failure
UINT32 start_all_cpus(IPC_HANDLER_FN handler, void* arg)
{
    STOP_CPU_CONTEXT *context = ipc_find_stop_guest_cpus_context(STOP_ALL_CONTEXT_ID);

    return execute_start(context, handler, arg);
}

// FUNCTION:        stop_all_guest_cpus
// DESCRIPTION:     Stop all CPUs running given guest. These CPUs will be executing the busy loop until
//                  they are resumed by calling start_all_guest_cpus()
// RETURN VALUE:    TRUE if CPUs running guest has stopped, FALSE in case of failure
BOOLEAN stop_all_guest_cpus(GUEST_HANDLE guest)
{
    STOP_CPU_CONTEXT *context = NULL;
    GUEST_ID guest_id = guest_get_id(guest);

    context = ipc_find_stop_guest_cpus_context(guest_id);

    return execute_stop(context, is_cpu_running_guest, (void *) (size_t) guest_id);
}

// FUNCTION:        start_all_guest_cpus
// DESCRIPTION:     Start all CPUs running given guest previously stopped by stop_all_guest_cpus()
// RETURN VALUE:    TRUE if all CPUs running guest has resumed, FALSE in case of failure
UINT32 start_all_guest_cpus(GUEST_HANDLE guest, IPC_HANDLER_FN handler, void* arg)
{
    STOP_CPU_CONTEXT *context = NULL;

    context = ipc_find_stop_guest_cpus_context(guest_get_id(guest));

    return execute_start(context, handler, arg);
}

// FUNCTION:        all_cpus
// DESCRIPTION:     Callback to check if current CPU is destination for IPC.
//                  all_cpus() is used for IPCs to all CPUs
// RETURN VALUE:    TRUE
BOOLEAN all_cpus(void *arg UNUSED)
{
    return TRUE;
}

// FUNCTION:        is_cpu_running_guest
// DESCRIPTION:     Callback to check if current CPU is destination for IPC.
//                  is_cpu_running_guest() is used for IPCs to CPUs running a specific guest
// ARGUMENTS:       arg -- guest id which CPUs need to stop
// RETURN VALUE:    TRUE if CPU executes the guest, FALSE if CPU does NOT execute the guest
BOOLEAN is_cpu_running_guest(void* arg)
{
    GUEST_ID stop_guest_id = (GUEST_ID) (size_t) arg;
    CPU_ID cpu_id = IPC_CPU_ID();
    GUEST_CPU_HANDLE gcpu = NULL;
    SCHEDULER_GCPU_ITERATOR iter;
    const VIRTUAL_CPU_ID *vcpu = NULL;

    for(gcpu = scheduler_same_host_cpu_gcpu_first(&iter, cpu_id); gcpu != NULL; gcpu = scheduler_same_host_cpu_gcpu_next(&iter))
    {
        vcpu = guest_vcpu(gcpu);
        VMM_ASSERT(vcpu);
        if(vcpu->guest_id == stop_guest_id)
        {
            return TRUE;
        }
    }

    return FALSE;
}


// FUNCTION:        stop_cpu_handler
// DESCRIPTION:     Handler that is called when IPC arrives. It stops the CPU
//                  by entering the busy-wait loop until corresponding start() is executed.
// ARGUMENTS:       arg -- IPC's context (STOP_CPU_CONTEXT)
void stop_cpu_handler(CPU_ID from, void* arg)
{
    STOP_CPU_CONTEXT *context = (STOP_CPU_CONTEXT *) arg;

    if (context->is_destination(context->is_destination_arg))
    {
        // check the timestamp in order not to miss "edge" of context->stop
        while (context->stop && context->timestamp == context->current_timestamp)
        {
            hw_pause();
            ipc_process_one_ipc();
        }

		// Check if on START handler should be performed.
		if (context->on_start_handler != NULL)
			context->on_start_handler(from, (void *) context->on_start_handler_arg);
    }
}


// FUNCTION:        execute_stop
// DESCRIPTION:     Send the stop IPC
// ARGUMENTS:       context -- context for busy-waiting at the receiver
//                  is_destination -- callback for destination CPU to check if it is target for IPC
//                  is_destination_arg -- argument for is_destination()
// RETURN VALUE:    TRUE if all destination processors has stopped, FALSE in case of failure
static BOOLEAN execute_stop(STOP_CPU_CONTEXT *context, is_destination_fn is_destination, void* is_destination_arg)
{
    IPC_DESTINATION dst;

    VMM_ASSERT( context != NULL );

    vmm_zeromem(&dst, sizeof(dst));

    interruptible_lock_acquire(ipc_start_stop_context.stop_lock);

    if (context->stop)
    {
		// already stopped - should not be here
        VMM_ASSERT( FALSE == context->stop );
        lock_release(ipc_start_stop_context.stop_lock);
        return FALSE;
    }

    context->stop = TRUE;
    context->timestamp = ++context->current_timestamp;
    context->is_destination = is_destination;
    context->is_destination_arg = is_destination_arg;

    dst.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;

    context->num_stopped_cpus = ipc_send_message(dst, IPC_TYPE_STOP, stop_cpu_handler, context);

    lock_release(ipc_start_stop_context.stop_lock);

    return TRUE;
}


// FUNCTION:        execute_start
// DESCRIPTION:     Send the start IPC
// ARGUMENTS:       context -- context used for busy-waiting at the receiver
// RETURN VALUE:    TRUE if all destination processors has started, FALSE in case of failure
static UINT32 execute_start(STOP_CPU_CONTEXT *context, IPC_HANDLER_FN handler, void* arg)
{
    IPC_DESTINATION dst;

    VMM_ASSERT( context != NULL );

    vmm_zeromem(&dst, sizeof(dst));

    interruptible_lock_acquire(ipc_start_stop_context.stop_lock);

    if (FALSE == context->stop)
    {
		// not stopped - should not be here
        VMM_ASSERT( TRUE == context->stop );
        lock_release(ipc_start_stop_context.stop_lock);
        return FALSE;
    }

    //if(handler != NULL)
    //{
    //    ipc_execute_handler_sync(dst, handler, arg);
    //}
    context->on_start_handler = handler;
    context->on_start_handler_arg = arg;
    context->stop = FALSE;

    dst.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;

    ipc_send_message(dst, IPC_TYPE_START, NULL, NULL);

    lock_release(ipc_start_stop_context.stop_lock);

    return context->num_stopped_cpus;
}


// FUNCTION:        ipc_initialize
// DESCRIPTION:     Initialize stop/start context and initialize IPC engine. Must be called before any IPCs can be generated.
// RETURN VALUE:    TRUE for success, FALSE for failure
BOOLEAN ipc_initialize(UINT16 number_of_host_processors)
{
    BOOLEAN           status;
    STOP_CPU_CONTEXT  *stop_all_context = NULL;
    GUEST_HANDLE      guest = NULL;
    GUEST_ID          guest_id = INVALID_GUEST_ID;
    GUEST_ECONTEXT    context;

    vmm_zeromem(&ipc_start_stop_context, sizeof(ipc_start_stop_context));

    status = ipc_state_init(number_of_host_processors);
    // BEFORE_VMLAUNCH. NOT_USED. OLD_IPC is not defined.
    VMM_ASSERT(status);

    list_init(ipc_start_stop_context.ipc_stop_context);
    lock_initialize(ipc_start_stop_context.stop_lock);

    stop_all_context = vmm_malloc(sizeof(STOP_CPU_CONTEXT));
    // BEFORE_VMLAUNCH. NOT_USED. OLD_IPC is not defined.
    VMM_ASSERT(stop_all_context);
    vmm_zeromem(stop_all_context, sizeof(STOP_CPU_CONTEXT));

    stop_all_context->guest_id = INVALID_GUEST_ID;

    list_add(ipc_start_stop_context.ipc_stop_context, stop_all_context->list);

    for(guest = guest_first(&context); guest != NULL; guest = guest_next(&context))
    {
        guest_id = guest_get_id(guest);
        ipc_guest_initialize(guest_id);
    }

    return TRUE;
}

// FUNCTION:        ipc_guest_initialize
// DESCRIPTION:     Initialize stop/start context and initialize IPC engine for a guest. Must be called when new guest is added.
// RETURN VALUE:    TRUE for success, FALSE for failure
BOOLEAN ipc_guest_initialize(GUEST_ID guest_id)
{
    BOOLEAN           status;
    STOP_CPU_CONTEXT  *stop_guest_cpus_context = NULL;

    status = ipc_guest_state_init(guest_id);
    // BEFORE_VMLAUNCH. NOT_USED. OLD_IPC is not defined.
    VMM_ASSERT(status);

    stop_guest_cpus_context = vmm_malloc(sizeof(STOP_CPU_CONTEXT));
    // BEFORE_VMLAUNCH. NOT_USED. OLD_IPC is not defined.
    VMM_ASSERT(stop_guest_cpus_context);
    vmm_zeromem(stop_guest_cpus_context, sizeof(STOP_CPU_CONTEXT));

    stop_guest_cpus_context->guest_id = guest_id;

    list_add(ipc_start_stop_context.ipc_stop_context, stop_guest_cpus_context->list);

    return TRUE;
}

static
STOP_CPU_CONTEXT *ipc_find_stop_guest_cpus_context(GUEST_ID guest_id)
{
    LIST_ELEMENT *iter = NULL;
    STOP_CPU_CONTEXT *stop_cpu_context = NULL;

    LIST_FOR_EACH(ipc_start_stop_context.ipc_stop_context, iter)
    {
        stop_cpu_context = LIST_ENTRY(iter, STOP_CPU_CONTEXT, list);
        if(stop_cpu_context->guest_id == guest_id)
        {
            return stop_cpu_context;
        }
    }

    return NULL;
}
