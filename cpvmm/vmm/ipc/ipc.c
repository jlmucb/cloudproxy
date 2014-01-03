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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(IPC_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(IPC_C, __condition)
#include "hw_interlocked.h"
#include "vmm_defs.h"
#include "ipc_impl.h"
#include "scheduler.h"
#include "vmcs_actual.h"
#include "vmx_ctrl_msrs.h"
#include "list.h"
#include "heap.h"
#include "guest_cpu_vmenter_event.h"
#include "vmm_dbg.h"
#include "guest.h"
#include "cli.h"
#include "vmx_nmi.h"
#include "hw_includes.h"


#pragma warning( disable : 4100)        // unreferenced formal parameter


static UINT16                  num_of_host_processors = 0;
static GUEST_ID                nmi_owner_guest_id = 0;
static char                    *ipc_state_memory = NULL;

// per-CPU contexts for IPC bookkeeping
static IPC_CPU_CONTEXT         *ipc_cpu_contexts = NULL;

// Acknowledge array.
static volatile UINT32         *ipc_ack_array = NULL;

// Per CPU activity state -- active/not-active (Wait-for-SIPI)
static volatile IPC_CPU_ACTIVITY_STATE  *cpu_activity_state = NULL;

// IPC send lock in order to have only one send in progress.
static VMM_LOCK                send_lock;

// Forward declaration of message preprocessing function.
static BOOLEAN ipc_preprocess_message(IPC_CPU_CONTEXT *ipc, CPU_ID dst, IPC_MESSAGE_TYPE  msg_type);

// Forward declaration of IPC cli registartion function.
static void ipc_cli_register(void);


// Debug variables.
static INT32                   debug_not_resend = 0;


// ***************************** Local Utilities ***********************************************

static UINT32 ipc_get_max_pending_messages(UINT32 number_of_host_processors)
{
    // the max ipc message queue length for each processor.
    return number_of_host_processors;
}

static UINT32 ipc_get_message_array_list_size(UINT32 number_of_host_processors) 
{
    return (UINT32) ALIGN_FORWARD(array_list_memory_size(
                                                            NULL, 
                                                            sizeof(IPC_MESSAGE), 
                                                            ipc_get_max_pending_messages(number_of_host_processors), 
                                                            IPC_ALIGNMENT
                                                         ), 
                                  IPC_ALIGNMENT);
}

static BOOLEAN ipc_hw_signal_nmi(IPC_DESTINATION dst)
{
    return local_apic_send_ipi(dst.addr_shorthand, dst.addr, IPI_DESTINATION_MODE_PHYSICAL,
                               IPI_DELIVERY_MODE_NMI, 0, IPI_DELIVERY_LEVEL_ASSERT /* must be 1 */,
                               IPI_DELIVERY_TRIGGER_MODE_EDGE);
}


static BOOLEAN ipc_hw_signal_sipi(IPC_DESTINATION dst)
{
    return local_apic_send_ipi(dst.addr_shorthand, dst.addr, IPI_DESTINATION_MODE_PHYSICAL,
                               IPI_DELIVERY_MODE_START_UP, 0xFF, IPI_DELIVERY_LEVEL_ASSERT,
                               IPI_DELIVERY_TRIGGER_MODE_EDGE);
}

#ifdef INCLUDE_UNUSED_CODE
static BOOLEAN ipc_is_nmi_owner_gcpu(GUEST_CPU_HANDLE gcpu)
{
    const VIRTUAL_CPU_ID *vcpu = NULL;

    vcpu = guest_vcpu(gcpu);

    return (vcpu->guest_id == nmi_owner_guest_id);
}
#endif


static BOOLEAN ipc_cpu_is_destination(IPC_DESTINATION dst, CPU_ID this_cpu_id, CPU_ID dst_cpu_id)
{
    BOOLEAN retVal = FALSE;

    switch(dst.addr_shorthand)
    {
    case IPI_DST_SELF:
        retVal = (this_cpu_id == dst_cpu_id);
        break;

    case IPI_DST_ALL_INCLUDING_SELF:
        retVal = TRUE;
        break;

    case IPI_DST_ALL_EXCLUDING_SELF:
        retVal = (this_cpu_id != dst_cpu_id);
        break;

    case IPI_DST_NO_SHORTHAND:
        retVal = ((CPU_ID) dst.addr == dst_cpu_id);
        break;

    case IPI_DST_CORE_ID_BITMAP:
        retVal = (BITMAP_ARRAY64_GET(dst.CoreBitMap, dst_cpu_id) != 0);
        break;
    }

    return retVal;
}


// **********************  Message Queue Management ***************************

static void ipc_increment_ack(volatile UINT32 *ack)
{
    if (NULL != ack)
    {
        hw_interlocked_increment((INT32 *) ack);
    }
}

// NOTE: Queue function are not multi-thread safe. Caller must first aquire the lock !!!

// FUNCTION:        ipc_enqueue_message
// DESCRIPTION:     Add message to the queue. Caller must acquire the lock before calling.
// RETURN VALUE:    TRUE if message was queued, FALSE if message could not be queued
static BOOLEAN ipc_enqueue_message(IPC_CPU_CONTEXT *ipc, IPC_MESSAGE_TYPE type, IPC_HANDLER_FN handler, void* arg,
                                   volatile UINT32 *before_handler_ack, volatile UINT32 *after_handler_ack)
{
    IPC_MESSAGE  msg;
    CPU_ID       cpu_id = IPC_CPU_ID();

    VMM_ASSERT(ipc != NULL);
    VMM_ASSERT(handler != NULL);

    msg.type = type;
    msg.from = cpu_id;
    msg.handler = handler;
    msg.arg = arg;
    msg.before_handler_ack = before_handler_ack;
    msg.after_handler_ack = after_handler_ack;

    return array_list_add(ipc->message_queue, &msg);
}

// FUNCTION:        ipc_dequeue_message
// DESCRIPTION:     Dequeue message for processing. Acknowledge the sender. Caller must acquire the lock before calling.
// RETURN VALUE:    TRUE if message was dequeued, FALSE if queue is empty
static IPC_MESSAGE *ipc_dequeue_message(IPC_CPU_CONTEXT *ipc)
{
    IPC_MESSAGE  *msg = NULL;

    VMM_ASSERT(ipc != NULL);

    msg = (IPC_MESSAGE *) array_list_first(ipc->message_queue, NULL);
    if (msg != NULL)
    {
        array_list_remove(ipc->message_queue, msg);
        ipc_increment_ack(msg->before_handler_ack);
        ipc->num_of_received_ipc_messages++;            // Receive IPC message counting.
    }

    return msg;
}

#ifdef INCLUDE_UNUSED_CODE
// FUNCTION:        ipc_clear_message_queue
// DESCRIPTION:     Clear message queue without processing. Acknowledge the sender. Caller must acquire the lock before calling.
static void ipc_clear_message_queue(IPC_CPU_CONTEXT *ipc)
{
    IPC_MESSAGE *msg = NULL;

    do
    {
        msg = ipc_dequeue_message(ipc);
        if (msg != NULL)
        {
            ipc_increment_ack(msg->after_handler_ack);
        }
    } while(msg != NULL);
}
#endif

// **********************  IPC Mechanism ***************************

// FUNCTION:        ipc_execute_send
// DESCRIPTION:     Send message to destination processors.
// RETURN VALUE:    number of CPUs on which handler is about to execute

UINT32 ipc_execute_send(IPC_DESTINATION   dst,
                        IPC_MESSAGE_TYPE  type,
                        IPC_HANDLER_FN    handler,
                        void              *arg,
                        BOOLEAN           wait_for_handler_finish)
{
    CPU_ID                  i;
    CPU_ID                  sender_cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT         *ipc = NULL;
    volatile UINT32         num_received_acks = 0;
    UINT32                  num_required_acks = 0;
    volatile UINT32         *ack_array = &ipc_ack_array[sender_cpu_id * num_of_host_processors];
    BOOLEAN                 status;
    IPC_DESTINATION         single_dst;
    UINT32                  wait_count = 0;
    UINT64                  nmi_accounted_flag[CPU_BITMAP_MAX] = {0};
    UINT64                  enqueue_flag[CPU_BITMAP_MAX] = {0};
    UINT64                  next_send_tsc;

    // Initializ ack array.
    vmm_memset((void *) ack_array, 0, num_of_host_processors * sizeof(UINT32));

    for(i = 0; i < num_of_host_processors; i++)
    {
        if (i != sender_cpu_id)                                 // Exclude yourself.
        {
            if (ipc_cpu_is_destination(dst, sender_cpu_id, i))
            {
                ipc = &ipc_cpu_contexts[i];

                lock_acquire(&ipc->data_lock);                  // Aquire lock to prevent mutual data access.

                if (ipc_preprocess_message(ipc, i, type))       // Preprocess IPC and check if need to enqueue.
                {
                    BOOLEAN  empty_queue = (array_list_size(ipc->message_queue) == 0);

                    BITMAP_ARRAY64_SET(enqueue_flag, i);                    // Mark CPU active.

                    num_required_acks++;
                    if (!wait_for_handler_finish)               // Do not wait for handlers to finish.
                        status = ipc_enqueue_message(ipc, type, handler, arg, &ack_array[i], NULL);
                    else                                        // Wait for handlers to finish.
                        status = ipc_enqueue_message(ipc, type, handler, arg, NULL, &ack_array[i]);

                    ipc->num_of_sent_ipc_messages++;            // IPC sent message counting.

                    // BEFORE_VMLAUNCH
                    VMM_ASSERT(status);

                    // Check if IPC signal should be sent.
                    if (empty_queue)
                    {
                        // Send IPC signal (NMI or SIPI)
                        single_dst.addr_shorthand = IPI_DST_NO_SHORTHAND;
                        single_dst.addr = (UINT8)i;

						if (cpu_activity_state[i] == IPC_CPU_ACTIVE)
						{
                            BITMAP_ARRAY64_SET(nmi_accounted_flag, i);

							ipc->num_of_sent_ipc_nmi_interrupts++;

	                        ipc_hw_signal_nmi(single_dst);
						}
						else
							ipc_hw_signal_sipi(single_dst);
                    }
                }

                lock_release(&ipc->data_lock);
            }
        }
    }

    if (num_required_acks > 0)
    {
        // BEFORE_VMLAUNCH
        VMM_ASSERT(hw_get_tsc_ticks_per_second() != 0);

        next_send_tsc = hw_rdtsc() + hw_get_tsc_ticks_per_second(); // Calculate next tsc tick to resend NMI.
                                                                    // Should be one second.

        // signal and wait for acknowledge
        while (num_received_acks != num_required_acks)
        {
            // Check wait count and time.
            if (wait_count++ > 1000 && hw_rdtsc() > next_send_tsc)
            {
                wait_count = 0;
                next_send_tsc = hw_rdtsc() + hw_get_tsc_ticks_per_second();

                for (i = 0, num_received_acks = 0; i < num_of_host_processors; i++)
                {
                    // Send additional IPC signal to stalled cores.
                    if (BITMAP_ARRAY64_GET(enqueue_flag, i) && !ack_array[i])    // exclude yourself and non active CPUs.
                    {
                        single_dst.addr_shorthand = IPI_DST_NO_SHORTHAND;
                        single_dst.addr = (UINT8) i;

                        // BEFORE_VMLAUNCH
						// Check that CPU is still active.
						VMM_ASSERT(cpu_activity_state[i] != IPC_CPU_NOT_ACTIVE);
						if (!debug_not_resend)
                        {
                            ipc = &ipc_cpu_contexts[i];

                            lock_acquire(&ipc->data_lock);

    						if (cpu_activity_state[i] == IPC_CPU_ACTIVE)
    						{
                                if (!BITMAP_ARRAY64_GET(nmi_accounted_flag, i))
    							{
                                    BITMAP_ARRAY64_SET(nmi_accounted_flag, i);
    								ipc->num_of_sent_ipc_nmi_interrupts++;
    							}

    	                        ipc_hw_signal_nmi(single_dst);

    							VMM_LOG(mask_anonymous, level_trace,"[%d] send additional NMI to %d\n", (int) sender_cpu_id, (int) i);
    						}
    						else
    						{
    							ipc_hw_signal_sipi(single_dst);
                            	VMM_LOG(mask_anonymous, level_trace,"[%d] send additional SIPI to %d\n", (int) sender_cpu_id, (int) i);
    						}

                            lock_release(&ipc->data_lock);
						}
                    }
                }
            }
            else
            {
                // Try to processs own received messages.
                // To prevent deadlock situation when 2 core send messages simultaneously.
                if (!ipc_process_one_ipc())
                    hw_pause();

                // Count received acks.
                for (i = 0, num_received_acks = 0; i < num_of_host_processors; i++)
                    num_received_acks += ack_array[i];
            }
        }
    }

    return num_required_acks;
}


// FUNCTION:        ipc_process_all_ipc_messages
// DESCRIPTION:     Process all IPC from this CPU's message queue.
void ipc_process_all_ipc_messages(IPC_CPU_CONTEXT  *ipc, BOOLEAN  nmi_flag)
{
    IPC_MESSAGE      *msg = 0;
    IPC_HANDLER_FN   handler = NULL;
    void             *arg = NULL;
    volatile UINT32  *after_handler_ack = NULL;
    BOOLEAN          last_msg = FALSE;

    if (array_list_size(ipc->message_queue) == 0)
        return;

    // Process all IPC messages.
    lock_acquire(&ipc->data_lock);

    do
    {
        // Get an IPC message from the queue.
        msg = ipc_dequeue_message(ipc);

        VMM_ASSERT(msg != NULL);

        // Check for last message.
        if (array_list_size(ipc->message_queue) == 0)
        {
            last_msg = TRUE;

            // Adjust processed interrupt counters.
            if (nmi_flag)
            {
                ipc->num_processed_nmi_interrupts++;
                ipc->num_of_processed_ipc_nmi_interrupts++;
            }
        }

        // Process message.
        handler = msg->handler;
        arg = msg->arg;
        after_handler_ack = msg->after_handler_ack;

        lock_release(&ipc->data_lock);

        handler(IPC_CPU_ID(), arg);

        lock_acquire(&ipc->data_lock);

        // Postprocessing.
        ipc_increment_ack(after_handler_ack);
    } while (!last_msg);

    lock_release(&ipc->data_lock);
}

#ifdef ENABLE_VTD
extern BOOLEAN vtd_handle_fault(void);
#endif

// FUNCTION:        ipc_dispatcher
// DESCRIPTION:     Dequeue message and call the handler. Caller must acquire the lock before calling.
// RETURN VALUE:    TRUE if message was handled, FALSE if queue is empty
static BOOLEAN ipc_dispatcher(IPC_CPU_CONTEXT *ipc, GUEST_CPU_HANDLE gcpu UNUSED)
{
    BOOLEAN  nmi_injected_to_guest = FALSE;

    // Process all IPC messages.
    ipc_process_all_ipc_messages(ipc, TRUE);

    // Perform decision about MNI injection to guest.
    lock_acquire(&ipc->data_lock);

    VMM_DEBUG_CODE(
    // Sanity check.
    if (ipc->num_received_nmi_interrupts < ipc->num_processed_nmi_interrupts ||
        ipc->num_of_sent_ipc_nmi_interrupts < ipc->num_of_processed_ipc_nmi_interrupts)
    {
        VMM_LOG(mask_anonymous, level_trace,"[%d] IPC Anomaly\n", IPC_CPU_ID());
        VMM_DEADLOOP();
    }
    )

    // Check if we have blocked guest NMI's.
    if (ipc->num_blocked_nmi_injections_to_guest > 0)
    {
        VMM_LOG(mask_anonymous, level_trace,"[%d] - %s: Blocked Injection counter = %d\n", IPC_CPU_ID(),
                __FUNCTION__, ipc->num_blocked_nmi_injections_to_guest);

        nmi_injected_to_guest = TRUE;                   // Set injection flag.
        ipc->num_blocked_nmi_injections_to_guest--;     // Adjust blocked NMI counter.
    }
    else if (ipc->num_of_sent_ipc_nmi_interrupts != ipc->num_received_nmi_interrupts &&
             NMIS_WAITING_FOR_PROCESSING(ipc) != IPC_NMIS_WAITING_FOR_PROCESSING(ipc))
    {
     /*   VMM_LOG(mask_anonymous, level_trace,"[%d] - %s: NMI_RCVD = %d NMI_PROCESSED = %d, IPC_NMI_SENT = %d IPC_NMI_PROCESSED = %d\n",
                 IPC_CPU_ID(), __FUNCTION__,
                 ipc->num_received_nmi_interrupts, ipc->num_processed_nmi_interrupts,
                 ipc->num_of_sent_ipc_nmi_interrupts, ipc->num_of_processed_ipc_nmi_interrupts);
	*/
        nmi_injected_to_guest = TRUE;                   // Set injection flag.
        ipc->num_processed_nmi_interrupts++;            // Adjust common NMI processed counter.

        nmi_raise_this();
    }

    lock_release(&ipc->data_lock);

    return nmi_injected_to_guest;
}

#ifdef ENABLE_VTD
extern BOOLEAN vtd_handle_fault(void);
#endif

// FUNCTION:        ipc_nmi_interrupt_handler
// DESCRIPTION:     ISR to handle NMI exception while in VMM (vector 2).
//                  Enables NMI Window for all guests to defer handling to more
//                  convinient conditions (e.g. stack, blocking etc.)
static void ipc_nmi_interrupt_handler(const ISR_PARAMETERS_ON_STACK  *p_stack UNUSED)
{
    CPU_ID            cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT   *ipc = &ipc_cpu_contexts[cpu_id];
    GUEST_CPU_HANDLE  gcpu = NULL;

#ifdef ENABLE_VTD
        if (vtd_handle_fault())
        {
            return;
        }
#endif // ENABLE_VTD

    hw_interlocked_increment64((INT64*)(&ipc->num_received_nmi_interrupts));

    // inject nmi windows to right guest on this host cpu.
    gcpu = scheduler_current_gcpu();
    VMM_ASSERT(gcpu);
    vmcs_nmi_handler(gcpu_get_vmcs(gcpu));
}


// FUNCTION:        ipc_nmi_window_vmexit_handler
// DESCRIPTION:     Handle Vm-Exit due to NMI Window -- handle pending IPC if any.
//                  Decide on injecting NMIs to guest if required.
BOOLEAN ipc_nmi_window_vmexit_handler(GUEST_CPU_HANDLE gcpu)
{
    CPU_ID           cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT  *ipc = &ipc_cpu_contexts[cpu_id];

    VMM_ASSERT(gcpu != NULL);

    gcpu_set_pending_nmi(gcpu, 0);                      // disable nmi window

    // handle queued IPC's
    return !ipc_dispatcher(ipc, gcpu);
}


// FUNCTION:        ipc_nmi_vmexit_handler
// DESCRIPTION:     Handle Vm-Exit due to NMI while in guest. Handle IPC if NMI was due to IPC.
//                  Reflect NMI back to guest if it is hardware or guest initiated NMI.
BOOLEAN ipc_nmi_vmexit_handler(GUEST_CPU_HANDLE gcpu)
{
    CPU_ID           cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT  *ipc = &ipc_cpu_contexts[cpu_id];

#ifdef ENABLE_VTD
	if(vtd_handle_fault())
	{
		// Clean hardware NMI block.
		hw_perform_asm_iret();
		return TRUE;
	}
#endif //ENABLE_VTD

	hw_interlocked_increment64((INT64*)&ipc->num_received_nmi_interrupts);
	
	hw_perform_asm_iret();

    // Handle queued IPC's
    return !ipc_dispatcher(ipc, gcpu);
}


// FUNCTION:        ipc_sipi_vmexit_handler
// DESCRIPTION:     Handle IPC if SIPI was due to IPC.
// RETURN VALUE:    TRUE, if SIPI was due to IPC, FALSE otherwise.
BOOLEAN ipc_sipi_vmexit_handler(GUEST_CPU_HANDLE gcpu)
{
    CPU_ID                       cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT              *ipc = &ipc_cpu_contexts[cpu_id];
    VMCS_OBJECT                  *vmcs = gcpu_get_vmcs(gcpu);
    IA32_VMX_EXIT_QUALIFICATION  qualification;
    BOOLEAN                      ret_val = FALSE;

	qualification.Uint64 = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);

	// Check if this is IPC SIPI signal.
	if (qualification.Sipi.Vector == 0xFF)
	{
	    // Process all IPC messages.
    	ipc_process_all_ipc_messages(ipc, FALSE);

        // Clear all NMI counters.
        lock_acquire(&ipc->data_lock);

        ipc->num_received_nmi_interrupts = 0;
        ipc->num_processed_nmi_interrupts = 0;
        ipc->num_of_sent_ipc_nmi_interrupts = 0;
        ipc->num_of_processed_ipc_nmi_interrupts = 0;
        ipc->num_blocked_nmi_injections_to_guest = 0;

        lock_release(&ipc->data_lock);

		ret_val = TRUE;
	}

	return ret_val;
}


// **********************  IPC Send Preprocessing ***************************

// FUNCTION:        ipc_preprocess_normal_message
// DESCRIPTION:     Preprocess normal message. Caller must acquire the lock before calling.
// RETURN VALUE:    TRUE if message must be enqueued at destination CPU, FALSE if message should not be queued
BOOLEAN ipc_preprocess_normal_message(IPC_CPU_CONTEXT *ipc UNUSED, CPU_ID dst)
{
    BOOLEAN enqueue_to_dst;

    enqueue_to_dst = (cpu_activity_state[dst] != IPC_CPU_NOT_ACTIVE);

    return enqueue_to_dst;
}


// FUNCTION:        ipc_preprocess_start_message
// DESCRIPTION:     Preprocess ON message. Caller must acquire the lock before calling.
// RETURN VALUE:    TRUE if message must be enqueued at destination CPU, FALSE if message should not be queued
BOOLEAN ipc_preprocess_start_message(IPC_CPU_CONTEXT *ipc, CPU_ID dst UNUSED)
{
	ipc->num_start_messages++;

	// never enqueue 'start' message
	return FALSE;
}


// FUNCTION:        ipc_preprocess_stop_message
// DESCRIPTION:     Preprocess OFF message. Caller must acquire the lock before calling.
// RETURN VALUE:    TRUE if message must be enqueued at destination CPU, FALSE if message should not be queued
BOOLEAN ipc_preprocess_stop_message(IPC_CPU_CONTEXT *ipc, CPU_ID dst)
{
    BOOLEAN enqueue_to_dst;

	enqueue_to_dst = (cpu_activity_state[dst] != IPC_CPU_NOT_ACTIVE);

    ipc->num_stop_messages++;

    return enqueue_to_dst;
}


// FUNCTION:        ipc_preprocess_message
// DESCRIPTION:     Preprocess message. Caller must acquire the lock before calling.
// RETURN VALUE:    TRUE  if message must be enqueued at destination CPU,
//                  FALSE if message should not be queued
BOOLEAN ipc_preprocess_message(IPC_CPU_CONTEXT *ipc , CPU_ID dst, IPC_MESSAGE_TYPE  msg_type)
{
    BOOLEAN enqueue_to_dst = FALSE;

    switch (msg_type)
    {
        case IPC_TYPE_NORMAL:
            enqueue_to_dst = ipc_preprocess_normal_message(ipc, dst);
            break;

        case IPC_TYPE_START:
            enqueue_to_dst = ipc_preprocess_start_message(ipc, dst);
            break;

        case IPC_TYPE_STOP:
            enqueue_to_dst = ipc_preprocess_stop_message(ipc, dst);
            break;

        case IPC_TYPE_SYNC:
        default:
            break;
    }

    return enqueue_to_dst;
}


// **********************  IPC API Implementation ***************************

// FUNCTION:        ipc_send_message
// DESCRIPTION:     Send IPC to destination CPUs. Returns just before handlers are about to execute.
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_send_message(IPC_DESTINATION dst, IPC_MESSAGE_TYPE type, IPC_HANDLER_FN handler, void* arg)
{
    UINT32  num_of_receivers = 0;

	if ((int) type >= IPC_TYPE_NORMAL && (int) type < IPC_TYPE_LAST)
	{
		switch (dst.addr_shorthand)
		{
//		case IPI_DST_SELF:
//		case IPI_DST_ALL_INCLUDING_SELF:
		case IPI_DST_ALL_EXCLUDING_SELF:
		case IPI_DST_NO_SHORTHAND:
		case IPI_DST_CORE_ID_BITMAP:
		//	interruptible_lock_acquire(&send_lock);
			num_of_receivers = ipc_execute_send(dst, type, handler, arg, FALSE);
		//	lock_release(&send_lock);
			break;

		default:
			VMM_LOG(mask_anonymous, level_trace,"ipc_send_message: Bad message destination shorthand 0x%X\r\n", dst.addr_shorthand);
			break;
	    }
	}
	else
	{
		VMM_LOG(mask_anonymous, level_trace,"ipc_send_message: Bad message type %d\r\n", type);
	}

    return num_of_receivers;
}


// FUNCTION:        ipc_send_message_sync
// DESCRIPTION:     Send IPC to destination CPUs. Returns after handlers finished their execution
// RETURN VALUE:    number of CPUs on which handler is about to execute
UINT32 ipc_send_message_sync(IPC_DESTINATION dst, IPC_MESSAGE_TYPE type, IPC_HANDLER_FN handler, void* arg)
{
    UINT32  num_of_receivers = 0;

	if ((int) type >= IPC_TYPE_NORMAL && (int) type < IPC_TYPE_LAST)
	{
		switch (dst.addr_shorthand)
		{
//		case IPI_DST_SELF:
//		case IPI_DST_ALL_INCLUDING_SELF:
		case IPI_DST_ALL_EXCLUDING_SELF:
		case IPI_DST_NO_SHORTHAND:
		case IPI_DST_CORE_ID_BITMAP:            
	//		interruptible_lock_acquire(&send_lock);
			num_of_receivers = ipc_execute_send(dst, type, handler, arg, TRUE);
	//		lock_release(&send_lock);
			break;

		default:
			VMM_LOG(mask_anonymous, level_trace,"ipc_send_message_sync: Bad message destination shorthand 0x%X\r\n", dst.addr_shorthand);
			break;
	    }
	}
	else
	{
		VMM_LOG(mask_anonymous, level_trace,"ipc_send_message_sync: Bad message type %d\r\n", type);
	}
    return num_of_receivers;
}


// FUNCTION:        ipc_process_one_ipc
// DESCRIPTION:     Process one IPC from this CPU's message queue.
// RETURN VALUE:    TRUE if IPC was processed, FALSE if there were no pending IPCs.
BOOLEAN ipc_process_one_ipc(void)
{
    CPU_ID           cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT  *ipc = &ipc_cpu_contexts[cpu_id];
    IPC_MESSAGE      *msg = 0;
    IPC_HANDLER_FN   handler = NULL;
    void             *arg = NULL;
    volatile UINT32  *after_handler_ack = NULL;
    BOOLEAN          process_ipc_msg = FALSE;

    if (array_list_size(ipc->message_queue) == 0)
        return process_ipc_msg;

    lock_acquire(&ipc->data_lock);

    msg = ipc_dequeue_message(ipc);
    process_ipc_msg = (msg != NULL);

    if (process_ipc_msg)
    {
        // Check for last message.
        if (array_list_size(ipc->message_queue) == 0 && cpu_activity_state[cpu_id] == IPC_CPU_ACTIVE)
        {
            // Adjust processed interrupt counters.
            ipc->num_processed_nmi_interrupts++;
            ipc->num_of_processed_ipc_nmi_interrupts++;
        }

        // Process a message.
        handler = msg->handler;
        arg = msg->arg;
        after_handler_ack = msg->after_handler_ack;

        lock_release(&ipc->data_lock);

        handler(IPC_CPU_ID(), arg);

        lock_acquire(&ipc->data_lock);

        // Postprocessing.
        ipc_increment_ack(after_handler_ack);
    }

    lock_release(&ipc->data_lock);

    return process_ipc_msg;
}


// FUNCTION:        ipc_change_state_to_active
// DESCRIPTION:     Mark CPU as ready for IPC. Called when CPU is no longer in Wait-for-SIPI state.
//                  Waits for all start/stop messages to arrive before changing CPU's state.
void ipc_change_state_to_active(GUEST_CPU_HANDLE gcpu UNUSED)
//void ipc_change_state_to_active(GUEST_CPU_HANDLE gcpu UNUSED)
{
    CPU_ID           cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT  *ipc = &ipc_cpu_contexts[cpu_id];

    if (cpu_activity_state[cpu_id] == IPC_CPU_ACTIVE)
        return;

    lock_acquire(&ipc->data_lock);

    cpu_activity_state[cpu_id] = IPC_CPU_ACTIVE;

    lock_release(&ipc->data_lock);

    VMM_LOG(mask_anonymous, level_trace,"CPU%d: IPC state changed to ACTIVE\n", cpu_id);
}


// FUNCTION:        ipc_change_state_to_sipi
// DESCRIPTION:     Mark CPU as NOT ready for IPC. Called when CPU is about to enter Wait-for-SIPI state.
//                  Acknowledge and discard all queued messages.
void ipc_change_state_to_sipi(GUEST_CPU_HANDLE gcpu)
{
    CPU_ID           cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT  *ipc = &ipc_cpu_contexts[cpu_id];

    if (cpu_activity_state[cpu_id] == IPC_CPU_SIPI)
		return;

    lock_acquire(&ipc->data_lock);

    cpu_activity_state[cpu_id] = IPC_CPU_SIPI;

    gcpu_set_pending_nmi(gcpu, 0);

    lock_release(&ipc->data_lock);

    VMM_LOG(mask_anonymous, level_trace,"CPU%d: IPC state changed to SIPI\n", cpu_id);
}

// FUNCTION:        ipc_mni_injection_failed
// DESCRIPTION:     Called when NMI injection to gues failed and should be performed once more later.
//                  Adjust right ounters.
void ipc_mni_injection_failed(void)
{
    CPU_ID           cpu_id = IPC_CPU_ID();
    IPC_CPU_CONTEXT  *ipc = &ipc_cpu_contexts[cpu_id];

    // Count blocked NMI injection.
    hw_interlocked_increment64((INT64*)(&ipc->num_blocked_nmi_injections_to_guest));
}


// ***************************** IPC Initialize/ Finalize **************************************

BOOLEAN ipc_state_init(UINT16 number_of_host_processors)
{
    UINT32           i = 0,
                     ipc_cpu_context_size = 0,
                     ipc_msg_array_size = 0,
                     cpu_state_size = 0,
                     ipc_ack_array_size = 0,
                     ipc_data_size = 0,
                     message_queue_offset = 0;
    IPC_CPU_CONTEXT  *ipc = 0;

    VMM_LOG(mask_anonymous, level_trace,"IPC state init: #host CPUs = %d\r\n", number_of_host_processors);
    num_of_host_processors = number_of_host_processors;
    nmi_owner_guest_id = INVALID_GUEST_ID;

    ipc_cpu_context_size = number_of_host_processors * ALIGN_FORWARD(sizeof(IPC_CPU_CONTEXT), IPC_ALIGNMENT);

    ipc_msg_array_size = number_of_host_processors * ipc_get_message_array_list_size(number_of_host_processors);

    cpu_state_size = (UINT32) ALIGN_FORWARD(num_of_host_processors * sizeof(IPC_CPU_ACTIVITY_STATE), IPC_ALIGNMENT);

    ipc_ack_array_size = number_of_host_processors * sizeof(UINT32) * number_of_host_processors;
    ipc_ack_array_size = (UINT32) ALIGN_FORWARD(ipc_ack_array_size, IPC_ALIGNMENT);


    ipc_data_size = ipc_cpu_context_size + ipc_msg_array_size + cpu_state_size + ipc_ack_array_size;
    ipc_state_memory = (char *) vmm_memory_alloc(ipc_data_size);

    if(ipc_state_memory == NULL)
    {
        return FALSE;
    }

    vmm_memset(ipc_state_memory, 0, ipc_data_size);

    ipc_cpu_contexts = (IPC_CPU_CONTEXT *) ipc_state_memory;

    for (i = 0; i < number_of_host_processors; i++)
    {
        ipc = &ipc_cpu_contexts[i];

        message_queue_offset = ipc_cpu_context_size + i * ipc_get_message_array_list_size(number_of_host_processors);

        ipc->message_queue = array_list_init(ipc_state_memory + message_queue_offset,
                                             ipc_get_message_array_list_size(number_of_host_processors), 
                                             sizeof(IPC_MESSAGE),
                                             ipc_get_max_pending_messages(number_of_host_processors), 
                                             IPC_ALIGNMENT
                                             );

        lock_initialize(&ipc->data_lock);
    }

    cpu_activity_state = (IPC_CPU_ACTIVITY_STATE *) (ipc_state_memory + ipc_cpu_context_size + ipc_msg_array_size);

    ipc_ack_array = (UINT32 *) ((char *) cpu_activity_state + cpu_state_size);

    lock_initialize(&send_lock);

    isr_register_handler((VMM_ISR_HANDLER) ipc_nmi_interrupt_handler, NMI_VECTOR);

	ipc_cli_register();

    return TRUE;
}


BOOLEAN ipc_guest_state_init(GUEST_ID guest_id)
{
    if (guest_is_nmi_owner(guest_handle(guest_id)))
    {
        nmi_owner_guest_id = guest_id;
    }

    return TRUE;
}
#ifdef INCLUDE_UNUSED_CODE
void ipc_finalize(void)
{
    VMM_ASSERT(ipc_state_memory);
    vmm_memory_free(ipc_state_memory);
}
#endif

void ipc_set_no_resend_flag(BOOLEAN  val)
{
    if (val)
    {
        hw_interlocked_increment(&debug_not_resend);
    }
    else
    {
        hw_interlocked_decrement(&debug_not_resend);
    }
}

void ipc_print_cpu_context(CPU_ID cpu_id, BOOLEAN use_lock)
{
    IPC_CPU_CONTEXT *ipc = &ipc_cpu_contexts[cpu_id];

    if (use_lock)
    {
        lock_acquire(&ipc->data_lock);

        VMM_LOG(mask_anonymous, level_trace,"IPC context on CPU %d:\r\n", cpu_id);
        VMM_LOG(mask_anonymous, level_trace,"    num_received_nmi_interrupts         = %d\r\n", ipc->num_received_nmi_interrupts);
        VMM_LOG(mask_anonymous, level_trace,"    num_processed_nmi_interrupts        = %d\r\n", ipc->num_processed_nmi_interrupts);
        VMM_LOG(mask_anonymous, level_trace,"    num_of_sent_ipc_nmi_interrupts      = %d\r\n", ipc->num_of_sent_ipc_nmi_interrupts);
        VMM_LOG(mask_anonymous, level_trace,"    num_of_processed_ipc_nmi_interrupts = %d\r\n", ipc->num_of_processed_ipc_nmi_interrupts);
        VMM_LOG(mask_anonymous, level_trace,"    num_of_sent_ipc_messages            = %d\r\n", ipc->num_of_sent_ipc_messages);
        VMM_LOG(mask_anonymous, level_trace,"    num_of_received_ipc_messages        = %d\r\n", ipc->num_of_received_ipc_messages);
        VMM_LOG(mask_anonymous, level_trace,"    num_start_messages                  = %d\r\n", ipc->num_start_messages);
        VMM_LOG(mask_anonymous, level_trace,"    num_stop_messages                   = %d\r\n", ipc->num_stop_messages);
        VMM_LOG(mask_anonymous, level_trace,"    num_blocked_nmi_injections_to_guest = %d\r\n", ipc->num_blocked_nmi_injections_to_guest);
        VMM_LOG(mask_anonymous, level_trace,"    Num of queued IPC messages          = %d\r\n", array_list_size(ipc->message_queue));

        lock_release(&ipc->data_lock);
    }
    else
    {
        VMM_LOG_NOLOCK("IPC context on CPU %d:\r\n", cpu_id);
        VMM_LOG_NOLOCK("    num_received_nmi_interrupts         = %d\r\n", ipc->num_received_nmi_interrupts);
        VMM_LOG_NOLOCK("    num_processed_nmi_interrupts        = %d\r\n", ipc->num_processed_nmi_interrupts);
        VMM_LOG_NOLOCK("    num_of_sent_ipc_nmi_interrupts      = %d\r\n", ipc->num_of_sent_ipc_nmi_interrupts);
        VMM_LOG_NOLOCK("    num_of_processed_ipc_nmi_interrupts = %d\r\n", ipc->num_of_processed_ipc_nmi_interrupts);
        VMM_LOG_NOLOCK("    num_of_sent_ipc_messages            = %d\r\n", ipc->num_of_sent_ipc_messages);
        VMM_LOG_NOLOCK("    num_of_received_ipc_messages        = %d\r\n", ipc->num_of_received_ipc_messages);
        VMM_LOG_NOLOCK("    num_start_messages                  = %d\r\n", ipc->num_start_messages);
        VMM_LOG_NOLOCK("    num_stop_messages                   = %d\r\n", ipc->num_stop_messages);
        VMM_LOG_NOLOCK("    num_blocked_nmi_injections_to_guest = %d\r\n", ipc->num_blocked_nmi_injections_to_guest);
        VMM_LOG_NOLOCK("    Num of queued IPC messages          = %d\r\n", array_list_size(ipc->message_queue));
   }
}

#ifdef CLI_INCLUDE
static int cli_ipc_print(unsigned argc, char *argv[])
{
    CPU_ID cpu_id;

    if (argc != 2)
        return -1;

    cpu_id = (CPU_ID) CLI_ATOL(argv[1]);

	if (cpu_id < 0 || cpu_id >= num_of_host_processors)
	{
		CLI_PRINT("CpuId must be in [0..%d] range\n", (int) num_of_host_processors - 1);
		return -1;
	}

    ipc_print_cpu_context(cpu_id, FALSE);

    return 0;
}

VMM_DEBUG_CODE(
static int cli_ipc_resend(unsigned argc UNUSED, char *argv[] UNUSED)
{
    BOOLEAN  no_resend;

	if (!CLI_STRNCMP(argv[1], "start", sizeof("start")))
		no_resend = FALSE;
	else if (!CLI_STRNCMP(argv[1], "stop", sizeof("stop")))
		no_resend = TRUE;
	else if (!CLI_STRNCMP(argv[1], "state", sizeof("state")))
	{
		CLI_PRINT("IPC resend disable state counter = %d\n", debug_not_resend);
		CLI_PRINT("IPC resend is %s\n", (debug_not_resend == 0) ? "ENABLED" : "DISABLED");
        return 0;
	}
	else
	{
		CLI_PRINT("Wrong command argument\n");
		return -1;
	}

    ipc_set_no_resend_flag(no_resend);
	CLI_PRINT("IPC resend disable state counter = %d\n", debug_not_resend);
	CLI_PRINT("IPC resend is %s\n", (debug_not_resend == 0) ? "ENABLED" : "DISABLED");

    return 0;
}
)


static void ipc_cli_register(void)
{
    VMM_DEBUG_CODE(
	CLI_AddCommand(cli_ipc_print, "ipc print",
				  "Print internal IPC state for given CPU.", "<cpu id>", CLI_ACCESS_LEVEL_SYSTEM)
	);

    VMM_DEBUG_CODE(
	CLI_AddCommand(cli_ipc_resend, "ipc resend",
				  "Stop/Start resend IPC signal.", "stop | start | state", CLI_ACCESS_LEVEL_SYSTEM)
	);
}
#else

static void ipc_cli_register(void) {}

#endif

