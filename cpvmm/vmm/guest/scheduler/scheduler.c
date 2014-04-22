/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(SCHEDULER_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(SCHEDULER_C, __condition)
#include "scheduler.h"
#include "hw_utils.h"
#include "heap.h"
#include "guest.h"
#include "vmm_dbg.h"
#include "list.h"
#include "memory_allocator.h"
#include "lock.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


// Guest Scheduler

// Principles:
// 1. Scheduler works independently on each host CPU
// 2. Scheduler on different host CPUs may communicate to make common decision



// scheduler vCPU object
typedef struct _SCHEDULER_VCPU_OBJECT {
    GUEST_CPU_HANDLE               gcpu;

    CPU_ID                         host_cpu;
    UINT16                         flags;

    UINT32                         reserved;
    struct _SCHEDULER_VCPU_OBJECT* next_same_host_cpu;
    struct _SCHEDULER_VCPU_OBJECT* next_all_cpus;
} SCHEDULER_VCPU_OBJECT;

// SCHEDULER_VCPU_OBJECT flags
typedef enum _VCPU_FLAGS_ENUM {
    VCPU_ALLOCATED_FLAG = 0,    // vcpu is allocated for some guest
    VCPU_READY_FLAG             // vcpu is ready for execution
} VCPU_FLAGS_ENUM;

#define SET_ALLOCATED_FLAG( obj )    BIT_SET( (obj)->flags, VCPU_ALLOCATED_FLAG)
#define CLR_ALLOCATED_FLAG( obj )    BIT_CLR( (obj)->flags, VCPU_ALLOCATED_FLAG)
#define GET_ALLOCATED_FLAG( obj )    BIT_GET( (obj)->flags, VCPU_ALLOCATED_FLAG)

#define SET_READY_FLAG( obj )    BIT_SET( (obj)->flags, VCPU_READY_FLAG)
#define CLR_READY_FLAG( obj )    BIT_CLR( (obj)->flags, VCPU_READY_FLAG)
#define GET_READY_FLAG( obj )    BIT_GET( (obj)->flags, VCPU_READY_FLAG)

typedef struct _SCHEDULER_CPU_STATE {
    SCHEDULER_VCPU_OBJECT*  vcpu_obj_list;
    SCHEDULER_VCPU_OBJECT*  current_vcpu_obj;
} SCHEDULER_CPU_STATE;


SCHEDULER_VCPU_OBJECT* scheduler_get_current_vcpu_for_guest( GUEST_ID guest_id );

static UINT16 g_host_cpus_count         = 0;
static UINT16 g_registered_vcpus_count  = 0;

// allocated space for internal objects
static SCHEDULER_VCPU_OBJECT* g_registered_vcpus = NULL;

// scheduler state per host CPU
static SCHEDULER_CPU_STATE* g_scheduler_state = 0;

// lock to support guest addition while performing scheduling operations
static VMM_READ_WRITE_LOCK g_registration_lock[1];


static SCHEDULER_VCPU_OBJECT* gcpu_2_vcpu_obj( GUEST_CPU_HANDLE gcpu )
{
    SCHEDULER_VCPU_OBJECT *vcpu_obj = NULL;

    for(vcpu_obj = g_registered_vcpus; vcpu_obj != NULL; vcpu_obj = vcpu_obj->next_all_cpus) {
        if(vcpu_obj->gcpu == gcpu) {
            return vcpu_obj;
        }
    }
    return NULL;
}

// list funcs
void add_to_per_cpu_list( SCHEDULER_VCPU_OBJECT* vcpu_obj )
{
    CPU_ID host_cpu = vcpu_obj->host_cpu;
    SCHEDULER_CPU_STATE* state = &(g_scheduler_state[host_cpu]);

    vcpu_obj->next_same_host_cpu = state->vcpu_obj_list;
    state->vcpu_obj_list = vcpu_obj;
}


// init
void scheduler_init( UINT16 number_of_host_cpus )
{
    UINT32 memory_for_state     = 0;

#ifdef JLMDEBUG
    bprint("g_registration_lock = %p\n", g_registration_lock);
#endif
    vmm_memset(g_registration_lock, 0, sizeof(g_registration_lock));
    g_host_cpus_count = number_of_host_cpus;
    // BEFORE_VMLAUNCH. PARANOID check.
    VMM_ASSERT( number_of_host_cpus != 0 );
    // count needed memory amount
    memory_for_state = sizeof(SCHEDULER_CPU_STATE) * g_host_cpus_count;
#ifdef JLMDEBUG
    bprint("Did vmm_memset, memory for state: %d\n", memory_for_state);
#endif
#if 0
    lock_initialize_read_write_lock(g_registration_lock);
#endif
    g_scheduler_state = (SCHEDULER_CPU_STATE*) vmm_malloc(memory_for_state);
    if(g_scheduler_state ==0) {
        bprint("Cant allocate scheduler state\n");
        LOOP_FOREVER
    }
    // BEFORE_VMLAUNCH. MALLOC should not fail.
    VMM_ASSERT( g_scheduler_state != 0 );
}

// register guest cpu
void scheduler_register_gcpu(GUEST_CPU_HANDLE gcpu_handle, CPU_ID   host_cpu_id,
                             BOOLEAN schedule_immediately )
{
    SCHEDULER_VCPU_OBJECT* vcpu_obj = NULL;

#ifdef JLMDEBUG
    bprint("scheduler_register_gcpu, about to alloc %d\n", 
           sizeof(SCHEDULER_VCPU_OBJECT));
#endif
    vcpu_obj = (SCHEDULER_VCPU_OBJECT*) vmm_malloc(sizeof(SCHEDULER_VCPU_OBJECT));
#ifdef JLMDEBUG
    bprint("done with vmm_alloc\n");
#endif
    VMM_ASSERT(vcpu_obj);
    interruptible_lock_acquire_writelock(g_registration_lock);
    vcpu_obj->next_all_cpus = g_registered_vcpus;
    g_registered_vcpus = vcpu_obj;
    hw_interlocked_increment((INT32*)&g_registered_vcpus_count);
    vcpu_obj->gcpu  = gcpu_handle;
    vcpu_obj->flags = 0;
    vcpu_obj->host_cpu = host_cpu_id;
    SET_ALLOCATED_FLAG( vcpu_obj );
    if (schedule_immediately) {
        SET_READY_FLAG( vcpu_obj );
    }
    // add to the per-host-cpu list
    add_to_per_cpu_list( vcpu_obj );
    lock_release_writelock(g_registration_lock);
}

// Get current GUEST_CPU_HANDLE
GUEST_CPU_HANDLE scheduler_current_gcpu( void )
{
    SCHEDULER_VCPU_OBJECT* vcpu_obj = 0;
    vcpu_obj = g_scheduler_state[hw_cpu_id()].current_vcpu_obj;
    VMM_ASSERT( vcpu_obj != NULL );
    return vcpu_obj == NULL ? NULL : vcpu_obj->gcpu;
}

// Get Host CPU Id for which given Guest CPU is assigned. Function assumes gcpu as valid input.
//Validate gcpu in caller.
UINT16 scheduler_get_host_cpu_id( GUEST_CPU_HANDLE gcpu )
{
    SCHEDULER_VCPU_OBJECT* vcpu_obj = NULL;

    interruptible_lock_acquire_readlock(g_registration_lock);
    vcpu_obj = gcpu_2_vcpu_obj(gcpu);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(vcpu_obj);
    lock_release_readlock(g_registration_lock);

    return vcpu_obj->host_cpu;
}

// iterator
GUEST_CPU_HANDLE
scheduler_same_host_cpu_gcpu_next( SCHEDULER_GCPU_ITERATOR* ctx )
{
    SCHEDULER_VCPU_OBJECT* vcpu_obj;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( ctx );
    vcpu_obj = *ctx;

    if (vcpu_obj) {
        vcpu_obj = vcpu_obj->next_same_host_cpu;
        *ctx = vcpu_obj;
    }
    return (vcpu_obj ? vcpu_obj->gcpu : NULL);
}

GUEST_CPU_HANDLE scheduler_same_host_cpu_gcpu_first( SCHEDULER_GCPU_ITERATOR* ctx,
                                    CPU_ID host_cpu_id)
{
    SCHEDULER_VCPU_OBJECT* vcpu_obj;

    // BEFORE_VMLAUNCH. Returning NULL instead of ASSERT.
    if(!(host_cpu_id < g_host_cpus_count))
        return NULL;
    // BEFORE_VMLAUNCH. Returning NULL instead of ASSERT.
    if(!ctx)
        return NULL;

    VMM_ASSERT(g_scheduler_state);
    vcpu_obj = g_scheduler_state[ host_cpu_id ].vcpu_obj_list;
    *ctx = vcpu_obj;

    return (vcpu_obj ? vcpu_obj->gcpu : NULL);
}


// scheduler
GUEST_CPU_HANDLE scheduler_select_initial_gcpu( void )
{
    CPU_ID                 host_cpu = hw_cpu_id();
    SCHEDULER_CPU_STATE*   state = &(g_scheduler_state[host_cpu]);
    SCHEDULER_VCPU_OBJECT* next_vcpu = state->vcpu_obj_list;

    // very simple implementation
    // assume only one guest per host CPU
    if (! (next_vcpu && GET_READY_FLAG(next_vcpu))) {
        return NULL;
    }
    state->current_vcpu_obj = next_vcpu;
    gcpu_swap_in(state->current_vcpu_obj->gcpu);  // load full state of new guest from memory
    return next_vcpu->gcpu;
}

GUEST_CPU_HANDLE scheduler_select_next_gcpu( void )
{
    CPU_ID                 host_cpu = hw_cpu_id();
    SCHEDULER_CPU_STATE*   state = &(g_scheduler_state[host_cpu]);
    SCHEDULER_VCPU_OBJECT* next_vcpu = NULL;

    if(state->current_vcpu_obj != NULL) {
        next_vcpu = state->current_vcpu_obj->next_same_host_cpu;
    }
    if(next_vcpu == NULL) {
        next_vcpu = state->vcpu_obj_list;
    }

    // very simple implementation
    // assume only one guest per host CPU
    if (! (next_vcpu && GET_READY_FLAG(next_vcpu))) {
        return NULL;
    }

    if (state->current_vcpu_obj != next_vcpu) {
        if (state->current_vcpu_obj != NULL) {
            gcpu_swap_out(state->current_vcpu_obj->gcpu);   // save full state of prev. guest in memory
        }
        state->current_vcpu_obj = next_vcpu;
        gcpu_swap_in(state->current_vcpu_obj->gcpu);        // load full state of new guest from memory
    }

    return next_vcpu->gcpu;
}

//Function assumes input parameter gcpu is valid. Validate in caller function.
GUEST_CPU_HANDLE scheduler_schedule_gcpu( GUEST_CPU_HANDLE gcpu )
{
    CPU_ID                 host_cpu = hw_cpu_id();
    SCHEDULER_CPU_STATE*   state = NULL;
    SCHEDULER_VCPU_OBJECT* next_vcpu = gcpu_2_vcpu_obj(gcpu);

    if (! (next_vcpu && GET_READY_FLAG(next_vcpu))) {
        return NULL;
    }

    state = &(g_scheduler_state[host_cpu]);

    if (state->current_vcpu_obj != next_vcpu) {
        if (state->current_vcpu_obj != NULL) {
            gcpu_swap_out(state->current_vcpu_obj->gcpu);   // save full state of prev. guest in memory
        }
        state->current_vcpu_obj = next_vcpu;
        gcpu_swap_in(state->current_vcpu_obj->gcpu);        // load full state of new guest from memory
    }
    return state->current_vcpu_obj->gcpu;
}

GUEST_CPU_HANDLE scheduler_get_current_gcpu_for_guest( GUEST_ID guest_id )
{
    SCHEDULER_VCPU_OBJECT* vcpu_obj;
    const VIRTUAL_CPU_ID* vcpuid=NULL;
    VMM_ASSERT(g_scheduler_state);
    for (vcpu_obj = g_scheduler_state[ hw_cpu_id() ].vcpu_obj_list;
         NULL != vcpu_obj;
         vcpu_obj = vcpu_obj->next_same_host_cpu) {
    	vcpuid=guest_vcpu(vcpu_obj->gcpu);
    	//paranoid check. If assertion fails, possible memory corruption.
    	VMM_ASSERT(vcpuid);
        if (vcpuid->guest_id == guest_id) {
            return vcpu_obj->gcpu; // found
        }
    }
    return NULL;
}

#ifdef INCLUDE_UNUSED_CODE
// Not MT-safe. Must be called when all CPUs are stopped.
GUEST_CPU_HANDLE scheduler_get_current_gcpu_on_host_cpu( CPU_ID host_cpu_id )
{
    if(g_scheduler_state[host_cpu_id].current_vcpu_obj == NULL) {
        return NULL;
    }
    return g_scheduler_state[host_cpu_id].current_vcpu_obj->gcpu;
}
#endif

