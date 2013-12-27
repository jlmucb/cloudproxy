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

/*++
Module Name:

  event_mgr

Abstract:

  Event delivery mechanism
  Based on the 'Observer' pattern

--*/

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(EVENT_MGR_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(EVENT_MGR_C, __condition)
#include "vmm_objects.h"
#include "guest_cpu.h"
#include "lock.h"
#include "event_mgr.h"
#include "common_libc.h"
#include "vmm_dbg.h"
#include "heap.h"
#include "hash64_api.h"
#include "memory_allocator.h"
#include "guest.h"
#include "list.h"

#define OBSERVERS_LIMIT         5
#define NO_EVENT_SPECIFIC_LIMIT (UINT32)-1



typedef struct _EVENT_ENTRY
{
    VMM_READ_WRITE_LOCK     lock;
    event_callback          call[OBSERVERS_LIMIT];
} EVENT_ENTRY, *PEVENT_ENTRY;

typedef struct  _CPU_EVENTS
{
    EVENT_ENTRY event[EVENTS_COUNT];
} CPU_EVENTS, *PCPU_EVENTS;

typedef struct _GUEST_EVENTS
{
    EVENT_ENTRY     event[EVENTS_COUNT];
    LIST_ELEMENT    link;
    GUEST_ID        guest_id;
    UINT8           pad[6];
} GUEST_EVENTS;

typedef struct _EVENT_MANAGER
{
    HASH64_HANDLE   gcpu_events;
    LIST_ELEMENT    guest_events;
    EVENT_ENTRY     general_event[EVENTS_COUNT]; // events not related to particular gcpu, e.g. guest create
} EVENT_MANAGER;

UINT32      host_physical_cpus;
EVENT_MANAGER event_mgr;

/*
 *  EVENT_CHARACTERISTICS:
 *
 *  Specify event specific characteristics, currently: name and observers limits.
 *  This list should be IDENTICAL(!) to UVMM_EVENT enumration.
 */
EVENT_CHARACTERISTICS   events_characteristics[] =
{
//  { Event observers Limit , observ.registered, "         Event Name            "},
    // emulator
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_EMULATOR_BEFORE_MEM_WRITE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_EMULATOR_AFTER_MEM_WRITE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_EMULATOR_AS_GUEST_ENTER"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_EMULATOR_AS_GUEST_LEAVE"},

    // guest cpu CR writes
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_AFTER_GUEST_CR0_WRITE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_AFTER_GUEST_CR3_WRITE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_AFTER_GUEST_CR4_WRITE"},

    // guest cpu invalidate page
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_INVALIDATE_PAGE"},
    {1,                       EVENT_GCPU_SCOPE, (CHAR8 *)"EVENT_GCPU_PAGE_FAULT"},

    // guest cpu msr writes
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_AFTER_EFER_MSR_WRITE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_AFTER_PAT_MSR_WRITE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_AFTER_MTRR_MSR_WRITE"},

    // guest activity state
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_ACTIVITY_STATE_CHANGE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_ENTERING_S3"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_RETRUNED_FROM_S3"},

    // EPT events
    {1,                       EVENT_GCPU_SCOPE, (CHAR8 *)"EVENT_GCPU_EPT_MISCONFIGURATION"},
    {1,                       EVENT_GCPU_SCOPE, (CHAR8 *)"EVENT_GCPU_EPT_VIOLATION"},

    // MTF events
    {1,                       EVENT_GCPU_SCOPE, (CHAR8 *)"EVENT_GCPU_MTF"},

    // GPM modification
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_BEGIN_GPM_MODIFICATION_BEFORE_CPUS_STOPPED"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_BEGIN_GPM_MODIFICATION_AFTER_CPUS_STOPPED"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_END_GPM_MODIFICATION_BEFORE_CPUS_RESUMED"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_END_GPM_MODIFICATION_AFTER_CPUS_RESUMED"},

    // guest memory modification
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_BEGIN_GUEST_MEMORY_MODIFICATION"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_END_GUEST_MEMORY_MODIFICATION"},


    // guest lifecycle
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GUEST_CREATE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GUEST_DESTROY"},

    // gcpu lifecycle
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_ADD"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GCPU_REMOVE"},
    {NO_EVENT_SPECIFIC_LIMIT, EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GUEST_LAUNCH"},

    {1,                       EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GUEST_CPU_BREAKPOINT"},
    {1,                       EVENT_ALL_SCOPE, (CHAR8 *)"EVENT_GUEST_CPU_SINGLE_STEP"},
};


static
BOOLEAN event_manager_add_gcpu(
    GUEST_CPU_HANDLE    gcpu,
    void                *pv
    );
static
BOOLEAN event_register_internal(
    PEVENT_ENTRY    p_event,
    UVMM_EVENT      e,      //  in: event
    event_callback  call    //  in: callback to register on event e
    );
static
BOOLEAN event_unregister_internal(
    PEVENT_ENTRY    p_event,
    UVMM_EVENT      e,      //  in: event
    event_callback  call    //  in: callback to register on event e
    );
static
BOOLEAN event_raise_internal(
    PEVENT_ENTRY        p_event,
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void *              p       // in:  pointer to event specific structure
    );
static
BOOLEAN event_global_raise(
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void *              p       // in:  pointer to event specific structure
    );
static
BOOLEAN event_guest_raise(
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void               *p       // in:  pointer to event specific structure
    );
static
BOOLEAN event_gcpu_raise(
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void               *p       // in:  pointer to event specific structure
    );


/*---------------------------------- Code ------------------------------------*/

static
EVENT_ENTRY * get_gcpu_observers(UVMM_EVENT e, GUEST_CPU_HANDLE gcpu)
{
    const VIRTUAL_CPU_ID*   p_vcpu;
    PCPU_EVENTS             p_cpu_events = NULL;
    EVENT_ENTRY             *p_event = NULL;
    BOOLEAN                 res;

    p_vcpu = guest_vcpu(gcpu);
    VMM_ASSERT(p_vcpu);
    res = hash64_lookup(event_mgr.gcpu_events,
                        (UINT64) (p_vcpu->guest_id << (8 * sizeof(GUEST_ID)) | p_vcpu->guest_cpu_id),
                        (UINT64 *) &p_cpu_events);

    if(p_cpu_events != NULL)
    {
        p_event = &(p_cpu_events->event[e]);
    }
    return p_event;
}

static
EVENT_ENTRY * get_guest_observers(UVMM_EVENT e, GUEST_HANDLE guest)
{
    EVENT_ENTRY     *p_event = NULL;
    GUEST_ID        guest_id = guest_get_id(guest);
    LIST_ELEMENT    *iter = NULL;

    LIST_FOR_EACH(&event_mgr.guest_events, iter)
    {
        GUEST_EVENTS *p_guest_events;
        p_guest_events = LIST_ENTRY(iter, GUEST_EVENTS, link);
        if(p_guest_events->guest_id == guest_id)
        {
            p_event = &p_guest_events->event[e];
            break;
        }
    }
    return p_event;
}

static
EVENT_ENTRY * get_global_observers(UVMM_EVENT e)
{
    return &(event_mgr.general_event[e]);
}

static
UINT32  event_observers_limit (UVMM_EVENT e)
{
    UINT32  observers_limits = 0;

    VMM_ASSERT(e <= ARRAY_SIZE(events_characteristics));

    /*
     *  See if event has specific observers limits. (If none, we'll use the array
     *  boundry limits).
     */
    if (events_characteristics[e].specific_observers_limits == NO_EVENT_SPECIFIC_LIMIT)
    {
        observers_limits = OBSERVERS_LIMIT;
    }
    else
    {
        observers_limits = (UINT32)events_characteristics[e].specific_observers_limits;
        VMM_ASSERT(observers_limits <= OBSERVERS_LIMIT);
    }
    VMM_ASSERT(observers_limits > 0);

    return observers_limits;
}


UINT32 event_manager_initialize(UINT32 num_of_host_cpus)
{
    PEVENT_ENTRY    general_event;
    int i;
    GUEST_HANDLE guest = NULL;
    GUEST_ID guest_id = INVALID_GUEST_ID;
    GUEST_ECONTEXT context;

    /*
     *  Assert that all events are registed both in events_characteristics
     *  and in the events enumeration UVMM_EVENT
     */
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(ARRAY_SIZE(events_characteristics) == EVENTS_COUNT);

    host_physical_cpus = num_of_host_cpus;

    vmm_memset( &event_mgr, 0, sizeof( event_mgr ));

    event_mgr.gcpu_events = hash64_create_default_hash(host_physical_cpus * host_physical_cpus);

    for(i = 0; i < EVENTS_COUNT; i++)
    {
        general_event = &(event_mgr.general_event[i]);
        lock_initialize_read_write_lock(&(general_event->lock));
    }

    list_init(&event_mgr.guest_events);

    for(guest = guest_first(&context); guest != NULL; guest = guest_next(&context))
    {
        guest_id = guest_get_id(guest);
        event_manager_guest_initialize(guest_id);
    }

    event_global_register(EVENT_GCPU_ADD, event_manager_add_gcpu);

    return 0;
}

UINT32 event_manager_guest_initialize(GUEST_ID guest_id)
{
    GUEST_CPU_HANDLE gcpu;
    GUEST_GCPU_ECONTEXT gcpu_context;
    GUEST_HANDLE guest = guest_handle(guest_id);
    GUEST_EVENTS *p_new_guest_events;
    PEVENT_ENTRY event;
    int i;

    p_new_guest_events = vmm_malloc(sizeof(*p_new_guest_events));
    VMM_ASSERT(p_new_guest_events);
    vmm_memset(p_new_guest_events, 0, sizeof(*p_new_guest_events));

    // init lock for each event
    for(i = 0; i < EVENTS_COUNT; i++)
    {
        event = &(p_new_guest_events->event[i]);
        lock_initialize_read_write_lock(&(event->lock));
    }

    p_new_guest_events->guest_id = guest_id;

    /* for each guest/cpu we keep the event (callbacks) array */
    for( gcpu = guest_gcpu_first(guest, &gcpu_context); gcpu; gcpu = guest_gcpu_next(&gcpu_context))
    {
        event_manager_gcpu_initialize(gcpu);
    }

    list_add(&event_mgr.guest_events, &p_new_guest_events->link);

    return 0;
}

#pragma warning( push )
#pragma warning (disable : 4100) // disable non-referenced formal parameters

static
BOOLEAN event_manager_add_gcpu (GUEST_CPU_HANDLE gcpu,
	                            void*            pv UNUSED)
{
    event_manager_gcpu_initialize(gcpu);
    return TRUE;
}

#pragma warning( pop )

UINT32 event_manager_gcpu_initialize(GUEST_CPU_HANDLE gcpu)
{
    const VIRTUAL_CPU_ID* p_vcpu = NULL;
    PCPU_EVENTS gcpu_events = NULL;
    PEVENT_ENTRY event = NULL;
    int i;

    p_vcpu = guest_vcpu( gcpu );
    VMM_ASSERT(p_vcpu);
    gcpu_events = (CPU_EVENTS *) vmm_malloc(sizeof(CPU_EVENTS));
    VMM_ASSERT(gcpu_events);

    VMM_LOG(mask_anonymous, level_trace,"event mgr add gcpu guest id=%d cpu id=%d with key %p\n", p_vcpu->guest_id, p_vcpu->guest_cpu_id, (UINT64) (p_vcpu->guest_id << (8 * sizeof(GUEST_ID)) | p_vcpu->guest_cpu_id));
    hash64_insert(event_mgr.gcpu_events,
                  (UINT64) (p_vcpu->guest_id << (8 * sizeof(GUEST_ID)) | p_vcpu->guest_cpu_id),
                  (UINT64) gcpu_events);

    // init lock for each event
    for(i = 0; i < EVENTS_COUNT; i++)
    {
        event = &(gcpu_events->event[i]);
        lock_initialize_read_write_lock(&(event->lock));
    }

    return 0;
}
#ifdef INCLUDE_UNUSED_CODE

void event_cleanup_event_manger(void)
{
    return;
}
#endif

BOOLEAN event_register_internal(
    PEVENT_ENTRY    p_event,
    UVMM_EVENT      e,      //  in: event
    event_callback  call    //  in: callback to register on event e
    )
{
    UINT32  i = 0;
    UINT32  observers_limits;
    BOOLEAN registered = FALSE;

    observers_limits = event_observers_limit(e);

    lock_acquire_writelock(&p_event->lock);

    /*
     *  Find free observer slot
     */
    while (i < observers_limits && p_event->call[i])
        ++i;

    if (i < observers_limits)
    {
        p_event->call[i] = call;
        registered = TRUE;
    }
    else
    {
        /*
         *  Exceeding allowed observers count
         */
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_DEADLOOP();
    }

    lock_release_writelock(&p_event->lock);
    return registered;
}


BOOLEAN event_global_register(
    UVMM_EVENT          e,      //  in: event
    event_callback      call    //  in: callback to register on event e
    )
{
    PEVENT_ENTRY    list;

    if (call == 0) return FALSE;
    if (e >= EVENTS_COUNT) return FALSE;
    if (0 == (events_characteristics[e].scope & EVENT_GLOBAL_SCOPE)) return FALSE;
    list = get_global_observers(e);
    return event_register_internal(list, e, call);

}
#ifdef ENABLE_VTLB
BOOLEAN event_guest_register(
    UVMM_EVENT          e,      //  in: event
    GUEST_HANDLE        guest,  // in:  guest handle
    event_callback      call    //  in: callback to register on event e
    )
{
    PEVENT_ENTRY    list;
    BOOLEAN         registered = FALSE;

    if (call == 0) return FALSE;
    if (e >= EVENTS_COUNT) return FALSE;
    if (0 == (events_characteristics[e].scope & EVENT_GUEST_SCOPE)) return FALSE;

    list = get_guest_observers(e, guest);
    if (NULL != list)
    {
        registered = event_register_internal(list, e, call);
    }

    return registered;
}
#endif

BOOLEAN event_gcpu_register(
    UVMM_EVENT          e,      //  in: event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    event_callback      call    //  in: callback to register on event e
    )
{
    PEVENT_ENTRY    list;
    BOOLEAN         registered = FALSE;

    if (call == 0) return FALSE;
    if (e >= EVENTS_COUNT) return FALSE;
    if (0 == (events_characteristics[e].scope & EVENT_GCPU_SCOPE)) return FALSE;

    list = get_gcpu_observers(e, gcpu);
    if (NULL != list)
    {
        registered = event_register_internal(list, e, call);
    }
    return registered;
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN event_unregister_internal(
    PEVENT_ENTRY    p_event,
    UVMM_EVENT      e,      //  in: event
    event_callback  call    //  in: callback to register on event e
    )
{
    UINT32          i= 0;
    UINT32          observers_limits;
    BOOLEAN         unregistered = FALSE;

    observers_limits = event_observers_limit(e);

    lock_acquire_writelock(&p_event->lock);

    while (i < observers_limits && p_event->call[i])
    {
        if (p_event->call[i] == call)
        {
            unregistered = TRUE;

            /*
             *  Match. Delete entry (promote the following entries, one entry forward)
             */
            while ((i+1) < observers_limits && p_event->call[i+1])
            {
                p_event->call[i] = p_event->call[i+1];
                ++i;
            }
            p_event->call[i] = 0;
            break;
        }

        ++i;
    } // while (i < observers_limits && list->call[i])

    lock_release_writelock(&p_event->lock);

    return unregistered;
}

BOOLEAN event_global_unregister(
    UVMM_EVENT          e,      //  in: event
    event_callback      call    //  in: callback to unregister from event e
    )
{
    PEVENT_ENTRY    list;
    BOOLEAN         unregistered = FALSE;

    if (call == 0) return FALSE;
    if (e >= EVENTS_COUNT) return FALSE;

    list = get_global_observers(e);
    if (NULL != list)
    {
        unregistered = event_unregister_internal(list, e, call);
    }
    return unregistered;
}

BOOLEAN event_guest_unregister(
    UVMM_EVENT          e,      //  in: event
    GUEST_HANDLE        guest,  // in:  guest handle
    event_callback      call    //  in: callback to unregister from event e
    )
{
    PEVENT_ENTRY    list;
    BOOLEAN         unregistered = FALSE;

    if (call == 0) return FALSE;
    if (e >= EVENTS_COUNT) return FALSE;

    list = get_guest_observers(e, guest);
    if (NULL != list)
    {
        unregistered = event_unregister_internal(list, e, call);
    }
    return unregistered;
}
#endif

#ifdef ENABLE_VTLB
BOOLEAN event_gcpu_unregister(
    UVMM_EVENT          e,      //  in: event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    event_callback      call    //  in: callback to unregister from event e
    )
{
    PEVENT_ENTRY    list;
    BOOLEAN         unregistered = FALSE;

    if (call == 0) return FALSE;
    if (e >= EVENTS_COUNT) return FALSE;

    list = get_gcpu_observers(e, gcpu);
    if (NULL != list)
    {
        unregistered = event_unregister_internal(list, e, call);
    }
    return unregistered;
}
#endif

BOOLEAN event_raise_internal(
    PEVENT_ENTRY        p_event,
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void *              p       // in:  pointer to event specific structure
    )
{
    UINT32          i= 0;
    UINT32          observers_limits;
    event_callback  call[OBSERVERS_LIMIT];
    BOOLEAN         event_is_handled = FALSE;

    observers_limits = event_observers_limit(e);

    lock_acquire_readlock(&p_event->lock);
    VMM_ASSERT(observers_limits <= OBSERVERS_LIMIT);
    vmm_memcpy(call, p_event->call, sizeof(call));
    lock_release_readlock(&p_event->lock);

    while (i < observers_limits && call[i])
    {
        call[i](gcpu, p);
        event_is_handled = TRUE;
        ++i;
    }

    return event_is_handled;
}


BOOLEAN event_global_raise(
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void *              p       // in:  pointer to event specific structure
    )
{
    PEVENT_ENTRY    list;
    list = get_global_observers(e);
    return event_raise_internal(list, e, gcpu, p);
}


BOOLEAN event_guest_raise(
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void               *p       // in:  pointer to event specific structure
    )
{
    GUEST_HANDLE    guest;
    PEVENT_ENTRY    list;
    BOOLEAN         event_handled = FALSE;

    VMM_ASSERT(gcpu);

    guest = gcpu_guest_handle(gcpu);
    VMM_ASSERT(guest);
    list = get_guest_observers(e, guest);
    if (NULL != list)
    {
        event_handled = event_raise_internal(list, e, gcpu, p);
    }
    return event_handled;
}


BOOLEAN event_gcpu_raise(
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void               *p       // in:  pointer to event specific structure
    )
{
    PEVENT_ENTRY    list;
    BOOLEAN         event_handled = FALSE;

    list = get_gcpu_observers(e, gcpu);
    if (NULL != list)
    {
        event_handled = event_raise_internal(list, e, gcpu, p);
    }

    return event_handled;
}


BOOLEAN event_raise(
    UVMM_EVENT          e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void                *p      // in:  pointer to event specific structure
    )
{
    BOOLEAN raised = FALSE;

    VMM_ASSERT(e < EVENTS_COUNT);

    if (e < EVENTS_COUNT)
    {
        if (NULL != gcpu)                                   // try to raise GCPU-scope event
            raised = event_gcpu_raise(e, gcpu, p);

        if (NULL != gcpu)                                   // try to raise GUEST-scope event
            raised = raised || event_guest_raise(e, gcpu, p);

        raised = raised || event_global_raise(e, gcpu, p);  // try to raise global-scope event
    }
    return raised;
}

#ifdef ENABLE_VTLB
BOOLEAN event_is_registered(
        UVMM_EVENT          e,      // in:  event
        GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
        event_callback      call    // in:  callback to check
        )
{
    PEVENT_ENTRY    list;
    UINT32          i = 0;
    UINT32          observers_limits;
    BOOLEAN         res = FALSE;

    if (call == 0) return FALSE;
    if (e >= EVENTS_COUNT) return FALSE;

    list = get_gcpu_observers(e, gcpu);

    if (list == NULL)
        return FALSE;

    observers_limits = event_observers_limit(e);

    lock_acquire_readlock(&list->lock);

    /*
     *  Find free observer slot
     */
    while (i < observers_limits && list->call[i])
    {
        if (list->call[i] == call)
        {
            res = TRUE;
            break;
        }
        ++i;
    }

    lock_release_readlock(&list->lock);
    return res;
}
#endif

