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

/*
 *  Event delivery mechanism
 *  Based on the 'Observer' pattern
 */

#pragma once
#include "vmm_startup.h"

#define EVENT_MGR_ERROR         (UINT32)-1

/*
 *	CALLBACK
 */
typedef BOOLEAN (*event_callback) (
    GUEST_CPU_HANDLE    gcpu,
    void                *pv
    );

/*
 *	EVENTS
 *
 *  This enumeration specify the supported UVMM events.
 *  Note that for every event there should be an entry in EVENT_CHARACTERISTICS
 *  characterizing the event in event_mgr.c.
 *
 *  failing to add entry in EVENT_CHARACTERISTICS triggers assertion at the
 *  event_initialize_event_manger entry point
 */
#ifndef UVMM_EVENT_INTERNAL
typedef enum {
    // emulator
    EVENT_EMULATOR_BEFORE_MEM_WRITE = 0,
    EVENT_EMULATOR_AFTER_MEM_WRITE,
    EVENT_EMULATOR_AS_GUEST_ENTER,
    EVENT_EMULATOR_AS_GUEST_LEAVE,

    // guest cpu CR writes
    EVENT_GCPU_AFTER_GUEST_CR0_WRITE,
    EVENT_GCPU_AFTER_GUEST_CR3_WRITE,
    EVENT_GCPU_AFTER_GUEST_CR4_WRITE,

    // guest cpu invalidate page
    EVENT_GCPU_INVALIDATE_PAGE,
    EVENT_GCPU_PAGE_FAULT,

    // guest cpu msr writes
    EVENT_GCPU_AFTER_EFER_MSR_WRITE,
    EVENT_GCPU_AFTER_PAT_MSR_WRITE,
    EVENT_GCPU_AFTER_MTRR_MSR_WRITE,

    // guest activity state
    EVENT_GCPU_ACTIVITY_STATE_CHANGE,
    EVENT_GCPU_ENTERING_S3,
    EVENT_GCPU_RETURNED_FROM_S3,

    // ept events
    EVENT_GCPU_EPT_MISCONFIGURATION,
    EVENT_GCPU_EPT_VIOLATION,

    // mtf events
    EVENT_GCPU_MTF,

    // GPM modification
    EVENT_BEGIN_GPM_MODIFICATION_BEFORE_CPUS_STOPPED,
    EVENT_BEGIN_GPM_MODIFICATION_AFTER_CPUS_STOPPED,
    EVENT_END_GPM_MODIFICATION_BEFORE_CPUS_RESUMED,
    EVENT_END_GPM_MODIFICATION_AFTER_CPUS_RESUMED,

    // guest memory modification
    EVENT_BEGIN_GUEST_MEMORY_MODIFICATION,
    EVENT_END_GUEST_MEMORY_MODIFICATION,

    // guest lifecycle
    EVENT_GUEST_CREATE,
    EVENT_GUEST_DESTROY,

    // gcpu lifecycle
    EVENT_GCPU_ADD,
    EVENT_GCPU_REMOVE,

    EVENT_GUEST_LAUNCH,

    EVENT_GUEST_CPU_BREAKPOINT,
    EVENT_GUEST_CPU_SINGLE_STEP,

	EVENTS_COUNT
} UVMM_EVENT_INTERNAL;
#endif

typedef enum {
    EVENT_GLOBAL_SCOPE = 1,
    EVENT_GUEST_SCOPE  = 2,
    EVENT_GCPU_SCOPE   = 4,
    EVENT_ALL_SCOPE    = (EVENT_GLOBAL_SCOPE | EVENT_GUEST_SCOPE  | EVENT_GCPU_SCOPE)
} EVENT_SCOPE;


typedef struct _EVENT_CHARACTERISTICS
{
    UINT32      specific_observers_limits;
    EVENT_SCOPE scope;
    CHAR8      *event_str;
} EVENT_CHARACTERISTICS, * PEVENT_CHARACTERISTICS;


/*
 *	Event Manager Interface
 */


UINT32 event_initialize_event_manger(const VMM_STARTUP_STRUCT* startup_struct);

UINT32 event_manager_initialize(UINT32 num_of_host_cpus);
UINT32 event_manager_guest_initialize(GUEST_ID guest_id);
UINT32 event_manager_gcpu_initialize(GUEST_CPU_HANDLE gcpu);

void event_cleanup_event_manger(void);

BOOLEAN event_global_register(
    UVMM_EVENT_INTERNAL e,      //  in: event
    event_callback      call    //  in: callback to register on event e
    );

BOOLEAN event_guest_register(
    UVMM_EVENT_INTERNAL e,      //  in: event
    GUEST_HANDLE        guest,  // in:  guest handle
    event_callback      call    //  in: callback to register on event e
    );

BOOLEAN event_gcpu_register(
    UVMM_EVENT_INTERNAL e,      //  in: event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    event_callback      call    //  in: callback to register on event e
    );


BOOLEAN event_global_unregister(
    UVMM_EVENT_INTERNAL e,      //  in: event
    event_callback      call    //  in: callback to unregister from event e
    );

BOOLEAN event_guest_unregister(
    UVMM_EVENT_INTERNAL e,      //  in: event
    GUEST_HANDLE        guest,  // in:  guest handle
    event_callback      call    //  in: callback to unregister from event e
    );

BOOLEAN event_gcpu_unregister(
    UVMM_EVENT_INTERNAL e,      //  in: event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    event_callback      call    //  in: callback to unregister from event e
    );

typedef enum {
    EVENT_NO_HANDLERS_REGISTERED,
    EVENT_HANDLED,
    EVENT_NOT_HANDLED,
} RAISE_EVENT_RETVAL;

// returns counter of executed observers
BOOLEAN event_raise(
    UVMM_EVENT_INTERNAL e,      // in:  event
    GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
    void                *p      // in:  pointer to event specific structure
    );

BOOLEAN event_is_registered(
        UVMM_EVENT_INTERNAL e,      // in:  event
        GUEST_CPU_HANDLE    gcpu,   // in:  guest cpu
        event_callback      call    // in:  callback to check
        );

