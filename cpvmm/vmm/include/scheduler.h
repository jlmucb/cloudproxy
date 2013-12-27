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

#ifndef _SCHEDULER_H_
#define _SCHEDULER_H_

#include "vmm_defs.h"
#include "hw_includes.h"
#include "guest_cpu.h"
#include "libc.h"
#include "vmm_objects.h"

//------------------------------------------------------------------------------
//
// Get current
//
// Return NULL if no guest cpu is running on current host cpu
//------------------------------------------------------------------------------
GUEST_CPU_HANDLE scheduler_current_gcpu( void );

//------------------------------------------------------------------------------
//
// Get Host CPU Id for which given Guest CPU is assigned
//
//------------------------------------------------------------------------------
UINT16 scheduler_get_host_cpu_id( GUEST_CPU_HANDLE gcpu );

//------------------------------------------------------------------------------
//
// Enumerate Guest CPUs assigned to the same Host CPU
//
//  Return NULL to indicate end of enumeration
//------------------------------------------------------------------------------

// user allocated enumeration context
typedef struct _SCHEDULER_VCPU_OBJECT*  SCHEDULER_GCPU_ITERATOR;

GUEST_CPU_HANDLE
scheduler_same_host_cpu_gcpu_first( SCHEDULER_GCPU_ITERATOR* ctx,
                                    CPU_ID                   host_cpu_id );

GUEST_CPU_HANDLE
scheduler_same_host_cpu_gcpu_next(  SCHEDULER_GCPU_ITERATOR* ctx );

// -------------------------- schedule -----------------------------------------

//------------------------------------------------------------------------------
//
// Determine initial gCPU to run on the current host CPU
// Makes selected gCPU "current" on the current host CPU and returns it.
//
// If no ready vcpus on the current host CPU, returns NULL
//------------------------------------------------------------------------------
GUEST_CPU_HANDLE scheduler_select_initial_gcpu( void );

//------------------------------------------------------------------------------
//
// Determine next gCPU to run on the current host CPU
// Makes selected gCPU "current" on the current host CPU and returns it.
//
// If no ready vcpus on the current host CPU, returns NULL
// Note:
//    1. scheduler_select_initial_gcpu() should be called before on this host
//       CPU
//------------------------------------------------------------------------------
GUEST_CPU_HANDLE scheduler_select_next_gcpu( void );

GUEST_CPU_HANDLE scheduler_schedule_gcpu( GUEST_CPU_HANDLE gcpu );

// ---------------------- initialization ---------------------------------------

// init scheduler.
void scheduler_init( UINT16 number_of_host_cpus );

// register guest cpu
void scheduler_register_gcpu(
                             GUEST_CPU_HANDLE gcpu_handle,
                             CPU_ID   host_cpu_id,
                             BOOLEAN schedule_immediately );


GUEST_CPU_HANDLE scheduler_get_current_gcpu_for_guest( GUEST_ID guest_id );

#ifdef INCLUDE_UNUSED_CODE
GUEST_CPU_HANDLE scheduler_get_current_gcpu_on_host_cpu( CPU_ID host_cpu_id );
#endif

#endif // _SCHEDULER_H_

