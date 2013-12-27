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

#ifndef _GUEST_H_
#define _GUEST_H_

#include "vmm_defs.h"
#include "list.h"
#include "vmm_objects.h"
#include "array_iterators.h"
#include "vmexit.h"
#include "vmexit_msr.h"
#include "vmm_startup.h"
#include "policy_manager.h"

//****************************************************************************
//
// Define guest-related global structures
//
//****************************************************************************

#define INVALID_GUEST_ID    ((GUEST_ID) -1)
#define ANONYMOUS_MAGIC_NUMBER  (UINT32)-1

///////////////////////////////////////////////////////////////////////////////
//
// guest descriptor
//
///////////////////////////////////////////////////////////////////////////////

//------------------------------------------------------------------------------
// initialization
//------------------------------------------------------------------------------
void guest_manager_init( UINT16 max_cpus_per_guest,
                         UINT16 host_cpu_count );

//------------------------------------------------------------------------------
// Get total number of guests
//------------------------------------------------------------------------------
UINT16 guest_count( void );

//------------------------------------------------------------------------------
// Get Guest by guest ID
//
// Return NULL if no such guest
//------------------------------------------------------------------------------
GUEST_HANDLE guest_handle( GUEST_ID guest_id );

//------------------------------------------------------------------------------
// Get Guest ID by guest handle
//------------------------------------------------------------------------------
GUEST_ID guest_get_id( GUEST_HANDLE guest );

//------------------------------------------------------------------------------
// Register new guest
//
// For primary guest physical_memory_size must be 0
//
// cpu_affinity - each 1 bit corresponds to host CPU_ID that should run GUEST_CPU
//                on behalf of this guest. Number of bits should correspond
//                to the number of registered guest CPUs for this guest
//                -1 means run on all available CPUs
//
// Return NULL on error
//------------------------------------------------------------------------------
GUEST_HANDLE guest_register( UINT32            magic_number,
                             UINT32            physical_memory_size,
                             UINT32            cpu_affinity,
                             const VMM_POLICY  *guest_policy);

//------------------------------------------------------------------------------
// Get guest magic number
//------------------------------------------------------------------------------
UINT32 guest_magic_number( const GUEST_HANDLE guest );

//------------------------------------------------------------------------------
// Get Guest by guest magic number
//
// Return NULL if no such guest
//------------------------------------------------------------------------------
GUEST_HANDLE guest_handle_by_magic_number( UINT32 magic_number );

#ifdef INCLUDE_UNUSED_CODE
//------------------------------------------------------------------------------
// Get guest physical memory size. For primary guest returns 0.
//------------------------------------------------------------------------------
UINT32 guest_physical_memory_size( const GUEST_HANDLE guest );

//------------------------------------------------------------------------------
// Get guest physical memory base. For primary guest returns 0.
//------------------------------------------------------------------------------
UINT64 guest_physical_memory_base( const GUEST_HANDLE guest );
void set_guest_physical_memory_base( const GUEST_HANDLE guest, UINT64 base );
#endif

//------------------------------------------------------------------------------
// Get guest cpu affinity.
//------------------------------------------------------------------------------
#ifdef ENABLE_MULTI_GUEST_SUPPORT
UINT32 guest_cpu_affinity( const GUEST_HANDLE guest );
#endif

#ifdef INCLUDE_UNUSED_CODE
void guest_set_cpu_affinity( const GUEST_HANDLE guest, UINT32 cpu_affinity );
#endif


//------------------------------------------------------------------------------
// Get guest POLICY
//------------------------------------------------------------------------------
const VMM_POLICY *guest_policy( const GUEST_HANDLE guest );


#ifdef INCLUDE_UNUSED_CODE
//------------------------------------------------------------------------------
// Set guest POLICY
//------------------------------------------------------------------------------
void guest_set_policy( const GUEST_HANDLE guest, const VMM_POLICY *new_policy);
#endif


//------------------------------------------------------------------------------
// Guest properties.
// Default for all properties - FALSE
//------------------------------------------------------------------------------
void    guest_set_primary(                  GUEST_HANDLE        guest );
BOOLEAN guest_is_primary(                   const GUEST_HANDLE  guest );
GUEST_ID guest_get_primary_guest_id(                void              );

void    guest_set_real_BIOS_access_enabled( GUEST_HANDLE        guest );
#ifdef INCLUDE_UNUSED_CODE
BOOLEAN guest_is_real_BIOS_access_enabled(  const GUEST_HANDLE  guest );
#endif

void    guest_set_nmi_owner(                GUEST_HANDLE        guest );
BOOLEAN guest_is_nmi_owner(                 const GUEST_HANDLE  guest );

void    guest_set_acpi_owner(               GUEST_HANDLE        guest );
#ifdef INCLUDE_UNUSED_CODE
BOOLEAN guest_is_acpi_owner(                const GUEST_HANDLE  guest );
#endif

void    guest_set_default_device_owner(     GUEST_HANDLE        guest );
#ifdef INCLUDE_UNUSED_CODE
BOOLEAN guest_is_default_device_owner(      const GUEST_HANDLE  guest );
#endif
GUEST_ID guest_get_default_device_owner_guest_id(      void           );

//------------------------------------------------------------------------------
// Get guest physical memory descriptor
//------------------------------------------------------------------------------
GPM_HANDLE guest_get_startup_gpm(GUEST_HANDLE guest);
GPM_HANDLE gcpu_get_current_gpm(GUEST_HANDLE guest);
void gcpu_set_current_gpm(GUEST_CPU_HANDLE gcpu, GPM_HANDLE gpm);

//------------------------------------------------------------------------------
// Guest executable image
//
// Should not be called for primary guest
//------------------------------------------------------------------------------
void guest_set_executable_image( GUEST_HANDLE       guest,
                                 const UINT8*       image_address,
                                 UINT32             image_size,
                                 UINT32             image_load_GPA,
                                 BOOLEAN            image_is_compressed );
#ifdef INCLUDE_UNUSED_CODE
//------------------------------------------------------------------------------
// Load guest executable image into the guest memory
//
// Should not be called for primary guest
//------------------------------------------------------------------------------
void guest_load_executable_image( GUEST_HANDLE       guest );
#endif

//------------------------------------------------------------------------------
// Add new CPU to the guest
//
// Return the newly created CPU
//------------------------------------------------------------------------------
GUEST_CPU_HANDLE guest_add_cpu( GUEST_HANDLE guest );

//------------------------------------------------------------------------------
// Get guest CPU count
//------------------------------------------------------------------------------
UINT16 guest_gcpu_count( const GUEST_HANDLE guest );

//------------------------------------------------------------------------------
// enumerate guest cpus
//
// Return NULL on enumeration end
//------------------------------------------------------------------------------
typedef GENERIC_ARRAY_ITERATOR GUEST_GCPU_ECONTEXT;

GUEST_CPU_HANDLE guest_gcpu_first( const GUEST_HANDLE guest,
                                   GUEST_GCPU_ECONTEXT* context );

GUEST_CPU_HANDLE guest_gcpu_next( GUEST_GCPU_ECONTEXT* context );

//------------------------------------------------------------------------------
// Guest vmexits control
//
// request vmexits for given guest
//
// Receives 2 bitmasks:
//    For each 1bit in mask check the corresponding request bit. If request bit
//    is 1 - request the vmexit on this bit change, else - remove the
//    previous request for this bit.
//------------------------------------------------------------------------------
void guest_control_setup( GUEST_HANDLE guest, const VMEXIT_CONTROL* request );

LIST_ELEMENT * guest_get_cpuid_list(GUEST_HANDLE guest);

MSR_VMEXIT_CONTROL * guest_get_msr_control(GUEST_HANDLE guest);

//------------------------------------------------------------------------------
// enumerate guests
//
// Return NULL on enumeration end
//------------------------------------------------------------------------------
typedef GUEST_HANDLE GUEST_ECONTEXT;

GUEST_HANDLE guest_first( GUEST_ECONTEXT* context );
GUEST_HANDLE guest_next( GUEST_ECONTEXT* context );

////////////////////////////////////////////////////////////////////////////////
//
//          Dynamic Creation of Guests
//
////////////////////////////////////////////////////////////////////////////////

//------------------------------------------------------------------------------
// Dynamically create new Guest
//
// Return the newly created GUEST
//------------------------------------------------------------------------------

#ifdef ENABLE_MULTI_GUEST_SUPPORT
GUEST_HANDLE guest_dynamic_create(BOOLEAN stop_and_notify, const VMM_POLICY  *guest_policy);

BOOLEAN guest_dynamic_assign_memory(GUEST_HANDLE src_guest, GUEST_HANDLE dst_guest, GPM_HANDLE memory_map);

//------------------------------------------------------------------------------
// Dynamically add new CPU to the guest
//
// Return the newly created Guest CPU
//
// Note:
//    if do_not_stop_and_notify == FALSE
//      guest_before_dynamic_add_cpu() and guest_after_dynamic_add_cpu() are
//      called internally
//
//    If do_not_stop_and_notify == TRUE the called must call
//    guest_before_dynamic_add_cpu() and guest_after_dynamic_add_cpu() around the call
//------------------------------------------------------------------------------
GUEST_CPU_HANDLE guest_dynamic_add_cpu(
                       GUEST_HANDLE                       guest,    /* assign to*/
                       const VMM_GUEST_CPU_STARTUP_STATE* gcpu_startup, /* init */
                       CPU_ID                             host_cpu, /* assign to*/
                       BOOLEAN                            ready_to_run,
                       BOOLEAN                            stop_and_notify);
#endif

#ifdef INCLUDE_UNUSED_CODE
// new CPU in WaitForSIPI state, on current host cpu and ready to run
GUEST_CPU_HANDLE guest_dynamic_add_cpu_default(GUEST_HANDLE guest);
#endif

// the following set of functions should be used only when you REALLY know what
// you are doing - actually they are internal
#ifdef DEBUG
void guest_register_vmcall_services(GUEST_HANDLE guest);
#endif

#ifdef ENABLE_MULTI_GUEST_SUPPORT
// called internally in guest_dynamic_add_cpu() if stop_and_notify == TRUE
// and in guest_dynamic_add_cpu_default()
void guest_before_dynamic_add_cpu( void );
void guest_after_dynamic_add_cpu( GUEST_CPU_HANDLE gcpu ); // if gcpu == NULL - creation failed
#endif


#endif // _GUEST_H_

