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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(CREATE_GUESTS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(CREATE_GUESTS_C, __condition)
#include "vmm_defs.h"
#include "vmm_bootstrap_utils.h"
#include "gpm_api.h"
#include "guest.h"
#include "guest_cpu.h"
#include "host_cpu.h"
#include "hw_utils.h"
#include "scheduler.h"
#include "layout_host_memory.h"
#include "vmm_dbg.h"
#include "vmexit_msr.h"
#include "device_drivers_manager.h"
#include "vmcall_api.h"
#include "vmcall.h"
#include "host_memory_manager_api.h"
#include "vmm_startup.h"
#include "vmm_events_data.h"
#include "guest_pci_configuration.h"
#include "ipc.h"
#include "pat_manager.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

//
// Read input data structure and create all guests
//

#ifdef FAST_VIEW_SWITCH
extern void fvs_initialize(GUEST_HANDLE guest, UINT32 number_of_host_processors);
#endif

#if 0 // never defined
static void raise_guest_create_event(GUEST_ID guest_id);  // moved to guest.c
#endif

#define PRIMARY_MAGIC 0


// Add CPU to guest
void add_cpu_to_guest(const VMM_GUEST_STARTUP* gstartup, GUEST_HANDLE guest, 
                            CPU_ID host_cpu_to_allocate, BOOLEAN ready_to_run )
{
    GUEST_CPU_HANDLE gcpu;
    const VIRTUAL_CPU_ID* vcpu = NULL;
    const VMM_GUEST_CPU_STARTUP_STATE* cpus_arr = NULL;

#ifdef JLMDEBUG1
    bprint("add_cpu_to_guest guest SU: %p,  guest: %d, host: %d\n",
            gstartup, guest, host_cpu_to_allocate);
#endif
    gcpu = guest_add_cpu(guest);
    VMM_ASSERT(gcpu);
    // find init data
    vcpu= guest_vcpu(gcpu);
    VMM_ASSERT(vcpu);
    // register with scheduler
    scheduler_register_gcpu(gcpu, host_cpu_to_allocate, ready_to_run);
#ifdef JLMDEBUG1
    bprint("done with scheduler_register_gcpu 0x%016lx\n", vcpu);
    bprint("guest_cpu_id: %d\n", vcpu->guest_cpu_id);
    bprint("states count: %d\n", gstartup->cpu_states_count);
#endif
    if(vcpu->guest_cpu_id<gstartup->cpu_states_count) {
        cpus_arr = (const VMM_GUEST_CPU_STARTUP_STATE*)gstartup->cpu_states_array;
#ifdef JLMDEBUG
        if(cpus_arr==NULL) {
            bprint("cpus_arr is NULL\n");
            LOOP_FOREVER
        }
#endif
        VMM_ASSERT(cpus_arr);
        VMM_LOG(mask_anonymous, level_trace,
                "Setting up initial state for the newly created Guest CPU\n");
#ifdef JLMDEBUG1
        bprint("about to call gcpu_initialize(0x%016lx, 0x%016lx)\n", vcpu, gcpu);
#endif
        gcpu_initialize(gcpu, &(cpus_arr[vcpu->guest_cpu_id]));
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,
                "Newly created Guest CPU was initialized with the Wait-For-SIPI state\n");
    }
    // host part will be initialized later
#ifdef JLMDEBUG1
    bprint("done with add_cpu_to_guest\n");
#endif
}

// Init guest except for guest memory
// Return NULL on error
static GUEST_HANDLE init_single_guest( UINT32 number_of_host_processors,
                                const VMM_GUEST_STARTUP* gstartup, 
                                const VMM_POLICY  *guest_policy)
{
    GUEST_HANDLE  guest;
    UINT32        cpu_affinity = 0;
    UINT32        bit_number;
    BOOLEAN       ready_to_run = FALSE;

    if ((gstartup->size_of_this_struct != sizeof(VMM_GUEST_STARTUP)) ||
        (gstartup->version_of_this_struct != VMM_GUEST_STARTUP_VERSION )) {
        VMM_LOG(mask_anonymous, level_trace,"ASSERT: unknown guest struct: size: %#x version %d\n",
                gstartup->size_of_this_struct, gstartup->version_of_this_struct );
        return NULL;
    }
#ifdef JLMDEBUG
    bprint("about to init_single_guest, guest magic: %d\n", 
           gstartup->guest_magic_number);
#endif

    // create guest
    guest= guest_register(gstartup->guest_magic_number, 
                          gstartup->physical_memory_size,
                          gstartup->cpu_affinity, guest_policy );
    if (!guest) {
#ifdef JLMDEBUG
        bprint("guest register failed\n");
        LOOP_FOREVER
#endif
        return NULL;
    }
#ifdef FAST_VIEW_SWITCH
    fvs_initialize(guest, number_of_host_processors);
#endif
    vmexit_guest_initialize(guest_get_id(guest));
    if (gstartup->devices_count!=0) {
#ifdef JLMDEBUG
        bprint("vmexit_guest_initialize failed\n");
        LOOP_FOREVER
#endif
        return NULL;
    }
    if (gstartup->image_size) {
        guest_set_executable_image( guest, (const UINT8*)gstartup->image_address,
            gstartup->image_size, gstartup->image_offset_in_guest_physical_memory,
            BITMAP_GET(gstartup->flags, VMM_GUEST_FLAG_IMAGE_COMPRESSED) != 0);
    }
    if (BITMAP_GET(gstartup->flags, VMM_GUEST_FLAG_REAL_BIOS_ACCESS_ENABLE) != 0) {
#ifdef JLMDEBUG
        bprint("calling guest_set_real_BIOS_access_enabled\n");
#endif
        guest_set_real_BIOS_access_enabled(guest);
    }
    msr_vmexit_guest_setup(guest);  // setup MSR-related control structure
#ifdef JLMDEBUG1
    bprint("finished msr_vmexit_guest_setup 0x%016lx\n", guest);
#endif

    // init cpus.
    // first init CPUs that has initial state
    cpu_affinity = gstartup->cpu_affinity;
    if (cpu_affinity == 0) {
        return NULL;
    }
    ready_to_run= (BITMAP_GET(gstartup->flags, VMM_GUEST_FLAG_LAUNCH_IMMEDIATELY)!=0);
    if (cpu_affinity == (UINT32)-1) {
        // special case - run on all existing CPUs
        for(bit_number = 0; bit_number<number_of_host_processors; bit_number++) {
#ifdef JLMDEBUG1
            bprint("bit_number: %d\n", bit_number);
            bprint("gstartup: %p\n", gstartup);
#endif
            add_cpu_to_guest(gstartup, guest, (CPU_ID)bit_number, ready_to_run);
            VMM_LOG(mask_anonymous, level_trace,
                    "CPU #%d added successfully to the current guest\n", bit_number);
        }
    }
#ifdef DEBUG
    //register_vmcall_services(guest);
    guest_register_vmcall_services(guest);
#endif
#ifdef JLMDEBUG
    bprint("init_single_guest finished, ready_to_run: %d\n", ready_to_run );
#endif
    return guest;
}


// Perform initialization of guests and guest CPUs
// Should be called on BSP only while all APs are stopped
// Return TRUE for success
BOOLEAN initialize_all_guests( UINT32 number_of_host_processors,
#if 0
        int num_excluded,
#endif
        const VMM_MEMORY_LAYOUT* vmm_memory_layout,
        const VMM_GUEST_STARTUP* primary_guest_startup_state,
        UINT32 number_of_secondary_guests,
        const VMM_GUEST_STARTUP* secondary_guests_startup_state_array,
        const VMM_APPLICATION_PARAMS_STRUCT* application_params)
{
    GUEST_HANDLE primary_guest;
    GPM_HANDLE   primary_guest_startup_gpm;
    BOOLEAN      ok = FALSE;
    GUEST_CPU_HANDLE gcpu;
    GUEST_GCPU_ECONTEXT gcpu_context;

    VMM_ASSERT(hw_cpu_id() == 0);
    VMM_ASSERT(number_of_host_processors > 0);
    VMM_ASSERT(vmm_memory_layout);
    VMM_ASSERT(primary_guest_startup_state);

    if (number_of_secondary_guests > 0) {
        VMM_LOG(mask_anonymous, level_trace,"initialize_all_guests ASSERT: Secondary guests are yet not implemented\n");
        VMM_ASSERT( secondary_guests_startup_state_array );
        // init guests and allocate memory for them
        // shutdown temporary layout object
        VMM_DEADLOOP();
        return FALSE;
    }

    // first init primary guest
    VMM_LOG(mask_anonymous, level_trace,"Init primary guest\n");

    // BUGBUG: This is a workaround until loader will not do this!!!
    BITMAP_SET(((VMM_GUEST_STARTUP*)primary_guest_startup_state)->flags, 
          VMM_GUEST_FLAG_REAL_BIOS_ACCESS_ENABLE|VMM_GUEST_FLAG_LAUNCH_IMMEDIATELY);
#ifdef JLMDEBUG
    bprint("initialize_all_guests, %d CPUs\n", number_of_host_processors);
#endif
    // TODO: Uses global policy but should be part of VMM_GUEST_STARTUP structure.
    ((VMM_GUEST_STARTUP*)primary_guest_startup_state)->guest_magic_number= PRIMARY_MAGIC;
    primary_guest = init_single_guest(number_of_host_processors, 
                                      primary_guest_startup_state, NULL);  
    if (!primary_guest) {
        VMM_LOG(mask_anonymous, level_trace,
                 "initialize_all_guests: Cannot init primary guest\n");
        VMM_DEADLOOP();
        return FALSE;
    }
    guest_set_primary(primary_guest);
    primary_guest_startup_gpm = guest_get_startup_gpm(primary_guest);

    // init memory layout in the startup gpm
    // JLM(FIX) change this call
#if 1
    ok = init_memory_layout(vmm_memory_layout, primary_guest_startup_gpm,
                            number_of_secondary_guests > 0, application_params);
#else
    ok = init_memory_layout_from_mbr( num_excluded, vmm_memory_layout, primary_guest_startup_gpm,
                            number_of_secondary_guests > 0, application_params);
#endif

    // Set active_gpm to startup gpm
    for(gcpu = guest_gcpu_first(primary_guest, &gcpu_context); gcpu; gcpu = guest_gcpu_next(&gcpu_context)) {
        gcpu_set_current_gpm(gcpu, primary_guest_startup_gpm);
    }
    VMM_LOG(mask_anonymous, level_trace,"Primary guest initialized successfully\n");
    return ok;
}

// Perform initialization of host cpu portion of all guest CPUs that run 
// on specified host CPU.  Should be called on the target host CPU
void initialize_host_vmcs_regions( CPU_ID current_cpu_id )
{
    GUEST_CPU_HANDLE        gcpu;
    SCHEDULER_GCPU_ITERATOR it;

    VMM_ASSERT(current_cpu_id == hw_cpu_id());
    for (gcpu = scheduler_same_host_cpu_gcpu_first( &it, current_cpu_id );
         gcpu != NULL; gcpu = scheduler_same_host_cpu_gcpu_next( &it )) {
        // now init the host CPU part for vm-exits
        host_cpu_vmcs_init(gcpu);
    }
}

