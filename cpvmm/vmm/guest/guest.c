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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_C, __condition)
#include "guest_internal.h"
#include "guest_cpu_internal.h"
#include "guest_cpu.h"
#include "vmcall.h"
#include "gpm_api.h"
#include "heap.h"
#include "vmexit.h"
#include "vmm_dbg.h"
#include "memory_allocator.h"
#include "vmm_events_data.h"
#include "guest_pci_configuration.h"
#include "ipc.h"
#include "host_memory_manager_api.h"
#include "memory_address_mapper_api.h"
#include "scheduler.h"
#include "host_cpu.h"
#include <pat_manager.h>
#include "ept.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define MIN_ANONYMOUS_GUEST_ID  30000

extern void vmm_acpi_pm_initialize(GUEST_ID guest_id);


// Guest Manager
#ifdef ENABLE_MULTI_GUEST_SUPPORT
static void raise_gcpu_add_event(CPU_ID from, void* arg);
#endif

static UINT32                guests_count = 0;
static UINT32                max_gcpus_count_per_guest = 0;
static UINT32                num_host_cpus = 0;
static GUEST_DESCRIPTOR *    guests = NULL;


void guest_manager_init(UINT16 max_cpus_per_guest, UINT16 host_cpu_count)
{
#ifdef DEBUG
    bprint("guest_manager_init %d\n", host_cpu_count);
#endif
    VMM_ASSERT(max_cpus_per_guest);
    max_gcpus_count_per_guest = max_cpus_per_guest;
    num_host_cpus = host_cpu_count;
    guests = NULL;
    // init subcomponents
    gcpu_manager_init(host_cpu_count);
    // create VMEXIT-related data
    // vmexit_initialize();
}


// Get Guest by guest ID
// Return NULL if no such guest
GUEST_HANDLE guest_handle(GUEST_ID guest_id)
{
    GUEST_DESCRIPTOR  *guest;

#ifdef JLMDEBUG1
    bprint("guest_handle(%d).  guests: 0x%016lx\n", guest_id, guests);
#endif
    if(guest_id >= guests_count) {
        return NULL;
    }
    for(guest = guests; guest != NULL; guest= guest->next_guest) {
        if(guest->id == guest_id) {
#ifdef JLMDEBUG1
            bprint("guest_id: %d\n", guest->id);
#endif
            return guest;
        }
    }
    return NULL;
}

// Get Guest ID by guest handle
GUEST_ID guest_get_id( GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    return guest->id;
}

// Register new guest
// For primary guest physical_memory_size must be 0
// cpu_affinity - each 1 bit corresponds to host CPU_ID that should run GUEST_CPU
//          on behalf of this guest. Number of bits should correspond
//          to the number of registered guest CPUs for this guest
//          -1 means run on all available CPUs
// Return NULL on error
GUEST_HANDLE guest_register(UINT32 magic_number, UINT32 physical_memory_size,
                            UINT32  cpu_affinity, const VMM_POLICY  *guest_policy)
{
    GUEST_DESCRIPTOR* guest;

#ifdef JLMDEBUG1
    bprint("guest_register: magic_number %u, \n", magic_number);
#endif
    guest = (GUEST_DESCRIPTOR *) vmm_malloc(sizeof(GUEST_DESCRIPTOR));
    VMM_ASSERT(guest);

    guest->id = (GUEST_ID)guests_count;
    ++guests_count;
    if(magic_number == ANONYMOUS_MAGIC_NUMBER) {
        guest->magic_number = MIN_ANONYMOUS_GUEST_ID + guest->id;
    }
    else {
        VMM_ASSERT(magic_number < MIN_ANONYMOUS_GUEST_ID);
        guest->magic_number = magic_number;
    }
    guest->physical_memory_size = physical_memory_size;
    guest->cpu_affinity = cpu_affinity;
    guest->cpus_array = (GUEST_CPU_HANDLE *) 
            vmm_malloc(sizeof(GUEST_CPU_HANDLE)*max_gcpus_count_per_guest);
    guest->cpu_count = 0;
    guest->flags = 0;
    guest->saved_image = NULL;
    guest->saved_image_size = 0;
    guest->startup_gpm = gpm_create_mapping();
#ifdef JLMDEBUG
    bprint("gpm_create_mapping() returned %d\n", guest->startup_gpm);
#endif
    VMM_ASSERT(guest->startup_gpm != GPM_INVALID_HANDLE);
    if (guest_policy == NULL)
        get_global_policy(&guest->guest_policy);
    else
        copy_policy(&guest->guest_policy, guest_policy);
    list_init(guest->cpuid_filter_list);    // prepare list for CPUID filters
    list_init(guest->msr_control->msr_list); // prepare list for MSR handlers
    // vmexit_guest_initialize(guest->id);
    guest->next_guest = guests;
    guests = guest;
#ifdef JLMDEBUG
    bprint("returning from guest register\n");
#endif
    return guest;
}


// Get total number of guests
UINT16 guest_count( void )
{
    return (UINT16)guests_count;
}

// Get guest magic number
UINT32 guest_magic_number( const GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    return guest->magic_number;
}

// Get Guest by guest magic number
// Return NULL if no such guest
GUEST_HANDLE guest_handle_by_magic_number(UINT32 magic_number)
{
    GUEST_DESCRIPTOR *guest;

#ifdef JLMDEBUG1
    bprint("guest_handle_by_magic_number(%d).  guests: 0x%016lx\n", 
           magic_number, guests);
#endif
    for(guest = guests; guest != NULL; guest = guest->next_guest) {
        if(guest->magic_number == magic_number) {
            return guest;
        }
    }
    return NULL;
}

#ifdef INCLUDE_UNUSED_CODE
// Get guest physical memory size. For primary guest returns 0.
UINT32 guest_physical_memory_size( const GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    return guest->physical_memory_size;
}

// Get guest physical memory base. For primary guest returns 0.
UINT64 guest_physical_memory_base( const GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    return guest->physical_memory_base;
}

void set_guest_physical_memory_base( const GUEST_HANDLE guest, UINT64 base )
{
    VMM_ASSERT( guest );
    VMM_ASSERT( GET_GUEST_IS_PRIMARY_FLAG(guest) == 0 );
    guest->physical_memory_base = base;
}
#endif

#ifdef ENABLE_MULTI_GUEST_SUPPORT
// Get guest cpu affinity.
UINT32 guest_cpu_affinity( const GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    return guest->cpu_affinity;
}
#endif

#ifdef INCLUDE_UNUSED_CODE
// Set guest cpu affinity.
void guest_set_cpu_affinity( const GUEST_HANDLE guest, UINT32 cpu_affinity )
{
    VMM_ASSERT( guest );
    guest->cpu_affinity = cpu_affinity;
}
#endif

// Get guest POLICY
const VMM_POLICY *guest_policy( const GUEST_HANDLE guest )
{
    VMM_ASSERT(guest);
    return &guest->guest_policy;
}

#ifdef INCLUDE_UNUSED_CODE
// Set guest POLICY
void guest_set_policy( const GUEST_HANDLE guest, const VMM_POLICY *new_policy)
{
    VMM_ASSERT(guest);
    VMM_ASSERT(new_policy);
    copy_policy(&guest->guest_policy, new_policy);
}
#endif

// Guest properties.
// Default for all properties - FALSE
void guest_set_primary( GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    VMM_ASSERT( guest->physical_memory_size == 0 );
    VMM_ASSERT( guest->physical_memory_base == 0 );
    VMM_ASSERT( guest->saved_image == NULL );
    VMM_ASSERT( guest->saved_image_size == 0 );
    guest->flags|= GUEST_IS_PRIMARY_FLAG;
}

BOOLEAN guest_is_primary(const GUEST_HANDLE  guest )
{
    VMM_ASSERT( guest );
    return (GET_GUEST_IS_PRIMARY_FLAG(guest) != 0);
}

GUEST_ID guest_get_primary_guest_id(void)
{
    GUEST_DESCRIPTOR    *guest;

    for(guest = guests; guest != NULL; guest = guest->next_guest) {
        if(0 != GET_GUEST_IS_PRIMARY_FLAG( guest )) {
            return guest->id;
        }
    }
    return INVALID_GUEST_ID;
}

void guest_set_real_BIOS_access_enabled(GUEST_HANDLE guest)
{
    VMM_ASSERT( guest );
    guest->flags|= GUEST_BIOS_ACCESS_ENABLED_FLAG;
#ifdef ENABLE_EMULATOR
    vmcall_register( guest_get_id(guest), VMCALL_EMULATOR_TERMINATE,
                 gcpu_return_to_native_execution, TRUE); // special case
#endif
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN guest_is_real_BIOS_access_enabled(  const GUEST_HANDLE  guest )
{
    VMM_ASSERT( guest );
    return (GET_GUEST_BIOS_ACCESS_ENABLED_FLAG(guest) != 0);
}
#endif

void guest_set_nmi_owner(GUEST_HANDLE guest)
{
#ifdef JLMDEBUG
    bprint("guest_set_nmi_owner %p\n", guest);
#endif
    VMM_ASSERT(guest);
    guest->flags|= GUEST_IS_NMI_OWNER_FLAG;
}

BOOLEAN guest_is_nmi_owner(const GUEST_HANDLE  guest )
{
    VMM_ASSERT( guest );
    return (GET_GUEST_IS_NMI_OWNER_FLAG(guest) != 0);
}

void    guest_set_acpi_owner(GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
#ifdef ENABLE_PM_S3
    guest->flags|= GUEST_IS_ACPI_OWNER_FLAG;
    vmm_acpi_pm_initialize(guest->id);  // for ACPI owner only
#endif
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN guest_is_acpi_owner(const GUEST_HANDLE  guest )
{
    VMM_ASSERT( guest );
    return (GET_GUEST_IS_ACPI_OWNER_FLAG(guest) != 0);
}
#endif

void    guest_set_default_device_owner(GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    guest->flags|= GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG;
}

#ifdef INCLUDE_UNUSED_CODE
BOOLEAN guest_is_default_device_owner(const GUEST_HANDLE  guest )
{
    VMM_ASSERT( guest );
    return (GET_GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG(guest) != 0);
}
#endif

GUEST_ID guest_get_default_device_owner_guest_id(void)
{
    GUEST_DESCRIPTOR    *guest;

    for(guest = guests; guest != NULL; guest = guest->next_guest) {
        if(0 != GET_GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG( guest )) {
            return guest->id;
        }
    }
    return INVALID_GUEST_ID;
}

// Get startup guest physical memory descriptor
GPM_HANDLE guest_get_startup_gpm(GUEST_HANDLE guest)
{
    VMM_ASSERT(guest);
    return guest->startup_gpm;
}

// Get guest physical memory descriptor
GPM_HANDLE gcpu_get_current_gpm(GUEST_HANDLE guest)
{
    GUEST_CPU_HANDLE gcpu;

    VMM_ASSERT(guest);
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMM_ASSERT(gcpu);
    return gcpu->active_gpm;
}

void gcpu_set_current_gpm(GUEST_CPU_HANDLE gcpu, GPM_HANDLE gpm)
{
    VMM_ASSERT(gcpu);
    gcpu->active_gpm = gpm;
}

// Guest executable image
// Should not be called for primary guest
void guest_set_executable_image( GUEST_HANDLE guest, const UINT8* image_address, 
            UINT32 image_size, UINT32 image_load_GPA, BOOLEAN  image_is_compressed )
{
    VMM_ASSERT( guest );
    VMM_ASSERT( GET_GUEST_IS_PRIMARY_FLAG(guest) == 0 );
    guest->saved_image = image_address;
    guest->saved_image_size = image_size;
    guest->image_load_GPA = image_load_GPA;
    if (image_is_compressed) {
        guest->flags|= GUEST_SAVED_IMAGE_IS_COMPRESSED_FLAG;
    }
}

#ifdef INCLUDE_UNUSED_CODE
// Load guest executable image into the guest memory
// Should not be called for primary guest
void guest_load_executable_image( GUEST_HANDLE       guest )
{
    VMM_ASSERT( guest );
    VMM_ASSERT( GET_GUEST_IS_PRIMARY_FLAG(guest) == 0 );
    guest = 0;
    VMM_LOG(mask_anonymous, level_trace,
            "guest::guest_load_executable_image() is not implemented yet\n");
    VMM_DEADLOOP();
    VMM_BREAKPOINT();
}
#endif

// Add new CPU to the guest
// Return the newly created CPU
GUEST_CPU_HANDLE guest_add_cpu( GUEST_HANDLE guest )
{
    VIRTUAL_CPU_ID    vcpu;
    GUEST_CPU_HANDLE  gcpu;

#ifdef JLMDEBUG1
    bprint("guest_add_cpu\n");
#endif
    VMM_ASSERT( guest );
    VMM_ASSERT( guest->cpu_count < max_gcpus_count_per_guest );
    vcpu.guest_id = guest->id;
    vcpu.guest_cpu_id   = guest->cpu_count ;
    ++(guest->cpu_count);
    gcpu = gcpu_allocate(vcpu, guest);
    guest->cpus_array[vcpu.guest_cpu_id] = gcpu;
    return gcpu;
}

// Get guest CPU count
UINT16 guest_gcpu_count( const GUEST_HANDLE guest )
{
    VMM_ASSERT( guest );
    return guest->cpu_count;
}

// enumerate guest cpus
// Return NULL on enumeration end
GUEST_CPU_HANDLE guest_gcpu_first( const GUEST_HANDLE guest, GUEST_GCPU_ECONTEXT* context )
{
    const GUEST_CPU_HANDLE* p_gcpu;

    VMM_ASSERT( guest );
    p_gcpu = ARRAY_ITERATOR_FIRST( GUEST_CPU_HANDLE, guest->cpus_array,
                                   guest->cpu_count, context );
    return p_gcpu ? *p_gcpu : NULL;
}

GUEST_CPU_HANDLE guest_gcpu_next( GUEST_GCPU_ECONTEXT* context )
{
    GUEST_CPU_HANDLE* p_gcpu;

    p_gcpu = ARRAY_ITERATOR_NEXT( GUEST_CPU_HANDLE, context );
    return p_gcpu ? *p_gcpu : NULL;
}

// enumerate guests
// Return NULL on enumeration end
GUEST_HANDLE guest_first( GUEST_ECONTEXT* context )
{
    GUEST_DESCRIPTOR *guest = NULL;

    VMM_ASSERT(context);
    guest = guests;
    *context = guest;
    return guest;
}

GUEST_HANDLE guest_next( GUEST_ECONTEXT* context )
{
    GUEST_DESCRIPTOR *guest = NULL;

    VMM_ASSERT(context);
    guest = (GUEST_DESCRIPTOR *) *context;

    if (guest != NULL) {
        guest = guest->next_guest;
        *context = guest;
    }
    return guest;
}

LIST_ELEMENT * guest_get_cpuid_list(GUEST_HANDLE guest)
{
    return guest->cpuid_filter_list;
}

MSR_VMEXIT_CONTROL * guest_get_msr_control(GUEST_HANDLE guest)
{
    return guest->msr_control;
}

// assumption - all CPUs are running
void    guest_begin_physical_memory_modifications( GUEST_HANDLE guest )
{
    EVENT_GPM_MODIFICATION_DATA gpm_modification_data;
    GUEST_CPU_HANDLE    gcpu;

    VMM_ASSERT( guest );
    gpm_modification_data.guest_id = guest->id;
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMM_ASSERT(gcpu);
    event_raise(EVENT_BEGIN_GPM_MODIFICATION_BEFORE_CPUS_STOPPED, gcpu, &gpm_modification_data);
    stop_all_cpus();
    //event_raise(EVENT_BEGIN_GPM_MODIFICATION_AFTER_CPUS_STOPPED, gcpu, &gpm_modification_data);
}

#pragma warning( push )
#pragma warning (disable : 4100) // disable non-referenced formal parameters

static
void guest_notify_gcpu_about_gpm_change( CPU_ID from UNUSED, void* arg )
{
    CPU_ID guest_id = (CPU_ID)(size_t)arg;
    GUEST_CPU_HANDLE gcpu;

    gcpu = scheduler_get_current_gcpu_for_guest(guest_id);
    if (!gcpu) {
        // no gcpu for the current guest on the current host cpu
        return;
    }
    gcpu_physical_memory_modified( gcpu );
}

#pragma warning( pop )

#ifdef INCLUDE_UNUSED_CODE
// assumption - all CPUs stopped
void guest_abort_physical_memory_modifications( GUEST_HANDLE guest )
{
    GUEST_CPU_HANDLE    gcpu;

    VMM_ASSERT( guest );
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMM_ASSERT(gcpu);
    start_all_cpus(NULL, NULL);
    event_raise(EVENT_END_GPM_MODIFICATION_AFTER_CPUS_RESUMED, gcpu, NULL);
}
#endif


// assumption - all CPUs stopped
void guest_end_physical_memory_perm_update( GUEST_HANDLE guest )
{
    EVENT_GPM_MODIFICATION_DATA gpm_modification_data;
    GUEST_CPU_HANDLE    gcpu;

    VMM_ASSERT( guest );

    // prepare to raise events
    gpm_modification_data.guest_id = guest->id;
    gpm_modification_data.operation = VMM_MEM_OP_UPDATE;
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMM_ASSERT(gcpu);
    event_raise(EVENT_END_GPM_MODIFICATION_BEFORE_CPUS_RESUMED, gcpu, &gpm_modification_data);
    start_all_cpus(NULL, NULL);
    event_raise(EVENT_END_GPM_MODIFICATION_AFTER_CPUS_RESUMED, gcpu, &gpm_modification_data);
}

// assumption - all CPUs stopped
void guest_end_physical_memory_modifications( GUEST_HANDLE guest )
{
    EVENT_GPM_MODIFICATION_DATA gpm_modification_data;
    IPC_DESTINATION ipc_dest;
    GUEST_CPU_HANDLE    gcpu;

    VMM_ASSERT( guest );
    // notify gcpu of the guest running on the current host cpu
    guest_notify_gcpu_about_gpm_change( guest->id, (void*)(size_t)guest->id );
    // notify all other gcpu of the guest
    ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
    ipc_dest.addr = 0;
    ipc_execute_handler(ipc_dest, guest_notify_gcpu_about_gpm_change, (void*)(size_t)guest->id);
    // prepare to raise events
    gpm_modification_data.guest_id = guest->id;
    gpm_modification_data.operation = VMM_MEM_OP_RECREATE;
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMM_ASSERT(gcpu);
    event_raise(EVENT_END_GPM_MODIFICATION_BEFORE_CPUS_RESUMED, gcpu, &gpm_modification_data);
    start_all_cpus(NULL, NULL);
    event_raise(EVENT_END_GPM_MODIFICATION_AFTER_CPUS_RESUMED, gcpu, &gpm_modification_data);
}

#ifdef INCLUDE_UNUSED_CODE
// assumption - all CPUs are running
void guest_begin_physical_memory_perm_switch( GUEST_HANDLE guest )
{
    EVENT_GPM_MODIFICATION_DATA gpm_modification_data;
    GUEST_CPU_HANDLE    gcpu;

    VMM_ASSERT( guest );
    gpm_modification_data.guest_id = guest->id;
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMM_ASSERT(gcpu);
    event_raise(EVENT_BEGIN_GPM_MODIFICATION_BEFORE_CPUS_STOPPED, gcpu, &gpm_modification_data);
}

// assumption - all CPUs stopped
void guest_end_physical_memory_perm_switch( GUEST_HANDLE guest )
{
    EVENT_GPM_MODIFICATION_DATA gpm_modification_data;
    GUEST_CPU_HANDLE gcpu;

    VMM_ASSERT( guest );
    // prepare to raise events
    gpm_modification_data.guest_id = guest->id;
    gpm_modification_data.operation = VMM_MEM_OP_SWITCH;
    gcpu = scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMM_ASSERT(gcpu);
    event_raise(EVENT_END_GPM_MODIFICATION_BEFORE_CPUS_RESUMED, gcpu, &gpm_modification_data);
    event_raise(EVENT_END_GPM_MODIFICATION_AFTER_CPUS_RESUMED, gcpu, &gpm_modification_data);
}
#endif

#ifdef ENABLE_MULTI_GUEST_SUPPORT
GUEST_HANDLE guest_dynamic_create(BOOLEAN stop_and_notify, const VMM_POLICY  *guest_policy)
{
    GUEST_HANDLE guest = NULL;
    GUEST_ID guest_id = INVALID_GUEST_ID;
    EVENT_GUEST_CREATE_DATA guest_create_event_data;

    if (TRUE == stop_and_notify) {
        stop_all_cpus();
    }
    // create guest
    guest = guest_register(ANONYMOUS_MAGIC_NUMBER, 0,
                            (UINT32) -1 /* cpu affinity */, guest_policy);
    if (! guest) {
        VMM_LOG(mask_anonymous, level_trace,"Cannot create guest with the following params: \n"
                 "\t\tguest_magic_number    = %#x\n"
                 "\t\tphysical_memory_size  = %#x\n"
                 "\t\tcpu_affinity          = %#x\n",
                 guest_magic_number(guest), 0, guest_cpu_affinity(guest) );
        return NULL;
    }
    guest_id = guest_get_id(guest);
    vmexit_guest_initialize(guest_id);
    gpci_guest_initialize(guest_id);
    ipc_guest_initialize(guest_id);
    event_manager_guest_initialize(guest_id);
    guest_register_vmcall_services(guest);
    VMM_LOG(mask_anonymous, level_trace,"Created new guest #%d\r\n", guest_id);
    if (TRUE == stop_and_notify) {
        vmm_zeromem(&guest_create_event_data, sizeof(guest_create_event_data));
        guest_create_event_data.guest_id = guest_id;
        event_raise(EVENT_GUEST_CREATE, NULL, &guest_create_event_data);
        start_all_cpus(NULL, NULL);
    }
    return guest;
}

BOOLEAN guest_dynamic_assign_memory(GUEST_HANDLE src_guest, GUEST_HANDLE dst_guest, 
                                    GPM_HANDLE memory_map)
{
    GPM_HANDLE src_gpm = NULL, dst_gpm = NULL;
    GPM_RANGES_ITERATOR gpm_iter = GPM_INVALID_RANGES_ITERATOR;
    GPA gpa = 0, src_gpa = 0;
    UINT64 size = 0;
    BOOLEAN status = FALSE;
    HPA hpa = 0;
    UINT64 i;
    MAM_ATTRIBUTES attrs;

    VMM_ASSERT(dst_guest);
    VMM_ASSERT(memory_map);
    dst_gpm = gcpu_get_current_gpm(dst_guest);
    gpm_iter = gpm_get_ranges_iterator(dst_gpm);
    // check that target gpm is empty
    VMM_ASSERT(GPM_INVALID_RANGES_ITERATOR == gpm_iter);
    if(GPM_INVALID_RANGES_ITERATOR != gpm_iter) {
        return FALSE;
    }
    if(src_guest != NULL) {
        guest_begin_physical_memory_modifications( src_guest );
        gpm_iter = gpm_get_ranges_iterator(memory_map);

        while(GPM_INVALID_RANGES_ITERATOR != gpm_iter) {
            gpm_iter = gpm_get_range_details_from_iterator(memory_map,
                                            gpm_iter, &gpa, &size);
            status = gpm_gpa_to_hpa(memory_map, gpa, &hpa, &attrs);
            VMM_ASSERT(status);
            src_gpm = gcpu_get_current_gpm(src_guest);
            for(i = hpa; i < hpa + size; i += PAGE_4KB_SIZE) {
                status = gpm_hpa_to_gpa(src_gpm, hpa, &src_gpa);
                VMM_ASSERT(status);
                gpm_remove_mapping(src_gpm, src_gpa, PAGE_4KB_SIZE);
            }
        }
        guest_end_physical_memory_modifications( src_guest );
    }
    status = gpm_copy(src_gpm, dst_gpm, FALSE, mam_no_attributes);
    VMM_ASSERT(status);
    return TRUE;
}

GUEST_CPU_HANDLE guest_dynamic_add_cpu(GUEST_HANDLE guest,
                          const VMM_GUEST_CPU_STARTUP_STATE* gcpu_startup,
                          CPU_ID host_cpu, BOOLEAN ready_to_run, BOOLEAN stop_and_notify)
{
    GUEST_CPU_HANDLE gcpu;
    const VIRTUAL_CPU_ID* vcpu = NULL;

    if (TRUE == stop_and_notify) {
        guest_before_dynamic_add_cpu();
    }

    // DK: Do not need this if IPC will work with WaitForSIPI
    // check that host_cpu is active
    //    gcpu = scheduler_get_current_gcpu_on_host_cpu(host_cpu);
    //    if(gcpu != NULL && gcpu_is_wait_for_sipi(gcpu)) {
    //        start_all_cpus(NULL, NULL);
    //        return NULL;
    //    }
    gcpu = guest_add_cpu(guest);
    VMM_ASSERT( gcpu );
    // find init data
    vcpu = guest_vcpu( gcpu );
    // register with scheduler
    scheduler_register_gcpu( gcpu, host_cpu, ready_to_run );
    if (gcpu_startup != NULL) {
        VMM_LOG(mask_anonymous, level_trace,
                "Setting up initial state for the newly created Guest CPU\n");
        gcpu_initialize( gcpu, gcpu_startup );
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,"Newly created Guest CPU was initialized with the Wait-For-SIPI state\n");
    }
    host_cpu_vmcs_init( gcpu );
    if (TRUE == stop_and_notify) {
        guest_after_dynamic_add_cpu( gcpu );
    }
    return gcpu;
}
#endif

#ifdef INCLUDE_UNUSED_CODE
GUEST_CPU_HANDLE guest_dynamic_add_cpu_default(GUEST_HANDLE guest)
{
    return guest_dynamic_add_cpu(guest, NULL, hw_cpu_id(), TRUE, TRUE);
}
#endif

#pragma warning( push )
#pragma warning (disable : 4100) // disable non-referenced formal parameters

#ifdef ENABLE_MULTI_GUEST_SUPPORT
static
void raise_gcpu_add_event(CPU_ID from UNUSED, void* arg)
{
    CPU_ID this_cpu_id = hw_cpu_id();
    GUEST_CPU_HANDLE gcpu = (GUEST_CPU_HANDLE) arg;

    VMM_LOG(mask_anonymous, level_trace,"cpu#%d raise gcpu add event gcpu %p\n", 
            this_cpu_id, gcpu);
    if(this_cpu_id == scheduler_get_host_cpu_id(gcpu)) {
        event_raise(EVENT_GCPU_ADD, gcpu, NULL);
    }
}

void guest_before_dynamic_add_cpu( void )
{
    stop_all_cpus();
}

void guest_after_dynamic_add_cpu( GUEST_CPU_HANDLE gcpu )
{
    CPU_ID cpu_id = hw_cpu_id();

    if (gcpu) {
        // created ok
        host_cpu_vmcs_init( gcpu );
        VMM_LOG(mask_anonymous, level_trace,"CPU#%d: Notify all on added gcpu: %p host_cpu: %d\r\n", cpu_id, gcpu, scheduler_get_host_cpu_id(gcpu));
        start_all_cpus(raise_gcpu_add_event, gcpu);
        VMM_LOG(mask_anonymous, level_trace,"CPU#%d: raise local gcpu add\r\n", cpu_id);
        raise_gcpu_add_event(cpu_id, gcpu);
    }
    else {
        // creation failed
        start_all_cpus( NULL, NULL );
    }
}
#endif

#pragma warning( pop )

// utils
#ifdef INCLUDE_UNUSED_CODE
BOOLEAN vmm_get_struct_host_ptr(GUEST_CPU_HANDLE gcpu,
            void* guest_ptr, VMCALL_ID expected_vmcall_id,
            UINT32 size_of_struct, void** host_ptr) {
    UINT64 gva = (UINT64)guest_ptr;
    UINT64 hva;
    void* host_ptr_tmp;

    if (!gcpu_gva_to_hva(gcpu, gva, &hva)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Invalid Parameter Struct Address %P\n", __FUNCTION__, gva);
        return FALSE;
    }
    host_ptr_tmp = (void*)hva;
    if (*((VMCALL_ID*)host_ptr_tmp) != expected_vmcall_id) {
        VMM_LOG(mask_anonymous, level_trace,
            "%s: Invalid first field (vmcall_id) of the struct: %d instead of %d\n", 
            __FUNCTION__, *((VMCALL_ID*)host_ptr_tmp), expected_vmcall_id);
        return FALSE;
    }
    if (ALIGN_BACKWARD(gva, PAGE_4KB_SIZE) != ALIGN_BACKWARD(gva+size_of_struct, PAGE_4KB_SIZE)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Parameters Struct crosses the page boundary. gva = %P, size_of_struct = 0x%x\n", __FUNCTION__, gva, size_of_struct);
        return FALSE;
    }
    *host_ptr = host_ptr_tmp;
    return TRUE;
}

#pragma warning( push )
#pragma warning (disable : 4100) // disable non-referenced formal parameters

static VMM_STATUS is_uvmm_running(GUEST_CPU_HANDLE gcpu, ADDRESS *arg1,
                            ADDRESS *arg2 UNUSED, ADDRESS *arg3 UNUSED) {
    void** is_vmm_running_params_guest_ptr = (void**)arg1;
    VMM_IS_UVMM_RUNNING_PARAMS* is_vmm_running_params;

    if (!vmm_get_struct_host_ptr(gcpu, *is_vmm_running_params_guest_ptr,
                                 VMCALL_IS_UVMM_RUNNING,
                                 sizeof(VMM_IS_UVMM_RUNNING_PARAMS),
                                 (void**)&is_vmm_running_params)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Error - could not retrieve pointer to parameters\n", __FUNCTION__);
        VMM_DEADLOOP();
        return VMM_ERROR;
    }
    VMM_LOG(mask_anonymous, level_trace,"%s: Notifying driver that uVMM is running\n", __FUNCTION__);
    is_vmm_running_params->version = 0;
    return VMM_OK;
}

static VMM_STATUS print_debug_message_service(GUEST_CPU_HANDLE gcpu, ADDRESS *arg1,
                            ADDRESS *arg2 UNUSED, ADDRESS *arg3 UNUSED)
{
    void** print_debug_message_params_guest_ptr = (void**)arg1;
    VMM_PRINT_DEBUG_MESSAGE_PARAMS* print_debug_message_params;

    if (!vmm_get_struct_host_ptr(gcpu, *print_debug_message_params_guest_ptr,
                                 VMCALL_PRINT_DEBUG_MESSAGE,
                                 sizeof(VMM_PRINT_DEBUG_MESSAGE_PARAMS),
                                 (void**)&print_debug_message_params)) {
        VMM_LOG(mask_anonymous, level_trace,
                "%s: Error - could not retrieve pointer to parameters\n", __FUNCTION__);
        return VMM_ERROR;
    }
    VMM_LOG(mask_anonymous, level_trace,"%s\n", print_debug_message_params->message);
    return VMM_OK;
}

#pragma warning( pop )
#endif

#ifdef DEBUG
extern void vmm_io_emulator_register( GUEST_ID guest_id );
void guest_register_vmcall_services(GUEST_HANDLE guest)
{
    GUEST_ID guest_id = guest_get_id(guest);
    vmm_io_emulator_register(guest_id);
}
#endif
