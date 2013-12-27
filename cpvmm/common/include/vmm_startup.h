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

#ifndef _UVMM_STARTUP_H_
#define _UVMM_STARTUP_H_

//==============================================================================
//
// uVMM Startup Definitions
//
// This files contains definitions of the interaction between the uVMM and its
// loader.
//
//==============================================================================

#include "vmm_defs.h"
#include "vmm_arch_defs.h"

#pragma PACK_ON


//==============================================================================
//
// uVMM Sturtup Constants
//
// Note:  Constants that are related to specific structures below are defined
//        near their respective structures.
//
//==============================================================================

// Default size for uVMM footprint in memory, that should be
// allocated by the loader.  Includes the uVMM executable image and work work
// area, but not the 32bit-to-64bit Thunk image.

#define UVMM_DEFAULT_FOOTPRINT          75 MEGABYTES

// Default size for uVMM stack, in pages

#define UVMM_DEFAULT_STACK_SIZE_PAGES   10


//==============================================================================
//
// uVMM Startup Structure Types
//
// Notes:
//
// These structures are used both in 32-bit and 64-bit modes, therefore:
// 
// - Structure sizes are 64-bit aligned
// - All pointers are defined as 64-bit, and must be set so their higher 32 bits
//   are 0 (< 4GB).  This ensures their usability in both 32-bit and 64-bit
//   modes.
// - All pointers are in a loader virtual memory space (if applicable).
//
// Major terms:
//
// Primary guest   - the guest that owns the platform and platform was
//                   booted originally to run this guest
//
// Secondary guest - the guest that is used to perform some dedicated tasks
//                   on behalf of the primary guest
//
// Following is the structure hierarchy (---> denotes a pointer):
//
// VMM_STARTUP_STRUCT
// +---- VMM_MEMORY_LAYOUT     vmm_memory_layout[]
// +---> INT15_E820_MEMORY_MAP physical_memory_layout_E820
// +---> VMM_GUEST_STARTUP     primary_guest_startup_state
// |     +---> VMM_GUEST_CPU_STARTUP_STATE cpu_states_array[]
// |     |     +---- VMM_GP_REGISTERS             gp
// |     |     +---- VMM_XMM_REGISTERS            xmm
// |     |     +---- VMM_SEGMENTS                 seg
// |     |     +---- VMM_CONTROL_REGISTERS        control
// |     |     +---- VMM_MODEL_SPECIFIC_REGISTERS msr
// |     +---> VMM_GUEST_DEVICE            devices_array[]
// +---> VMM_GUEST_STARTUP     secondary_guests_startup_state_array[]
// |     +... as above
// +---- VMM_DEBUG_PARAMS      debug_params
//       +---- VMM_DEBUG_PORT_PARAMS       port
// VMM_APPLICATION_PARAMS_STRUCT
//
//==============================================================================


//------------------------------------------------------------------------------
//
// VMM_MEMORY_LAYOUT
//
// VMM bounding box - vmm memory layout as it was built by loader
// Data about sizes is part of installer info
//
// Vmm image occupies area [base_address .. base_address+image_size]
// Area [base_address+image_size .. base_address+total_size] is used for
// vmm heaps and stacks
//------------------------------------------------------------------------------

typedef struct _VMM_MEMORY_LAYOUT
{
    UINT32      total_size;
    UINT32      image_size;     // the VMM image is loaded at the area start
    UINT64      base_address;
    UINT64      entry_point;
} PACKED VMM_MEMORY_LAYOUT;


//------------------------------------------------------------------------------
//
// VMM_GUEST_CPU_STARTUP_STATE: Initial Guest CPU State
//
// Specified per each active CPU for each guest, and will be put into Guest VMCS
// at guest launch time. All addresses are absolute values that should be put in
// VMCS.
//
// If for some guest CPU VMM_GUEST_CPU_STARTUP_STATE is not specified,
// this guest CPU is put into the Wait-for-SIPI state.
// VMM_GUEST_CPU_STARTUP_STATE must be specified for at least first processor
// (BSP) of each guest.
//
// Guest initial entry point should be set as the CS:RIP pair:
//
// - CS is specified in the seg[IA32_SEG_CS].selector value
// - RIP is specified in the gp[IA32_REG_RIP] value
//
// These values are specified as:
//
//  1. If guest paging is active CS:RIP is in the GVA notation
//  2. If guest is in protected non-paged mode CS:RIP is in the GPA notation
//  3. If guest is in the real mode CS:RIP is in the GPA notation and CS
//     specifies the GPA value of the segment base, shifted right 4 bits.
//
//------------------------------------------------------------------------------
// 
#define VMM_GUEST_CPU_STARTUP_STATE_VERSION       1

// This structure should be aligned on 8 byte
#define VMM_GUEST_CPU_STARTUP_STATE_ALIGNMENT     8

typedef struct _VMM_GUEST_CPU_STARTUP_STATE
{
    UINT16                          size_of_this_struct;
    UINT16                          version_of_this_struct;
    UINT32                          reserved_1;

    /* 64-bit aligned */

    // there are additional registers in the CPU that are not passed here.
    // it is assumed that for the new guest the state of such registers is
    // the same, as it was at the VMM entry point.

    VMM_GP_REGISTERS                gp;
    VMM_XMM_REGISTERS               xmm;
    VMM_SEGMENTS                    seg;
    VMM_CONTROL_REGISTERS           control;
    VMM_MODEL_SPECIFIC_REGISTERS    msr;
}PACKED VMM_GUEST_CPU_STARTUP_STATE;


//------------------------------------------------------------------------------
// 
// VMM_GUEST_DEVICE: Guest Devices
//
// Describes virtualized, hidden or attached device
//
// If device is assinged to this guest is may be exposed using its real
// id or virtualized id.
// If the same real_vendor_id/real_device_id is specified for
// number of guests, this device will be exposed to each of this guests.
// If VT-d is active, this device will be hidden from all other guests.
// If VT-d is not active, it will be exposed using "unsupported vendor/device id"
//
// *** THIS FEATURE IS NOT CURRENTLY SUPPORTED ***
//
//------------------------------------------------------------------------------

#define VMM_GUEST_DEVICE_VERSION                  1

typedef struct _VMM_GUEST_DEVICE
{
    UINT16              size_of_this_struct;
    UINT16              version_of_this_struct;
    UINT32              reserved_1;

    // Real device data
    
    UINT16              real_vendor_id;
    UINT16              real_device_id;
    
    // Virtual device data
    
    UINT16              virtual_vendor_id;
    UINT16              virtual_device_id;
} PACKED  VMM_GUEST_DEVICE;


//------------------------------------------------------------------------------
// 
// VMM_GUEST_STARTUP: Describes One Guest
//
//------------------------------------------------------------------------------

#define VMM_GUEST_STARTUP_VERSION                 1

//-------------
// Guest flags
//-------------

// 1 - allow execution of 'int' instructions in real mode
// 0 - stop guest scheduling on first 'int' intruction execution in real mode
#define VMM_GUEST_FLAG_REAL_BIOS_ACCESS_ENABLE    BIT_VALUE(0)

// 1 - start the guest as soon as possible without any additional request
// 0 - start the guest on a specific request of some other guest
//     using the appropriate VmCall( guest_magic_number )
// at least one guest have to be configured as 'start_immediately'
#define VMM_GUEST_FLAG_LAUNCH_IMMEDIATELY         BIT_VALUE(1)

// 1 - image is compressed. Should be uncompressed before execution.
#define VMM_GUEST_FLAG_IMAGE_COMPRESSED           BIT_VALUE(2)

// This structure should be aligned on 8 bytes
#define VMM_GUEST_STARTUP_ALIGNMENT               8

typedef struct _VMM_GUEST_STARTUP {
    UINT16                  size_of_this_struct;
    UINT16                  version_of_this_struct;

    // set of flags that define policies for this guest, see definition
    // above
    UINT32                  flags;

    /* 64-bit aligned */

	// guest unique id in the current application.
	UINT32                  guest_magic_number;

	// set bit to 1 for each physical CPU, where GuestCPU should run.
	// Guest should have num_of_virtual_CPUs == num of 1-bits in the mask
	// ex. 0x3 means that guest has 2 CPUs that run on physical-0 and
	// physical-1 CPUs
	//
	// if -1 - run on all available CPUs
	//
	// if number of 1 bits is more than cpu_states_count, all other guest
	// CPUs will be initialized in the Wait-for-SIPI state.
	//
	// if 1 is set for bit-number greater than physically available CPU count,
	// the whole guest is discarded. The only exception is -1.
	UINT32                  cpu_affinity;

    /* 64-bit aligned */

    // number of VMM_GUEST_CPU_STATE structures provided.
    // if number of VMM_GUEST_CPU_STATE structures is less than number
    // of processors used by this guest, all other processors will
    // be initialized in the Wait-for-SIPI state
    UINT32                  cpu_states_count;

    /* 64-bit aligned */

	// number of virtualized or hidden devices for specific guest
	// if count == 0 - guest is deviceless,
	// except the case that the guest is also signed as default_device_owner
	UINT32                  devices_count;

    // guest image as loaded by the loader
    //  For primary guest it must be zeroed
    UINT32                  image_size;
    UINT64                  image_address;

    /* 64-bit aligned */

    // amount of physical memory for this guest
    //  For primary guest it must be zeroed
    UINT32                  physical_memory_size;

    // load address of the image in the guest physical memory
    //  For primary guest it must be zeroed
    UINT32                  image_offset_in_guest_physical_memory;

    // pointer to an array of initial CPU states for guest CPUs
    // First entry is for the guest BSP processor, that is a least-numbered
    // 1 bit in the cpu_affinity. At least one such structure has to exist.
    // Guest CPUs that does not have this structure are started in the
    // Wait-for-SIPI state.
    //  VMM_GUEST_CPU_STARTUP_STATE*
    UINT64                  cpu_states_array;

    // pointer to an array of guest devices
    //  VMM_GUEST_DEVICE*
    UINT64                  devices_array;
}PACKED VMM_GUEST_STARTUP;


//------------------------------------------------------------------------------
// 
// VMM_DEBUG_PARAMS: Debug Parameters
//
// Controls various parameters for VMM debug
//
// Note: There are no 'size' and 'version' fields in VMM_DEBUG_PARAMS, since
//       this strucure is included in VMM_STURTUP_STRUCT.  Set the version
//       there!
//
//------------------------------------------------------------------------------

// VMM_DEBUG_PORT_TYPE: Type of debug port

typedef enum _VMM_DEBUG_PORT_TYPE
{
    // No debug port is used
    VMM_DEBUG_PORT_NONE = 0,

    // The debug port is a generic 16450-compatible serial controller
    VMM_DEBUG_PORT_SERIAL,       

    VMM_DEBUG_PORT_TYPE_LAST
} VMM_DEBUG_PORT_TYPE;

// VMM_DEBUG_PORT_IDENT_TYPE: How the debug port is identified

#define VMM_DEBUG_PORT_IDENT_PCI_INDEX_MAX 15   // See below

typedef enum _VMM_DEBUG_PORT_IDENT_TYPE
{
    // No debug port is identified, use the VMM default
    VMM_DEBUG_PORT_IDENT_DEFAULT = 0,

    // The debug port is identified using its h/w base address in the I/O space
    VMM_DEBUG_PORT_IDENT_IO,       

    // The debug port is identified as the N'th debug port (of type
    // VMM_DEBUG_PORT_TYPE) on the PCI bus.
    // Range is 0 to VMM_DEBUG_PORT_IDENT_PCI_INDEX_MAX
    // **** NOTES:  1. This is not directly supported by uVMM yet.
    //              2. Loaders may support this, but must detect devices and
    //                 convert to VMM_DEBUG_PORT_IDENT_IO before invoking uVMM
    VMM_DEBUG_PORT_IDENT_PCI_INDEX,

    VMM_DEBUG_PORT_IDENT_LAST
} VMM_DEBUG_PORT_IDENT_TYPE;

// VMM_DEBUG_PORT_VIRT_MODE: How the debug port is virtualized

typedef enum _VMM_DEBUG_PORT_VIRT_MODE
{
    // No virtaulization
    VMM_DEBUG_PORT_VIRT_NONE = 0,

    // Hide the port.  Reads return all 1, writes do nothing.  This mode is
    // useful when all the guests are expected to discover the port before they
    // attempt to use it.
    VMM_DEBUG_PORT_VIRT_HIDE,       

    // Port acts as /dev/null: Status reads emulate ready for output, no
    // available input.  Writes do nothing.  This modes may be useful for late
    // launch, to avoid hanging the primary guest if it tries to use the same
    // port.
    // **** THIS MODE IS NOT SUPPORTED YET ****
    VMM_DEBUG_PORT_VIRT_NULL,
    
    VMM_DEBUG_PORT_VIRT_LAST
} VMM_DEBUG_PORT_VIRT_MODE;


// This structure should be aligned on 8 byte
#define VMM_DEBUG_PORT_PARAMS_ALIGNMENT           8

#define VMM_DEBUG_PORT_SERIAL_IO_BASE_DEFAULT 0x3F8   // std com1

typedef struct _VMM_DEBUG_PORT_PARAMS
{
    UINT8  type;         // VMM_DEBUG_PORT_TYPE
    UINT8  virt_mode;    // VMM_DEBUG_PORT_VIRT_MODE
    UINT8  reserved_1;
    UINT8  ident_type;   // VMM_DEBUG_PORT_IDENT_TYPE
    union
    {
        UINT16 io_base;  // For use with ident_type == VMM_DEBUG_PORT_IDENT_IO
        UINT32 index;    // For use with ident_type == VMM_DEBUG_PORT_IDENT_PCI_INDEX
        UINT32 ident32;  // Dummy filler
    }      ident;

    /* 64-bit aligned */
} PACKED VMM_DEBUG_PORT_PARAMS;

// This structure should be aligned on 8 byte
#define VMM_DEBUG_PARAMS_ALIGNMENT                8

typedef struct _VMM_DEBUG_PARAMS
{
    // Global level filter  for debug printouts.  Only messages whose level are
    // lower or equal than this value are printed.
    // 0 : Only top-priority messages (e.g., fatal errors) are printed
    // 1 : In addition to the above, error messages are printed (default)
    // 2 : In addition to the above, warnings are printed
    // 3 : In addition to the above, informational messages are printed
    // 4 : In addition to the above, trace messages are printed
    UINT8                 verbosity;         

    UINT8                 reserved[7];

    /* 64-bit aligned */

    // Main debug port: used for logging, CLI etc.
    VMM_DEBUG_PORT_PARAMS port;

    /* 64-bit aligned */

    // Auxiliary debug port: used for GDB
    VMM_DEBUG_PORT_PARAMS aux_port;

    /* 64-bit aligned */

    // Global bit-mask filter for debug printouts.  Each bit in the mask
    // enables printing of one class (documented separately) of printout.
    // All 0's : nothing is printed
    // All 1's : everything is printed
    UINT64                mask;

    /* 64-bit aligned */

    // Physical address of debug buffer used during deadloop
    UINT64                debug_data;

    /* 64-bit aligned */

} PACKED VMM_DEBUG_PARAMS;


//------------------------------------------------------------------------------
// 
// VMM_STARTUP_STRUCT: Startup Parameters
//
// Top level structure that describes VMM layout, guests, etc.
// Passed to VMM entry point.
//
//------------------------------------------------------------------------------

#define VMM_STARTUP_STRUCT_VERSION                5

// Minimal version number of VMM_STARTUP_STRUCT that includes VMM_DEBUG_PARAMS.
// This is required for proper version checking on VMM initialization, as older
// versions don't have this structure and VMM must use defaults.
#define VMM_STARTUP_STRUCT_MIN_VERSION_WITH_DEBUG 2


// Startup capability flags (max 16 bits)

#define VMM_STARTUP_ACPI_DISCOVERY_CAPABILITY     BIT_VALUE(0)

// 1 - the VMM is launched in a post-os-launch mode
// 0 - the VMM is launched in a pre-os-launch mode
#define VMM_STARTUP_POST_OS_LAUNCH_MODE           BIT_VALUE(1)

// Images used by uVMM

typedef enum _UVMM_IMAGE_INDEX
{
    uvmm_image = 0,
    thunk_image,
    uvmm_images_count
} UVMM_IMAGE_INDEX;

// This structure should be aligned on 8 byte
#define VMM_STARTUP_STRUCT_ALIGNMENT              8

typedef struct _VMM_STARTUP_STRUCT {
    UINT16                      size_of_this_struct;
    UINT16                      version_of_this_struct;

    // number of processors/cores at install time.
    // used to verify correctness of the bootstrap process
    UINT16                      number_of_processors_at_install_time;

    // number of processors/cores as was discovered by vmm loader
    // used to verify correctness of the bootstrap process
    UINT16                      number_of_processors_at_boot_time;

    /* 64-bit aligned */

    // number of secondary Guests
    UINT16                      number_of_secondary_guests;

    // size of stack for VMM per processor. In 4K pages.
    UINT16                      size_of_vmm_stack;

    // values to be used by VMM to hide devices if VT-d is not accessable
    // **** THIS FEATURE IS CURRENTLY NOT SUPPORTED ****
    UINT16                      unsupported_vendor_id;
    UINT16                      unsupported_device_id;

    /* 64-bit aligned */

    // set of flags, that define policies for the VMM as a whole
    UINT32                      flags;

    // magic number of the guest, that owns all platform devices
    // that were not assigned to any guest
    UINT32                      default_device_owner;

    /* 64-bit aligned */

    // magic number of the guest, that serves as OSPM.
    // SMM code is executed in the context of this guest
    UINT32                      acpi_owner;

    // magic number of the guest, that process platform NMIs.
    UINT32                      nmi_owner;

    /* 64-bit aligned */

    // vmm memory layout
    VMM_MEMORY_LAYOUT           vmm_memory_layout[uvmm_images_count];

    // pointer to the int 15 E820 BIOS table
    //  INT15_E820_MEMORY_MAP*
    // Loader must convert the table into the E820 extended format
    // (each entry 24 bytes long). If BIOS-returned entry was 20 bytes long
    // the extended attributes should be set to 0x1.
    UINT64                      physical_memory_layout_E820;

    /* 64-bit aligned */
    // pointer to the primary guest state
    //   VMM_GUEST_STARTUP*
    UINT64                      primary_guest_startup_state;

    /* 64-bit aligned */
    // pointer to the array of secondary guest states
    // size of array is number_of_secondary_guests
    //   VMM_GUEST_STARTUP*
    UINT64                      secondary_guests_startup_state_array;

    /* 64-bit aligned */
    // Debug parameters
    VMM_DEBUG_PARAMS            debug_params;
	
    /* 64-bit aligned */
    // Active cpu local apic ids
    UINT8						cpu_local_apic_ids[ALIGN_FORWARD(VMM_MAX_CPU_SUPPORTED, 8)];
}PACKED VMM_STARTUP_STRUCT;


//------------------------------------------------------------------------------
// 
// VMM_APPLICATION_PARAMS_STRUCT: Application Parameters
//
// Top level structure that describes application parameters.
// Used to pass application-related install data from installer to VMM-based app.
//
//------------------------------------------------------------------------------

#define VMM_APPLICATION_PARAMS_STRUCT_VERSION   1

typedef struct _VMM_APPLICATION_PARAMS_STRUCT {
	UINT32                      size_of_this_struct; // overall, including all params
	UINT32                      number_of_params;    // number of params that will follow


    // random generated id to avoid vmm shutdown by others
    UINT64                      session_id;
    // page entry list for the additional heap
    UINT64                      address_entry_list;
    UINT64                      entry_number;
	// this is per parameter
	// VMM_GUID                 guid_of_param1;
	// struct                   param1;
	//
	// VMM_GUID                 guid_of_param2;
	// struct                   param2;
	//
#ifdef USE_ACPI
    UINT64                      fadt_gpa;
#ifdef ENABLE_VTD
    UINT64                      dmar_gpa;
#endif
#endif //ifdef USE_ACPI
} VMM_APPLICATION_PARAMS_STRUCT;


//==============================================================================
//
// VMM entry point itself. Must be called by VMM loader once for each
// processor/core in the platform. Parameters to the entry point are different
// for BSP (boot strap processor) and for each AP (application processor)
//
// The order of the calls between processors is not defined, assuming that
// this function will be called on all number_of_processors defined in the
// VMM_STARTUP_STRUCT.
//
// Never returns.
//
//==============================================================================

void CDECL vmm_main(
    // logical local apic ID of the current processor
     // 0 - BSP, != 0 - AP
    UINT32                                 local_apic_id,

    // VMM_STARTUP_STRUCT should be passed only for BSP
    //   VMM_STARTUP_STRUCT*
    UINT64                                 startup_data,

    // VMM_APPLICATION_PARAMS_STRUCT should be passed only for BSP
    //   VMM_APPLICATION_PARAMS_STRUCT*
    UINT64                                 application_params,

    // must be 0
    UINT64                                 reserved
);


#pragma PACK_OFF

#endif // _UVMM_STARTUP_H_

