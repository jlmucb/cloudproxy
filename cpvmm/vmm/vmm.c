/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMM_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMM_C, __condition)
#include "vmm_defs.h"
#include "vmm_startup.h"
#include "vmm_globals.h"
#include "vmm_callback.h"
#include "libc.h"
#include "vmm_serial.h"
#include "cli.h"
#include "address.h"
#include "lock.h"
#include "hw_includes.h"
#include "heap.h"
#include "gdt.h"
#include "isr.h"
#include "vmm_stack_api.h"
#include "e820_abstraction.h"
#include "host_memory_manager_api.h"
#include "cli_monitor.h"
#include "vmcs_init.h"
#include "efer_msr_abstraction.h"
#include "mtrrs_abstraction.h"
#include "guest.h"
#include "policy_manager.h"
#include "host_cpu.h"
#include "scheduler.h"
#include "vmm_bootstrap_utils.h"
#include "ipc.h"
#include "vmexit.h"
#include "parse_pe_image.h"
#include "vmm_dbg.h"
#include "vmx_trace.h"
#include "event_mgr.h"
#include <pat_manager.h>
#include "host_pci_configuration.h"
#include "guest_pci_configuration.h"
#include "vtd.h"
#include "ept.h"
#include "device_drivers_manager.h"
#include "vmx_nmi.h"
#include "vmdb.h"
#include "vmx_timer.h"
#include "guest/guest_cpu/unrestricted_guest.h"
#include "vmx_teardown.h"
#include "vmcs_api.h"
#ifdef FAST_VIEW_SWITCH
#include "fvs.h"
#endif
#include "profiling.h"
#ifdef USE_ACPI
#include "vmm_acpi.h"
#endif

#define __builtin_va_end(p)
#define __builtin_stdarg_start(a,b)
#define __builtin_va_arg(a,p) 0

#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


#ifdef JLMDEBUG

#define PS 0x00000080ULL
UINT64 getphysical(UINT64 cr3, UINT64 virt)
{
    UINT64 i1, i2, i3, i4, i5;
    UINT64 *b1, *b2, *b3, *b4;
    UINT64 c0, c1, c2, c3, c4;
    UINT64  phys;

    c0= cr3;
    c0&= (UINT64)~0xfff;   // pml4

    i1= virt>>39;
    i2= (virt>>30)&(UINT64)0x1ff;
    i3= (virt>>21)&(UINT64)0x01ff;

    b1= (UINT64*) (c0+sizeof(UINT64)*i1);
    if((*b1&0x1)==0) {
	bprint("Mapping failed for b1\n");
        return (UINT64)-1;
    }
    c1= *b1&~(UINT64)0xfff;
    b2= (UINT64*) (c1+sizeof(UINT64)*i2);
    if((*b2&0x1)==0) {
	bprint("Mapping failed for b2\n");
        return (UINT64)-1;
    }
    c2= *b2&~(UINT64)0xfff;
    b3= (UINT64*)(c2+sizeof(UINT64)*i3);
    if((*b3&0x1)==0) {
 	bprint("Mapping failed for b3\n");
        return (UINT64)-1;
    }
    if((*b3&PS)!=0) {
    	i4= virt&(UINT64)0x01fffff;
	c3= *b3;
        c3&= ~0x01fffff;
	return c3|i4;
    }
    i4= (virt>>12)&(UINT64)0x01ff;
    i5= virt&(UINT64)0x0fff;
    c3= *b3&~(UINT64)0xfff;
    b4= (UINT64*)(c3+sizeof(UINT64)*i4);
    if((*b4&0x1)==0) {
	bprint("Mapping failed for b4\n");
        return (UINT64)-1;
    }
    c4= *b4&~(UINT64)0xfff;
    phys= c4|i5;
    return phys;
}
#endif


BOOLEAN vmcs_sw_shadow_disable[VMM_MAX_CPU_SUPPORTED];

typedef struct VMM_INPUT_PARAMS_S {
    UINT64 local_apic_id;
    UINT64 startup_struct;
    UINT64 application_params_struct; // change name
} VMM_INPUT_PARAMS;

//      globals
VMM_STARTUP_STRUCT vmm_startup_data;
CPU_ID g_num_of_cpus = 0;
static volatile UINT32 g_application_procs_may_be_launched = FALSE;
static volatile UINT32 g_application_procs_launch_the_guest = 0;
VMM_PAGING_POLICY g_pg_policy;
UINT32 g_is_post_launch = 0;

extern void *g_vmx_capabilities_ptr;
extern UINT64 g_debug_gpa;
extern UINT64 g_session_id;
extern void setup_data_for_s3(void);

UINT64 g_additional_heap_pa = 0;
UINT32 g_heap_pa_num = 0;
UINT64 g_additional_heap_base = 0;
extern BOOLEAN build_extend_heap_hpa_to_hva(void);

//      macros
#define WAIT_FOR_APPLICATION_PROCS_LAUNCH()                         \
    {while (!g_application_procs_may_be_launched) { hw_pause(); }}

#define LAUNCH_APPLICATION_PROCS()                                  \
    {hw_assign_as_barrier( &g_application_procs_may_be_launched, TRUE);}

#define WAIT_FOR_APPLICATION_PROCS_LAUNCHED_THE_GUEST( count )      \
    {while (g_application_procs_launch_the_guest != (UINT32)(count)) { hw_pause(); }}

#define APPLICATION_PROC_LAUNCHING_THE_GUEST()                      \
    {hw_interlocked_increment( (INT32*)(&g_application_procs_launch_the_guest) );}

//      forward declaration

// main for BSP - should never return.  local_apic_id is always 0
void vmm_bsp_proc_main(UINT32 local_apic_id, 
       const VMM_STARTUP_STRUCT* startup_struct,
       const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct);

// main for APs - should never return
void vmm_application_procs_main(UINT32 local_apic_id);
int cli_show_memory_layout(unsigned argc, char *args[]);
void make_guest_state_compliant(GUEST_CPU_HANDLE gcpu);

#if defined DEBUG || defined ENABLE_RELEASE_VMM_LOG
//      implementation
INLINE UINT8 lapic_id(void)
{
    CPUID_PARAMS cpuid_params;
    cpuid_params.m_rax = 1;
    hw_cpuid(&cpuid_params);
    return (UINT8) (cpuid_params.m_rbx >> 24) & 0xFF;
}
#endif

INLINE void enable_fx_ops(void)
{
    UINT64 CR0_Value = hw_read_cr0();
    BITMAP_CLR64(CR0_Value,CR0_TS);
          
    BITMAP_CLR64(CR0_Value,CR0_MP);
    hw_write_cr0(CR0_Value);
}

INLINE void enable_ept_during_launch(GUEST_CPU_HANDLE initial_gcpu)
{
    UINT64 guest_cr4;
  
    ept_acquire_lock();
    
    // Enable EPT, if it is currently not enabled
    if( !ept_is_ept_enabled(initial_gcpu) ) {
    
        ept_enable(initial_gcpu);

                //set the right pdtprs into the vmcs.
                guest_cr4 = gcpu_get_guest_visible_control_reg(initial_gcpu, IA32_CTRL_CR4);

                ept_set_pdtprs(initial_gcpu, guest_cr4);
    }
    
    ept_release_lock();
}

// Per CPU type policy setup
// Sets policies depending on host CPU features. Should be called on BSP only
void vmm_setup_cpu_specific_policies( VMM_POLICY* p_policy )
{
    CPUID_INFO_STRUCT   info;
    UINT32              cpuid_1_eax; // cpu identification

    cpuid(&info, 1); // get version info
    cpuid_1_eax = CPUID_VALUE_EAX(info);

    // WSM CPUs has ucode bug that crashes CPU if VTx is ON and CR0.CD=1
    // prevent this
    //   WSM cpu ids
    //      wsm_a0 -  0x00020650
    //      wsm_b0 -  0x00020651
    //      wsm_e0 -  0x00020654
    //      wsm_t0 -  0x000206c0
    //      wsm_u0 -  0x000206c0 - temp
    switch (cpuid_1_eax & ~0xF) {
        case 0x00020650:
        case 0x000206c0:
            VMM_LOG(mask_uvmm, level_trace,
                    "Switching ON policy to disable CR0.CD=1 settings\n");
            set_cache_policy(p_policy, POL_CACHE_DIS_VIRTUALIZATION);
            break;

        default:
            set_cache_policy(p_policy, POL_CACHE_DIS_NO_INTERVENING);
            break;
    }
}

extern void ASM_FUNCTION ITP_JMP_DEADLOOP(void);

// MAIN
// Started in parallel for all available processors
// Should never return!
void vmm_main_continue(VMM_INPUT_PARAMS* vmm_input_params)
{
    const VMM_STARTUP_STRUCT* startup_struct = (const VMM_STARTUP_STRUCT*)vmm_input_params->startup_struct;
    const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct = (const VMM_APPLICATION_PARAMS_STRUCT*)(vmm_input_params->application_params_struct);

    UINT32 local_apic_id = (UINT32)(vmm_input_params->local_apic_id);

    if (local_apic_id == 0) {
        vmm_bsp_proc_main(local_apic_id, startup_struct, application_params_struct);
    }
    else {
        vmm_application_procs_main(local_apic_id);
    }
    VMM_BREAKPOINT();
}

void vmm_main(UINT32 local_apic_id, UINT64 startup_struct_u, 
              UINT64 application_params_struct_u, UINT64 reserved UNUSED)
{
#ifdef JLMDEBUG
    bootstrap_partial_reset();
     bprint("***********************\n");
    bprint("vmm_main in 64 bit mode\n");
    bprint("local_apic_id %d, startup_struct_u %016lx\n", local_apic_id, startup_struct_u);
    bprint("application_params_struct_u %016lx, reserved  %016lx\n",
            application_params_struct_u, reserved);
#endif
    const VMM_STARTUP_STRUCT* startup_struct = 
                (const VMM_STARTUP_STRUCT*)startup_struct_u;
    HVA                       new_stack_pointer = 0;
    VMM_INPUT_PARAMS          input_params;
    CPU_ID                    cpu_id = (CPU_ID)local_apic_id;

    vmm_startup_data = *startup_struct; // save for usage during S3 resume

    {
        BOOLEAN release_mode=TRUE;
        VMM_DEBUG_CODE(release_mode = FALSE);
        if (release_mode) {
#ifdef ENABLE_RELEASE_VMM_LOG
            vmm_startup_data.debug_params.verbosity = vmm_startup_data.debug_params.verbosity && 0x1; 
            // Limits the verbosity level to 1 (level_print_always and level_error) when 
            // VMM_LOG is enabled in release build
            vmm_startup_data.debug_params.mask = vmm_startup_data.debug_params.mask & ~((1<< mask_cli)+(1<<mask_anonymous)+(1<<mask_emulator)+(1<<mask_gdb)+(1<<mask_ept)+(1<<mask_handler));
#else
            vmm_startup_data.debug_params.mask = vmm_startup_data.debug_params.mask & ~((1<< mask_cli)+(1<<mask_anonymous)+(1<<mask_emulator)+(1<<mask_gdb)+(1<<mask_ept)+(1<<mask_uvmm)+(1<<mask_tmm)+(1<<mask_tmsl)+(1<<mask_handler));
#endif
        }
    }

#ifdef JLMDEBUG
   UINT8* pbss= (UINT8*) (startup_struct->vmm_memory_layout[0].base_address+
          +startup_struct->vmm_memory_layout[0].image_size -0x4a00);
    bprint("evmm position 1\n");
    bprint("hex of bss %p\n", pbss);
    HexDump(pbss, pbss+16);
#endif

    host_cpu_enable_usage_of_xmm_regs();

    // setup stack
    if (!startup_struct || !vmm_stack_caclulate_stack_pointer(startup_struct, cpu_id, &new_stack_pointer)) {
        // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
        VMM_BREAKPOINT();
    }

    input_params.local_apic_id = local_apic_id;
    input_params.startup_struct = startup_struct_u;
    input_params.application_params_struct = application_params_struct_u;

#ifdef JLMDEBUG
    bprint("evmm position 2\n");
#endif


    hw_set_stack_pointer(new_stack_pointer, (main_continue_fn)vmm_main_continue, &input_params);
    // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
    VMM_BREAKPOINT();
}


// The Boot Strap Processor main routine
// Should never return!
void vmm_bsp_proc_main(UINT32 local_apic_id, 
                  const VMM_STARTUP_STRUCT* startup_struct,
                  const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct)
{
    HVA lowest_stacks_addr = 0;
    UINT32 stacks_size = 0;
    HVA heap_address;
    UINT32 heap_size;
    HVA heap_last_occupied_address;
    CPU_ID num_of_cpus = (CPU_ID)startup_struct->number_of_processors_at_boot_time;
    CPU_ID cpu_id = (CPU_ID)local_apic_id;
    HPA new_cr3 = 0;
    const VMM_STARTUP_STRUCT* startup_struct_heap;
    const VMM_APPLICATION_PARAMS_STRUCT* application_params_heap;
    const VMM_GUEST_STARTUP*  primary_guest_startup;
    const VMM_GUEST_STARTUP*  secondary_guests_array;
    GUEST_HANDLE nmi_owner_guest, device_default_owner_guest, acpi_owner_guest;
    UINT32 num_of_guests;
    GUEST_CPU_HANDLE initial_gcpu = NULL;
    VMM_POLICY policy;
    BOOLEAN debug_port_params_error;
    REPORT_INITIALIZATION_DATA initialization_data;
    GUEST_HANDLE   guest;
    GUEST_ECONTEXT guest_ctx;
    UINT32 i = 0;
    
#ifdef USE_ACPI
    HVA fadt_hva = 0;
#ifdef ENABLE_VTD
    HVA dmar_hva = 0;
#endif
#endif

#ifdef JLMDEBUG
    bprint("evmm position 3\n");
#endif

    // save number of CPUs
    g_num_of_cpus = num_of_cpus;

    // get post launch status
#if 0
    g_is_post_launch = (BITMAP_GET(startup_struct->flags, VMM_STARTUP_POST_OS_LAUNCH_MODE) != 0);
#else
    g_is_post_launch = 0;
#endif
    hw_calibrate_tsc_ticks_per_second();

    // Init the debug port.  If the version is too low, there's no debug parameters.
    // Use the defaults and later on assert.

    if (startup_struct->version_of_this_struct >= VMM_STARTUP_STRUCT_MIN_VERSION_WITH_DEBUG) {
        debug_port_params_error = vmm_debug_port_init_params(&startup_struct->debug_params.port);
        g_debug_gpa = startup_struct->debug_params.debug_data;
    } else {
        debug_port_params_error = vmm_debug_port_init_params(NULL);
    }

#ifdef JLMDEBUG
    bprint("evmm position 4\n");
#endif

    // init the LIBC library
    vmm_libc_init();

#ifdef JLMDEBUG
    bprint("evmm position 5\n");
#endif

    // Now we have a functional debug output
    if (debug_port_params_error) {
        VMM_LOG(mask_uvmm, level_error,
                "\nFAILURE: Loader-VMM version mismatch (no debug port parameters)\n");
        // BEFORE_VMLAUNCH. It will not happen in final Release mode
        VMM_DEADLOOP();
    };

    if(g_is_post_launch) {
        if(application_params_struct) {
            if (application_params_struct->size_of_this_struct != sizeof(VMM_APPLICATION_PARAMS_STRUCT)) {
                VMM_LOG(mask_uvmm, level_error,
                        "\nFAILURE: application params structure size mismatch)\n");
                // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
                VMM_DEADLOOP();
            };
            g_session_id = application_params_struct->session_id;
            g_heap_pa_num = (UINT32)(application_params_struct->entry_number);
            g_additional_heap_pa = application_params_struct->address_entry_list;
        }
        else
            g_session_id = 0;
    }

    // Print global version message
    vmm_version_print();

#ifdef JLMDEBUG
    bprint("evmm position 6\n");
#endif

#if 1
    VMM_LOG(mask_uvmm, level_trace,"\nBSP: uVMM image base address = %P, entry point address = %P\n", startup_struct->vmm_memory_layout[0].base_address, startup_struct->vmm_memory_layout[0].entry_point);
    VMM_LOG(mask_uvmm, level_trace,"\nBSP: Initializing all data structures...\n");
    //VMM_LOG(mask_uvmm, level_trace,"\n\nBSP: Alive.  Local APIC ID=%P\n", lapic_id());
#endif

    // check input structure
    if (startup_struct->version_of_this_struct != VMM_STARTUP_STRUCT_VERSION) {
#if 0
        VMM_LOG(mask_uvmm, level_error,
                "\nFAILURE: Loader-VMM version mismatch (init structure version mismatch)\n");
        // BEFORE_VMLAUNCH. This condition can't happen with the current
        // version. Keep the Deadloop for now.
        VMM_DEADLOOP();
#else
        bprint("startup struct wrong version\n");
#endif
    };
    if (startup_struct->size_of_this_struct != sizeof(VMM_STARTUP_STRUCT)) {
#if 0
        VMM_LOG(mask_uvmm, level_error,
                "\nFAILURE: Loader-VMM version mismatch (init structure size mismatch)\n");
        // BEFORE_VMLAUNCH. This condition can't happen with the current
        // version. Keep the Deadloop for now.
        VMM_DEADLOOP();
#else
        bprint("startup struct wrong size %d %d\n",  
               sizeof(VMM_STARTUP_STRUCT),
               startup_struct->size_of_this_struct);
#endif
    };

#ifdef JLMDEBUG
    bprint("evmm position 7\n");
#endif

    addr_setup_address_space();

#ifdef JLMDEBUG
    bprint("evmm position 8\n");
#endif

    // Initialize stack
    if (!vmm_stack_initialize(startup_struct)) {
#if 0
        VMM_LOG(mask_uvmm, level_error,
                "\nFAILURE: Stack initialization failed\n");
        // BEFORE_VMLAUNCH. Keep the Deadloop as this condition will not
        // occur with POSTLAUNCH.
        VMM_DEADLOOP();
#else
        bprint("Cant initialize stack\n");
#endif
    }

#ifdef JLMDEBUG
    bprint("evmm position 9\n");
#endif

    // BEFORE_VMLAUNCH. Redundant check as above if condition already ensures
    // this does not happen. Keep the Deadloop for now.
    VMM_ASSERT(vmm_stack_is_initialized());
    vmm_stacks_get_details(&lowest_stacks_addr, &stacks_size);
    VMM_LOG(mask_uvmm, level_trace,"\nBSP:Stacks are successfully initialized:\n");
    VMM_LOG(mask_uvmm, level_trace,"\tlowest address of all stacks area = %P\n", lowest_stacks_addr);
    VMM_LOG(mask_uvmm, level_trace,"\tsize of whole stacks area = %P\n", stacks_size);
    VMM_DEBUG_CODE(vmm_stacks_print());

    // Initialize Heap
    heap_address = lowest_stacks_addr + stacks_size;
    heap_size = (UINT32)
                ((startup_struct->vmm_memory_layout[0].base_address + 
                startup_struct->vmm_memory_layout[0].total_size) - heap_address);
    heap_last_occupied_address = vmm_heap_initialize(heap_address, heap_size);
#ifdef JLMDEBUG
    bprint("stack initialized %d\n", vmm_stack_is_initialized());
    bprint("heap_address, heap_size, heap_last_occupied_address: 0x%016lx, %ld, 0x%016lx\n", 
           heap_address, heap_size, heap_last_occupied_address);
#endif

    VMM_LOG(mask_uvmm, level_trace,"\nBSP:Heap is successfully initialized: \n");
    VMM_LOG(mask_uvmm, level_trace,"\theap base address = %P \n", heap_address);
    VMM_LOG(mask_uvmm, level_trace,"\theap last occupied address = %P \n", 
                heap_last_occupied_address);
    VMM_LOG(mask_uvmm, level_trace,"\tactual size is %P, when requested size was %P\n", 
            heap_last_occupied_address - heap_address, heap_size);
    // BEFORE_VMLAUNCH. Can't hit this condition in POSTLAUNCH. Keep the
    // ASSERT for now. 
    VMM_ASSERT(heap_last_occupied_address <= (startup_struct->vmm_memory_layout[0].base_address + startup_struct->vmm_memory_layout[0].total_size));

#ifdef JLMDEBUG
    bprint("evmm position 10\n");
#endif
    
    //  Initialize CLI monitor
    CliMonitorInit();   // must be called after heap initialization.

#ifdef JLMDEBUG
    bprint("evmm position 11\n");
#endif

    vmdb_initialize();
    vmm_serial_cli_init();

#ifdef JLMDEBUG
    bprint("evmm position 12\n");
#endif

#ifdef DEBUG
    CLI_AddCommand(
        cli_show_memory_layout,
        "debug memory layout",
        "Print overall memory layout", "",
        CLI_ACCESS_LEVEL_USER);
#endif
    VMM_LOG(mask_uvmm, level_trace,"BSP: Original VMM_STARTUP_STRUCT dump\n");
    VMM_DEBUG_CODE(
        print_startup_struct( startup_struct );
    )

    // Copy the startup data to heap.
    // After this point all pointers points to the same structure in the heap.
    startup_struct_heap = vmm_create_startup_struct_copy(startup_struct);
    startup_struct = startup_struct_heap; // overwrite the parameter;
    if (startup_struct_heap == NULL) {
        // BEFORE_VMLAUNCH. We must ASSERT if condition is false.
        VMM_DEADLOOP();
    }

#ifdef JLMDEBUG
    bprint("evmm position 13\n");
#endif

    VMM_LOG(mask_uvmm, level_trace,"BSP: Copied VMM_STARTUP_STRUCT dump\n");
    VMM_DEBUG_CODE( print_startup_struct( startup_struct ); )

    application_params_heap = vmm_create_application_params_struct_copy(application_params_struct);
    if ((application_params_struct != NULL) && (application_params_heap == NULL)) {
        // BEFORE_VMLAUNCH. Should not fail.
        VMM_DEADLOOP();
    }
    application_params_struct = application_params_heap; // overwrite the parameter

#ifdef JLMDEBUG
    bprint("evmm position 14\n");
    bprint("num of cpus: %d\n", num_of_cpus);
    uint16_t cpuid= hw_cpu_id();
    bprint("from hw_cpu_id: %04x\n", cpuid);
#endif

    // Initialize GDT for all cpus
    hw_gdt_setup(num_of_cpus);
    VMM_LOG(mask_uvmm, level_trace,"\nBSP: GDT setup is finished.\n");

#ifdef JLMDEBUG
    bprint("evmm position 15\n");
#endif

    // Load GDT for BSP
    hw_gdt_load(cpu_id);
    VMM_LOG(mask_uvmm, level_trace,"BSP: GDT is loaded.\n");

#ifdef JLMDEBUG
    bprint("evmm position 16\n");
#endif

    // Initialize IDT for all cpus
    isr_setup();
    VMM_LOG(mask_uvmm, level_trace,"\nBSP: ISR setup is finished. \n");

#ifdef JLMDEBUG
    bprint("evmm position 17\n");
#endif

    // Load IDT for BSP
    isr_handling_start();
    VMM_LOG(mask_uvmm, level_trace,"BSP: ISR handling started. \n");

#ifdef JLMDEBUG
    bprint("evmm position 18\n");
#endif

    // Store information about e820
    if (!e820_abstraction_initialize((const INT15_E820_MEMORY_MAP*)startup_struct->physical_memory_layout_E820)) {
        VMM_LOG(mask_uvmm, level_error, "BSP FAILURE: there is no proper e820 map\n");
        // BEFORE_VMLAUNCH. Should not fail.
        VMM_DEADLOOP();
    }

#ifdef JLMDEBUG
    bprint("evmm position 19\n");
#endif

    if (!mtrrs_abstraction_bsp_initialize()) {
        VMM_LOG(mask_uvmm, level_error, "BSP FAILURE: failed to cache mtrrs\n");
        // BEFORE_VMLAUNCH. Should not fail.
        VMM_DEADLOOP();
    }
    VMM_LOG(mask_uvmm, level_trace,"\nBSP: MTRRs were successfully cached.\n");

#ifdef JLMDEBUG
    bprint("evmm position 20\n");
#endif

    // init uVMM image parser
    exec_image_initialize();

#ifdef JLMDEBUG
    bprint("evmm position 21\n");
#endif

    // Initialize Host Memory Manager
    if (!hmm_initialize(startup_struct)) {
        VMM_LOG(mask_uvmm, level_error,"\nBSP FAILURE: Initialization of Host Memory Manager has failed\n");
        // BEFORE_VMLAUNCH. Should not fail.
        VMM_DEADLOOP();
    }
    VMM_LOG(mask_uvmm, level_trace,"\nBSP: Host Memory Manager was successfully initialized. \n");

#ifdef JLMDEBUG
    bprint("evmm position 22\n");
#endif

    hmm_set_required_values_to_control_registers();

    new_cr3 = hmm_get_vmm_page_tables(); // PCD and PWT bits will be 0;
    UINT64 old_cr3= hw_read_cr3();
    UINT64 old_cr4= hw_read_cr4();
#ifdef JLMDEBUG
    bprint("evmm position 22.6, new cr3: 0x%016x, old cr3: 0x%016x\n",
            new_cr3, old_cr3);
    bprint("old cr4: 0x%016lx\n", old_cr4);
    HexDump((UINT8*)new_cr3, (UINT8*)new_cr3+40);
    bprint("resetting cr3\n");
    hw_write_cr3(old_cr3);
    bprint("that worked\n");
    bprint("new map\n");
    UINT64 tvirt= 0x70000000ULL;
    UINT64 tphys= 0ULL;
    tphys= getphysical(new_cr3, tvirt);
    bprint("virt: 0x%016lx, phys: 0x%016lx\n", tvirt, tphys);
    tvirt= (UINT64) vmm_bsp_proc_main;
    tphys= getphysical(new_cr3, tvirt);
    bprint("(bsp)virt: 0x%016lx, phys: 0x%016lx\n", tvirt, tphys);
    tvirt= (UINT64) bprint;
    tphys= getphysical(new_cr3, tvirt);
    bprint("(bprint)virt: 0x%016lx, phys: 0x%016lx\n", tvirt, tphys);
    bprint("old map\n");
    tvirt= 0x70000000ULL;
    tphys= 0ULL;
    tphys= getphysical(old_cr3, tvirt);
    bprint("virt: 0x%016lx, phys: 0x%016lx\n", tvirt, tphys);
    tvirt= (UINT64) vmm_bsp_proc_main;
    tphys= getphysical(old_cr3, tvirt);
    bprint("(bsp)virt: 0x%016lx, phys: 0x%016lx\n", tvirt, tphys);
    tvirt= (UINT64) bprint;
    tphys= getphysical(old_cr3, tvirt);
    bprint("(bprint)virt: 0x%016lx, phys: 0x%016lx\n", tvirt, tphys);
#endif

    // BEFORE_VMLAUNCH. PARANOID check. Should not fail.
    VMM_ASSERT(new_cr3 != HMM_INVALID_VMM_PAGE_TABLES);
    VMM_LOG(mask_uvmm, level_trace,"BSP: New cr3=%P. \n", new_cr3);

    hw_write_cr3(new_cr3);
#ifdef JLMDEBUG
    bprint("evmm position 22.7\n");
    //LOOP_FOREVER  //reached
#endif

    VMM_LOG(mask_uvmm, level_trace,"BSP: Successfully updated CR3 to new value\n");
    // BEFORE_VMLAUNCH. PARANOID check. Should not fail.
    VMM_ASSERT(hw_read_cr3() == new_cr3);

#ifdef JLMDEBUG
    bprint("evmm position 23\n");
#endif

#if 0
    // Allocates memory from heap for s3 resume structure on AP's
    // This should be called before calling vmm_heap_extend() in order to
    // ensure identity mapped memory within 4GB for post-OS launch.
    // Upon heap extending, the memory allocated may be arbitrary mapped.
#ifdef ENABLE_PM_S3
    setup_data_for_s3();
#endif
    if (g_is_post_launch) {
        // To create [0~4G] identity mapping
        // on NO UG machines (NHM), FPT will be used to handle guest non-paged protected mode.
        // aka. CR0.PE = 1, CR0.PG = 0 
        // make sure the 32bit FPT pagetables located below 4G physical memory.
        // assume that GPA-HPA mapping won't be changed. 
        // those page tables are cached.
        if( !is_unrestricted_guest_supported()){
            BOOLEAN  fpt_32bit_ok = 
                      fpt_create_32_bit_flat_page_tables_under_4G((UINT64) 4 GIGABYTES - 1 ); 
            VMM_ASSERT(fpt_32bit_ok);
            VMM_LOG(mask_uvmm, level_trace,"BSP: Successfully created 32bit FPT tables and cached them\n");    
        }   

#ifdef JLMDEBUG
    bprint("evmm position 24\n");
#endif
        
        init_teardown_lock();
        VMM_LOG(mask_uvmm, level_trace,"VMM: Image and stack used %dKB memory.\n",
            ((UINT64)heap_address - startup_struct->vmm_memory_layout[uvmm_image].base_address)/(1024));

#ifdef JLMDEBUG
    bprint("evmm position 25\n");
#endif

        // BEFORE_VMLAUNCH. Should not fail.
        VMM_ASSERT(g_additional_heap_base != 0);
        heap_last_occupied_address = vmm_heap_extend( g_additional_heap_base, 
                                        g_heap_pa_num * PAGE_4KB_SIZE);

#ifdef JLMDEBUG
    bprint("evmm position 26\n");
#endif

        if (g_additional_heap_pa)
            build_extend_heap_hpa_to_hva();
    }
    VMM_DEBUG_CODE ( vmm_trace_init(VMM_MAX_GUESTS_SUPPORTED, num_of_cpus) );
#endif

#ifdef PCI_SCAN
    host_pci_initialize();
#endif

#ifdef JLMDEBUG
    UINT64 m1=  hw_read_msr(IA32_MSR_VMCS_REVISION_IDENTIFIER_INDEX);
    bprint("evmm position 27, msr: 0x%016lx\n", m1);
    uint16_t cpuid2= hw_cpu_id();
    bprint("from hw_cpu_id: %04x\n", cpuid2);
    bprint("Phys addr for virtual %p is %p\n", 
           (UINT64)g_vmx_capabilities_ptr, 
           getphysical(new_cr3, g_vmx_capabilities_ptr));
#endif
    vmcs_hw_init();

#ifdef JLMDEBUG
    bprint("evmm position 28\n");
#endif

    // BEFORE_VMLAUNCH. REDUNDANT as this check is already done in POSTLAUNCH.
    VMM_ASSERT( vmcs_hw_is_cpu_vmx_capable() );

    // init CR0/CR4 to the VMX compatible values
    UINT64 old_cr0= hw_read_cr0();
    UINT64 new_cr0= vmcs_hw_make_compliant_cr0(old_cr0);
#ifdef JLMDEBUG
    bprint("evmm position 28, old_cr0: 0x%016lx, new_cr0: 0x%016lx\n",
           old_cr0, new_cr0);
#endif
    hw_write_cr0(new_cr0);  
    if(g_is_post_launch) {
        // clear TS bit, since we need to operate on XMM registers.
        enable_fx_ops();
    }

#ifdef JLMDEBUG
    bprint("evmm position 29\n");
#endif
    hw_write_cr4(  vmcs_hw_make_compliant_cr4( hw_read_cr4() ) );
    num_of_guests = startup_struct->number_of_secondary_guests + 1;

#ifdef JLMDEBUG
    bprint("evmm position 30\n");
#endif

    // TODO: remove the compile time policy
    clear_policy(&policy);

#ifdef JLMDEBUG
    bprint("evmm position 31\n");
#endif

#ifdef VTLB_IS_SUPPORTED
    set_paging_policy(&policy, ept_is_ept_supported() ? POL_PG_EPT: POL_PG_VTLB);
#else
    if (ept_is_ept_supported()) {
        set_paging_policy(&policy, POL_PG_EPT);
    }
    else {
        VMM_LOG(mask_uvmm, level_error,"BSP: EPT is not supported\n");

        // BEFORE_VMLAUNCH. REDUNDANT as this check is already done in
        // POSTLAUNCH.
        VMM_DEADLOOP();
    }
#endif

#ifdef JLMDEBUG
    bprint("evmm position 32\n");
#endif

    vmm_setup_cpu_specific_policies( &policy );
    global_policy_setup(&policy);
#ifdef JLMDEBUG
    bprint("evmm position 33\n");
#endif
    scheduler_init( (UINT16)num_of_cpus );
#ifdef JLMDEBUG
    bprint("evmm position 34\n");
    LOOP_FOREVER
#endif
    host_cpu_manager_init( num_of_cpus );
#ifdef JLMDEBUG
    bprint("evmm position 35\n");
#endif
    guest_manager_init( (UINT16)num_of_cpus, (UINT16)num_of_cpus );
#ifdef JLMDEBUG
    bprint("evmm position 36\n");
#endif
    local_apic_init( (UINT16)num_of_cpus );
#ifdef JLMDEBUG
    bprint("evmm position 37\n");
#endif

    // tmsl profiling
    TMSL_PROFILING_INIT((UINT16)num_of_cpus );

    // create VMEXIT-related data
    vmexit_initialize();

#ifdef JLMDEBUG
    bprint("evmm position 38\n");
#endif
    // init current host CPU
    host_cpu_init();
#ifdef JLMDEBUG
    bprint("evmm position 39\n");
#endif
    local_apic_cpu_init();
#ifdef JLMDEBUG
    bprint("evmm position 40\n");
#endif

#ifdef ENABLE_PREEMPTION_TIMER
    vmx_timer_hw_setup();   // called on every CPU
#endif

#ifdef INCLUDE_UNUSED_CODE
    // init device drivers manager
    ddm_initialize();
#endif
    // create guests
    VMM_LOG(mask_uvmm, level_trace,"BSP: Create guests\n");
#ifdef JLMDEBUG
    bprint("evmm position 41\n");
#endif

    primary_guest_startup =
        (const VMM_GUEST_STARTUP*)startup_struct->primary_guest_startup_state;
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(primary_guest_startup);

    secondary_guests_array =
        (const VMM_GUEST_STARTUP*)startup_struct->secondary_guests_startup_state_array;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT((num_of_guests == 1) || (secondary_guests_array != 0));

    if (! initialize_all_guests(num_of_cpus, 
#if 0
                                (int) startup_struct->num_excluded_regions, startup_struct->vmm_memory_layout,
#else
                                &(startup_struct->vmm_memory_layout[0]),
#endif
                                primary_guest_startup, num_of_guests - 1,
                                secondary_guests_array, application_params_heap)) {
        VMM_LOG(mask_uvmm, level_error,"BSP: Error initializing guests. Halt.\n");
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_DEADLOOP();
    }
#ifdef JLMDEBUG
    bprint("evmm position 42\n");
    LOOP_FOREVER
#endif

    VMM_LOG(mask_uvmm, level_trace,"BSP: Guests created succefully. Number of guests: %d\n", guest_count());

    // should be set only after guests initialized
    vmm_set_state(VMM_STATE_BOOT);

    // get important guest ids
    nmi_owner_guest = guest_handle_by_magic_number(startup_struct->nmi_owner);
    acpi_owner_guest = guest_handle_by_magic_number(startup_struct->acpi_owner);
    device_default_owner_guest = guest_handle_by_magic_number(startup_struct->default_device_owner);

    // BEFORE_VMLAUNCH. PARANOID check as we have only one guest.
    VMM_ASSERT(nmi_owner_guest);
    // BEFORE_VMLAUNCH. PARANOID check as we have only one guest.
    VMM_ASSERT(acpi_owner_guest);
    // BEFORE_VMLAUNCH. PARANOID check as we have only one guest.
    VMM_ASSERT(device_default_owner_guest);

    guest_set_nmi_owner(nmi_owner_guest);
    guest_set_acpi_owner(acpi_owner_guest);
    guest_set_default_device_owner(device_default_owner_guest);

    VMM_LOG(mask_uvmm, level_trace,"BSP: NMI owning guest ID=%d \tMagic Number = %#x\n",
                        guest_get_id(nmi_owner_guest), guest_magic_number(nmi_owner_guest));
    VMM_LOG(mask_uvmm, level_trace,"BSP: ACPI owning guest ID=%d \tMagic Number = %#x\n",
                        guest_get_id(acpi_owner_guest), guest_magic_number(acpi_owner_guest));
    VMM_LOG(mask_uvmm, level_trace,"BSP: Default device owning guest ID=%d \tMagic Number = %#x\n",
                        guest_get_id(device_default_owner_guest),
                        guest_magic_number(device_default_owner_guest));

    // Initialize Event Manager
    // must be called after heap and CLI initialization
    event_manager_initialize(num_of_cpus);
#ifdef PCI_SCAN
    gpci_initialize();
#endif
    // init IPC engine
#ifdef OLD_IPC
    if (!ipc_initialize(num_of_cpus))
#else
    if (!nmi_manager_initialize(num_of_cpus))
#endif
    {
        VMM_LOG(mask_uvmm, level_trace,"\nFAILURE: IPC initialization failed\n");
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_DEADLOOP();
    }
    for(i=0; i < VMM_MAX_CPU_SUPPORTED; i++)
        vmcs_sw_shadow_disable[i] = FALSE;

    if(g_is_post_launch) {
#ifdef USE_ACPI  
        if (INVALID_PHYSICAL_ADDRESS == application_params_struct->fadt_gpa ||
                !gpm_gpa_to_hva(gcpu_get_current_gpm(acpi_owner_guest), 
                (GPA)(application_params_struct->fadt_gpa), &fadt_hva))
            fadt_hva = 0;
#ifdef ENABLE_VTD
        if (INVALID_PHYSICAL_ADDRESS == application_params_struct->dmar_gpa || 
                !gpm_gpa_to_hva(gcpu_get_current_gpm(acpi_owner_guest), 
                (GPA)(application_params_struct->dmar_gpa), &dmar_hva))
            dmar_hva = 0;
#endif
#endif
    }

#ifdef USE_ACPI
    vmm_acpi_init(fadt_hva);
#endif

#ifdef ENABLE_VTD
    vtd_initialize( &(startup_struct->vmm_memory_layout[uvmm_image]),application_params_heap, dmar_hva);
#endif //ENABLE_VTD

    // init all addon packages
    start_addons(num_of_cpus, startup_struct_heap, application_params_heap);

    // Destroy startup structures, which reside in heap
    vmm_destroy_startup_struct(startup_struct_heap);
    startup_struct = NULL;
    startup_struct_heap = NULL;

    vmm_destroy_application_params_struct(application_params_heap);
    application_params_struct = NULL;
    application_params_heap = NULL;

    // TODO: global var - init finished

    vmcs_hw_allocate_vmxon_regions(num_of_cpus);

    // Initialize guest data
    initialization_data.num_of_cpus = (UINT16) num_of_cpus;
    for (i = 0; i < VMM_MAX_GUESTS_SUPPORTED; i++) {
        initialization_data.guest_data[i].guest_id = INVALID_GUEST_ID;
        initialization_data.guest_data[i].primary_guest = FALSE;
    }
    if (num_of_guests > VMM_MAX_GUESTS_SUPPORTED) {
        VMM_LOG(mask_uvmm, level_error, "%s: %d guests not supported by VMM.\n", __FUNCTION__, num_of_guests);
    } else {
        for (guest = guest_first(&guest_ctx), i = 0; guest; guest = guest_next(&guest_ctx), i++) {
            initialization_data.guest_data[i].guest_id = guest_get_id(guest);
            if (guest_is_primary(guest)) {
                initialization_data.guest_data[i].primary_guest = TRUE;
            }
        }
    }
    if (!report_uvmm_event(UVMM_EVENT_INITIALIZATION_BEFORE_APS_STARTED, NULL, NULL, 
                            (void *)&initialization_data)) {
        VMM_LOG(mask_uvmm, level_trace, "report_initialization failed before the APs have started\n");
    }
    VMM_LOG(mask_uvmm, level_trace,"BSP: Successfully finished single-core initializations\n");

    vmm_set_state(VMM_STATE_WAIT_FOR_APs);
    LAUNCH_APPLICATION_PROCS();
    initialize_host_vmcs_regions(cpu_id);
    VMM_LOG(mask_uvmm, level_trace,"BSP: Successfully finished initializations\n");
    vmcs_hw_vmx_on();
    VMM_LOG(mask_uvmm, level_trace,"BSP: VMXON\n");

    // schedule first gcpu
    initial_gcpu = scheduler_select_initial_gcpu();

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(initial_gcpu != NULL);
    VMM_LOG(mask_uvmm, level_trace,"BSP: initial guest selected: GUEST_ID: %d GUEST_CPU_ID: %d\n",
            guest_vcpu( initial_gcpu )->guest_id, guest_vcpu( initial_gcpu )->guest_cpu_id );

    ipc_change_state_to_active(initial_gcpu);
    vmm_print_test(local_apic_id);
    VMM_LOG(mask_uvmm, level_trace,"BSP: Wait for APs to launch the first Guest CPU\n");
    WAIT_FOR_APPLICATION_PROCS_LAUNCHED_THE_GUEST( num_of_cpus - 1 );

    // Assumption: initialization_data was not changed
    if (!report_uvmm_event(UVMM_EVENT_INITIALIZATION_AFTER_APS_STARTED, 
                     (VMM_IDENTIFICATION_DATA)initial_gcpu, (const GUEST_VCPU*)guest_vcpu(initial_gcpu), 
                     (void *)&initialization_data)) {
        VMM_LOG(mask_uvmm, level_trace, "report_initialization failed after the APs have launched the guest\n");
    }

    vmm_set_state(VMM_STATE_RUN);
    VMM_LOG(mask_uvmm, level_trace,"BSP: Resuming the first Guest CPU\n");
    event_raise(EVENT_GUEST_LAUNCH, initial_gcpu, &local_apic_id);

    // enable unrestricted guest support in early boot
    // make guest state compliant for code execution
    // On systems w/o UG, emulator takes care of it
    if(is_unrestricted_guest_supported()) {
        make_guest_state_compliant(initial_gcpu);
        unrestricted_guest_enable(initial_gcpu);
        //make_guest_state_compliant(initial_gcpu);
    } else {
        // For non-UG systems enable EPT, if guest is in paging mode
        EM64T_CR0 guest_cr0;
        guest_cr0.Uint64 = gcpu_get_guest_visible_control_reg(initial_gcpu,IA32_CTRL_CR0);
        if (guest_cr0.Bits.PG) {
            enable_ept_during_launch(initial_gcpu);
        }
    }
#ifdef FAST_VIEW_SWITCH
    if(fvs_is_eptp_switching_supported()) {
        fvs_guest_vmfunc_enable(initial_gcpu);
        fvs_vmfunc_vmcs_init(initial_gcpu);     
    }
#endif

    vmcs_store_initial(initial_gcpu, cpu_id);
    gcpu_resume( initial_gcpu );
    VMM_LOG(mask_uvmm, level_error,"BSP: Resume initial guest cpu failed\n", cpu_id);
    VMM_DEADLOOP();
}

// The Application Processor main routine
// Should never return!
void vmm_application_procs_main(UINT32 local_apic_id)
{
    CPU_ID cpu_id = (CPU_ID)local_apic_id;
    HPA new_cr3 = 0;
    GUEST_CPU_HANDLE initial_gcpu = NULL;

    WAIT_FOR_APPLICATION_PROCS_LAUNCH();
    VMM_LOG(mask_uvmm, level_trace,"\n\nAP%d: Alive.  Local APIC ID=%P\n", cpu_id, lapic_id());

    // Load GDT/IDT
    hw_gdt_load(cpu_id);
    VMM_LOG(mask_uvmm, level_trace,"AP%d: GDT is loaded.\n", cpu_id);
    isr_handling_start();
    VMM_LOG(mask_uvmm, level_trace,"AP%d: ISR handling started.\n", cpu_id);

    if (!mtrrs_abstraction_ap_initialize()) {
        VMM_LOG(mask_uvmm, level_error,"AP%d FAILURE: Failed to cache MTRRs\n", cpu_id);
        VMM_DEADLOOP();
    }
    VMM_LOG(mask_uvmm, level_trace,"AP%d: MTRRs were successfully cached\n", cpu_id);

    // Set new CR3 to VMM page tables
    hmm_set_required_values_to_control_registers();
    new_cr3 = hmm_get_vmm_page_tables();
    VMM_ASSERT(new_cr3 != HMM_INVALID_VMM_PAGE_TABLES);
    VMM_LOG(mask_uvmm, level_trace,"AP%d: New cr3=%P. \n", cpu_id, new_cr3);
    hw_write_cr3(new_cr3);
    VMM_LOG(mask_uvmm, level_trace,"AP%d: Successfully updated CR3 to new value\n", cpu_id);
    VMM_ASSERT(hw_read_cr3() == new_cr3);

    VMM_ASSERT( vmcs_hw_is_cpu_vmx_capable() );

    // init CR0/CR4 to the VMX compatible values
    hw_write_cr0(  vmcs_hw_make_compliant_cr0( hw_read_cr0() ) );
    if(g_is_post_launch) {
       // clear TS bit, since we need to operate on XMM registers.
       enable_fx_ops();
    }
    hw_write_cr4(  vmcs_hw_make_compliant_cr4( hw_read_cr4() ) );

    // init current host CPU
    host_cpu_init();
    local_apic_cpu_init();

    initialize_host_vmcs_regions( cpu_id );
    VMM_LOG(mask_uvmm, level_trace,"AP%d: Successfully finished initializations\n", cpu_id);

    vmcs_hw_vmx_on();
    VMM_LOG(mask_uvmm, level_trace,"AP%d: VMXON\n", cpu_id);

    // schedule first gcpu
    initial_gcpu = scheduler_select_initial_gcpu();
    VMM_ASSERT( initial_gcpu != NULL );
    VMM_LOG(mask_uvmm, level_trace,"AP%d: initial guest selected: GUEST_ID: %d GUEST_CPU_ID: %d\n",
            cpu_id, guest_vcpu( initial_gcpu )->guest_id, guest_vcpu( initial_gcpu )->guest_cpu_id );

    ipc_change_state_to_active( initial_gcpu );
    vmm_print_test(local_apic_id);
    APPLICATION_PROC_LAUNCHING_THE_GUEST();
    VMM_LOG(mask_uvmm, level_trace,"AP%d: Resuming the first Guest CPU\n", cpu_id);
    //VMM_DEADLOOP();

    event_raise(EVENT_GUEST_LAUNCH, initial_gcpu, &local_apic_id);

    // enable unrestricted guest support in early boot
    // make guest state compliant for code execution
    // On systems w/o UG, emulator takes care of it
    if(is_unrestricted_guest_supported()) {
        make_guest_state_compliant(initial_gcpu);
        unrestricted_guest_enable(initial_gcpu);
        //make_guest_state_compliant(initial_gcpu);
    } else {
        // For non-UG systems enable EPT, if guest is in paging mode
        EM64T_CR0 guest_cr0;
        guest_cr0.Uint64 = gcpu_get_guest_visible_control_reg(initial_gcpu,IA32_CTRL_CR0);
        if (guest_cr0.Bits.PG) {
            enable_ept_during_launch(initial_gcpu);
        }
    }
#ifdef FAST_VIEW_SWITCH
    if ( fvs_is_eptp_switching_supported() ) {
        fvs_guest_vmfunc_enable(initial_gcpu);
        fvs_vmfunc_vmcs_init(initial_gcpu);
    }
#endif

    vmcs_store_initial(initial_gcpu, cpu_id);
    gcpu_resume( initial_gcpu );
    VMM_LOG(mask_uvmm, level_error,"AP%d: Resume initial guest cpu failed\n", cpu_id);
    VMM_DEADLOOP();
}

void make_guest_state_compliant(GUEST_CPU_HANDLE initial_gcpu)
{
    UINT16            selector;
    UINT64            base;
    UINT32            limit;
    UINT32            attr;
    UINT32            idx;
    UINT64            cr0;

    cr0 =  gcpu_get_guest_visible_control_reg(initial_gcpu, IA32_CTRL_CR0);
    if (!(cr0 & CR0_PE)) {
        // for guest to execute real mode code
        // its state needs to be in certain way
        // this code enforces it
        for (idx = IA32_SEG_CS; idx < IA32_SEG_COUNT; ++idx) {
            gcpu_get_segment_reg(initial_gcpu, (VMM_IA32_SEGMENT_REGISTERS)idx, &selector, &base, &limit, &attr);
            make_segreg_hw_real_mode_compliant(initial_gcpu, selector, base, limit, attr, (VMM_IA32_SEGMENT_REGISTERS)idx);
        }
        VMM_LOG(mask_uvmm, level_info,"BSP: guest compliant in real mode  for UG early boot.\n");
    }
}

#ifdef DEBUG
int cli_show_memory_layout(unsigned argc UNUSED, char *args[] UNUSED)
{
    CLI_PRINT(" Memory Layout :      uVMM        :      Thunk\n");
    CLI_PRINT("---------------:------------------:-----------------\n");
    CLI_PRINT(" Base Address  : %16P : %16P\n",
            vmm_startup_data.vmm_memory_layout[uvmm_image].base_address,
            vmm_startup_data.vmm_memory_layout[thunk_image].base_address);
    CLI_PRINT(" Entry Point   : %16P : %16P\n",
            vmm_startup_data.vmm_memory_layout[uvmm_image].entry_point,
            vmm_startup_data.vmm_memory_layout[thunk_image].entry_point);
    CLI_PRINT(" Image Size    : %16P : %16P\n",
            vmm_startup_data.vmm_memory_layout[uvmm_image].image_size,
            vmm_startup_data.vmm_memory_layout[thunk_image].image_size);
    CLI_PRINT(" Total Size    : %16P : %16P\n",
            vmm_startup_data.vmm_memory_layout[uvmm_image].total_size,
            vmm_startup_data.vmm_memory_layout[thunk_image].total_size);
    return 0;
}
#endif
