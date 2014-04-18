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

#include "host_cpu.h"
#include "guest_cpu.h"
#include "heap.h"
#include "vmx_trace.h"
#include "vmcs_api.h"
#include "vmcs_init.h"
#include "libc.h"
#include "gpm_api.h"
#include "host_memory_manager_api.h"
#include "hw_utils.h"
#include "vmx_asm.h"
#include "vmm_stack_api.h"
#include "scheduler.h"
#include "hw_utils.h"
#include "em64t_defs.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(HOST_CPU_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(HOST_CPU_C, __condition)

//
// Host CPU model for VMCS
//

//          types

#pragma PACK_ON

// Minimum size of allocated MSR list
#define MIN_SIZE_OF_MSR_LIST  4


//#define USE_SYSENTER_STACK

#ifdef USE_SYSENTER_STACK
    #define SYSENTER_STACK_SIZE 16
#endif

// main save area
typedef struct _HOST_CPU_SAVE_AREA {
    HVA     vmxon_region_hva;
    HPA     vmxon_region_hpa;

    UINT16  state_flags;
    UINT8   padding0[6];

    IA32_VMX_MSR_ENTRY*   vmexit_msr_load_list;
    UINT32  vmexit_msr_load_count;
    UINT32  max_vmexit_msr_load_count;
    GUEST_CPU_HANDLE last_vmexit_gcpu;

    UINT64 host_dr7;
    // must be aligned on 16-byte boundary
    //ALIGN16 UINT8       fxsave_area[512];
#ifdef USE_SYSENTER_STACK
    ALIGN16(ADDRESS, sysenter_stack[SYSENTER_STACK_SIZE]);
#endif
} PACKED HOST_CPU_SAVE_AREA;

#pragma PACK_OFF

typedef enum _HOST_CPU_FLAGS {
    HCPU_VMX_IS_ON_FLAG = 0, // VMXON was executed
} HOST_CPU_FLAGS;

#define SET_VMX_IS_ON_FLAG( hcpu )  BIT_SET( (hcpu)->state_flags, HCPU_VMX_IS_ON_FLAG)
#define CLR_VMX_IS_ON_FLAG( hcpu )  BIT_CLR( (hcpu)->state_flags, HCPU_VMX_IS_ON_FLAG)
#define GET_VMX_IS_ON_FLAG( hcpu )  BIT_GET( (hcpu)->state_flags, HCPU_VMX_IS_ON_FLAG)

//          globals
static HOST_CPU_SAVE_AREA*   g_host_cpus = NULL;
static UINT16                g_max_host_cpus = 0;

#ifdef USE_SYSENTER_STACK
//          internal funcs
static void sysenter_func( void )
{
    VMM_LOG(mask_anonymous, level_trace,"sysenter_func CALLED!!!!!!");
    VMM_DEADLOOP();
}
#endif


extern BOOLEAN is_cr4_osxsave_supported(void);

void host_cpu_manager_init( UINT16 max_host_cpus )
{
    // BEFORE_VMLAUNCH. PARANOID check.
    VMM_ASSERT( max_host_cpus );

    g_max_host_cpus = max_host_cpus;
    g_host_cpus = vmm_memory_alloc( sizeof( HOST_CPU_SAVE_AREA ) * max_host_cpus );

    // BEFORE_VMLAUNCH. MALLOC should not fail.
    VMM_ASSERT( g_host_cpus );
}


static void host_cpu_add_msr_to_vmexit_load_list(CPU_ID cpu, UINT32 msr_index, UINT64 msr_value)
{
    HOST_CPU_SAVE_AREA*  hcpu = &g_host_cpus[cpu];
    BOOLEAN              update_gcpus = FALSE;
    IA32_VMX_MSR_ENTRY*  new_msr_ptr = NULL;
    UINT32               i = 0;

    // Check if MSR is already in the list.
    if (hcpu->vmexit_msr_load_list != NULL) {
        for (i = 0, new_msr_ptr = hcpu->vmexit_msr_load_list; i < hcpu->vmexit_msr_load_count; i++, new_msr_ptr++)
            if (new_msr_ptr->MsrIndex == msr_index)
                break;
    }
    else
        i = hcpu->vmexit_msr_load_count;

    if (i >= hcpu->vmexit_msr_load_count) {
        if  (hcpu->vmexit_msr_load_list == NULL || hcpu->vmexit_msr_load_count >= hcpu->max_vmexit_msr_load_count)
        {
            // The list is full or not allocated, expand it
            UINT32               new_max_count = MAX(hcpu->max_vmexit_msr_load_count * 2, MIN_SIZE_OF_MSR_LIST);
            UINT32               new_size = sizeof(IA32_VMX_MSR_ENTRY) * new_max_count;
            IA32_VMX_MSR_ENTRY*  new_list = vmm_malloc_aligned(new_size, sizeof(IA32_VMX_MSR_ENTRY));
            UINT32               i;

            if (new_list == NULL) {
                VMM_LOG(mask_anonymous, level_trace,"%s: Memory allocation failed\n", __FUNCTION__);
                // BEFORE_VMLAUNCH. MALLOC should not fail.
                VMM_DEADLOOP();
            }

            // Copy the old list.
            for (i = 0; i < hcpu->vmexit_msr_load_count; i++) {
                new_list[i] = hcpu->vmexit_msr_load_list[i];
            }

            // Free the old list.
            if (hcpu->vmexit_msr_load_list != NULL)
                vmm_mfree(hcpu->vmexit_msr_load_list);

            // Assign the new one.
            hcpu->vmexit_msr_load_list = new_list;
            hcpu->max_vmexit_msr_load_count = new_max_count;

            update_gcpus = TRUE;
        }

        new_msr_ptr = &hcpu->vmexit_msr_load_list[hcpu->vmexit_msr_load_count++];
    }

    VMM_ASSERT(new_msr_ptr);
    new_msr_ptr->MsrIndex = msr_index;
    new_msr_ptr->Reserved = 0;
    new_msr_ptr->MsrData = msr_value;

    if (update_gcpus) {
        SCHEDULER_GCPU_ITERATOR iter;
        GUEST_CPU_HANDLE gcpu;

        gcpu = scheduler_same_host_cpu_gcpu_first(&iter, cpu);
        while (gcpu != NULL)
        {
            gcpu_change_level0_vmexit_msr_load_list(gcpu, hcpu->vmexit_msr_load_list, hcpu->vmexit_msr_load_count);

            gcpu = scheduler_same_host_cpu_gcpu_next(&iter);
        }
    }
}

#ifdef INCLUDE_UNUSED_CODE
void host_cpu_add_msr_to_level0_autoswap(CPU_ID cpu, UINT32 msr_index) {
    SCHEDULER_GCPU_ITERATOR iter;
    GUEST_CPU_HANDLE gcpu;
    UINT64 msr_value = hw_read_msr(msr_index);

    gcpu = scheduler_same_host_cpu_gcpu_first(&iter, cpu);
    while (gcpu != NULL) {
        VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy( gcpu ), VMCS_LEVEL_0);

        vmcs_add_msr_to_vmexit_store_and_vmenter_load_lists(vmcs, msr_index, msr_value);

        gcpu = scheduler_same_host_cpu_gcpu_next(&iter);
    }

    host_cpu_add_msr_to_vmexit_load_list(cpu, msr_index, msr_value);
}


void host_cpu_delete_msr_from_vmexit_load_list(CPU_ID cpu, UINT32 msr_index)
{
    HOST_CPU_SAVE_AREA*  hcpu = &g_host_cpus[cpu];
    BOOLEAN              update_gcpus = FALSE;
    IA32_VMX_MSR_ENTRY*  msr_ptr = NULL;
    UINT32               i = 0, j = 0;
    UINT32               msrs_to_copy;

    // Check if MSR is in the list.
    if (hcpu->vmexit_msr_load_list != NULL && hcpu->vmexit_msr_load_count != 0) {
        for (i = 0, msr_ptr = hcpu->vmexit_msr_load_list; 
             i < hcpu->vmexit_msr_load_count; i++, msr_ptr++) {
            if (msr_ptr->MsrIndex == msr_index) {
                // New list size.
                hcpu->vmexit_msr_load_count--;
                // Shift the rest of a list by one up.
                for (j = 0, msrs_to_copy = hcpu->vmexit_msr_load_count - i; 
                     j < msrs_to_copy; j++) {
                    msr_ptr[j] = msr_ptr[j + 1];
                }
                update_gcpus = TRUE;
                break;
            }
        }
    }

    if (update_gcpus) {
        SCHEDULER_GCPU_ITERATOR  iter;
        GUEST_CPU_HANDLE         gcpu;

        gcpu = scheduler_same_host_cpu_gcpu_first(&iter, cpu);

        while (gcpu != NULL) {
            gcpu_change_level0_vmexit_msr_load_list(gcpu, hcpu->vmexit_msr_load_list, 
                                                    hcpu->vmexit_msr_load_count);
            gcpu = scheduler_same_host_cpu_gcpu_next(&iter);
        }
    }
}


void host_cpu_delete_msr_from_level0_autoswap(CPU_ID cpu, UINT32 msr_index)
{
    SCHEDULER_GCPU_ITERATOR iter;
    GUEST_CPU_HANDLE gcpu;

    gcpu = scheduler_same_host_cpu_gcpu_first(&iter, cpu);

    while (gcpu != NULL) {
        VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy( gcpu ), VMCS_LEVEL_0);
        vmcs_delete_msr_from_vmexit_store_and_vmenter_load_lists(vmcs, msr_index);
        gcpu = scheduler_same_host_cpu_gcpu_next(&iter);
    }
    host_cpu_delete_msr_from_vmexit_load_list(cpu, msr_index);
}
#endif

void host_cpu_init_vmexit_store_and_vmenter_load_msr_lists_according_to_vmexit_load_list(
            GUEST_CPU_HANDLE gcpu) {
    CPU_ID cpu = hw_cpu_id();
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    UINT32 i;
    VMM_ASSERT(vmcs);
    vmcs_clear_vmexit_store_list(vmcs);
    vmcs_clear_vmenter_load_list(vmcs);

    //    VMM_ASSERT(g_host_cpus[cpu].vmexit_msr_load_count > 0);
    VMM_ASSERT(g_host_cpus);
    for (i = 0; i < g_host_cpus[cpu].vmexit_msr_load_count; i++) {
        vmcs_add_msr_to_vmexit_store_and_vmenter_load_lists(vmcs, g_host_cpus[cpu].vmexit_msr_load_list[i].MsrIndex,
                                                            g_host_cpus[cpu].vmexit_msr_load_list[i].MsrData);
    }
}

//
// Initialize current host cpu
//
void host_cpu_init( void )
{
#ifdef USE_SYSENTER_STACK
    CPU_ID              cpu_id = hw_cpu_id();
    HOST_CPU_SAVE_AREA* hcpu = &(g_host_cpus[cpu_id]);
#endif

#ifdef USE_SYSENTER_STACK
    hw_write_msr(IA32_MSR_SYSENTER_CS, hw_read_cs());
    hw_write_msr(IA32_MSR_SYSENTER_EIP, (ADDRESS)sysenter_func);
    hw_write_msr(IA32_MSR_SYSENTER_ESP, (ADDRESS)(hcpu->sysenter_stack + SYSENTER_STACK_SIZE - 5));
#else
    hw_write_msr(IA32_MSR_SYSENTER_CS, 0);
    hw_write_msr(IA32_MSR_SYSENTER_EIP, 0 );
    hw_write_msr(IA32_MSR_SYSENTER_ESP, 0);
#endif

    {
        CPU_ID              cpu = hw_cpu_id();
        HOST_CPU_SAVE_AREA* host_cpu = &(g_host_cpus[cpu]);

        host_cpu->vmexit_msr_load_list = NULL;
        host_cpu->vmexit_msr_load_count = 0;
        host_cpu->max_vmexit_msr_load_count = 0;

        if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.SaveDebugControls != 1) {
            host_cpu_add_msr_to_vmexit_load_list(cpu, IA32_MSR_DEBUGCTL, hw_read_msr(IA32_MSR_DEBUGCTL));
        }
        if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.SaveSysEnterMsrs != 1) {
            host_cpu_add_msr_to_vmexit_load_list(cpu, IA32_MSR_SYSENTER_ESP, hw_read_msr(IA32_MSR_SYSENTER_ESP));
            host_cpu_add_msr_to_vmexit_load_list(cpu, IA32_MSR_SYSENTER_EIP, hw_read_msr(IA32_MSR_SYSENTER_EIP));
            host_cpu_add_msr_to_vmexit_load_list(cpu, IA32_MSR_SYSENTER_CS, hw_read_msr(IA32_MSR_SYSENTER_CS));
        }
        if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.SaveEfer != 1) {
            host_cpu_add_msr_to_vmexit_load_list(cpu, IA32_MSR_EFER, hw_read_msr(IA32_MSR_EFER));
        }
        if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.SavePat != 1) {
            host_cpu_add_msr_to_vmexit_load_list(cpu, IA32_MSR_PAT, hw_read_msr(IA32_MSR_PAT));
        }
        if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.Load_IA32_PERF_GLOBAL_CTRL != 1) {
            host_cpu_add_msr_to_vmexit_load_list(cpu, IA32_MSR_PERF_GLOBAL_CTRL, hw_read_msr(IA32_MSR_PERF_GLOBAL_CTRL));
        }
    }
}

// Init VMCS host cpu are for the target cpu. May be executed on any other CPU
void host_cpu_vmcs_init( GUEST_CPU_HANDLE gcpu)
{
    HPA                     host_msr_load_addr = 0;
    VMCS_OBJECT*            vmcs;

    EM64T_GDTR              gdtr;
    EM64T_IDT_DESCRIPTOR    idtr;
    HVA                     gcpu_stack;
    CPU_ID                  cpu;
    VM_EXIT_CONTROLS        exit_controls;
    ADDRESS                 base;
    UINT32                  limit;
    UINT32                  attributes;
    VMEXIT_CONTROL          vmexit_control;
    BOOLEAN                 success;
    VMM_STATUS              status;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( gcpu );

    exit_controls.Uint32 = 0;
    vmm_memset(&vmexit_control, 0, sizeof(vmexit_control));

    cpu = hw_cpu_id();
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( cpu < g_max_host_cpus );

    vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy( gcpu ), VMCS_LEVEL_0);
    //vmcs = gcpu_get_vmcs(gcpu);

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( vmcs );

    //  Control Registers
    vmcs_write(vmcs, VMCS_HOST_CR0, vmcs_hw_make_compliant_cr0(hw_read_cr0()));
    vmcs_write(vmcs, VMCS_HOST_CR3, hw_read_cr3());

    if(is_cr4_osxsave_supported()){
        EM64T_CR4 cr4_mask;
        cr4_mask.Uint64 = 0;
        cr4_mask.Bits.OSXSAVE = 1;
        vmcs_write(vmcs, VMCS_HOST_CR4, vmcs_hw_make_compliant_cr4(hw_read_cr4()|
            (vmcs_read(vmcs,VMCS_GUEST_CR4) & cr4_mask.Uint64)));
    } else {
        vmcs_write(vmcs, VMCS_HOST_CR4, vmcs_hw_make_compliant_cr4(hw_read_cr4()));
    }


    /*
     *  EIP, ESP
     */
    vmcs_write(vmcs, VMCS_HOST_RIP, (UINT64)vmexit_func);
    success = vmm_stack_get_stack_pointer_for_cpu(cpu, &gcpu_stack);
    VMM_ASSERT(success == TRUE);
    vmcs_write(vmcs, VMCS_HOST_RSP, gcpu_stack);

    /*
     *  Base-address fields for FS, GS, TR, GDTR, and IDTR (64 bits each).
     */
    hw_sgdt(&gdtr);
    vmcs_write( vmcs, VMCS_HOST_GDTR_BASE, gdtr.base );

    hw_sidt(&idtr);
    vmcs_write( vmcs, VMCS_HOST_IDTR_BASE, idtr.base );

    /*
     *  FS (Selector + Base)
     */
    status = hw_gdt_parse_entry((UINT8 *) gdtr.base, hw_read_fs(), &base, &limit, &attributes);
    VMM_ASSERT(status == VMM_OK);
    vmcs_write(vmcs, VMCS_HOST_FS_SELECTOR, hw_read_fs());
    vmcs_write(vmcs, VMCS_HOST_FS_BASE, base);

    /*
     *  GS (Selector + Base)
     */
    status = hw_gdt_parse_entry((UINT8 *) gdtr.base, hw_read_gs(), &base, &limit, &attributes);
    VMM_ASSERT(status == VMM_OK);
    vmcs_write(vmcs, VMCS_HOST_GS_SELECTOR, hw_read_gs());
    vmcs_write(vmcs, VMCS_HOST_GS_BASE, base);

    /*
     *  TR (Selector + Base)
     */
    status = hw_gdt_parse_entry((UINT8 *) gdtr.base, hw_read_tr(), &base, &limit, &attributes);
    VMM_ASSERT(status == VMM_OK);
    vmcs_write(vmcs, VMCS_HOST_TR_SELECTOR, hw_read_tr());
    vmcs_write(vmcs, VMCS_HOST_TR_BASE, base);

    /*
     *  Selector fields (16 bits each) for the segment registers CS, SS, DS, ES, FS, GS, and TR
     */
    vmcs_write(vmcs, VMCS_HOST_CS_SELECTOR, hw_read_cs());
    vmcs_write(vmcs, VMCS_HOST_SS_SELECTOR, hw_read_ss());
    vmcs_write(vmcs, VMCS_HOST_DS_SELECTOR, hw_read_ds());
    vmcs_write(vmcs, VMCS_HOST_ES_SELECTOR, hw_read_es());

    /*
     *  MSRS
     */
    if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.LoadSysEnterMsrs == 1) {
        vmcs_write(vmcs, VMCS_HOST_SYSENTER_CS, hw_read_msr(IA32_MSR_SYSENTER_CS));
        vmcs_write(vmcs, VMCS_HOST_SYSENTER_ESP, hw_read_msr(IA32_MSR_SYSENTER_ESP));
        vmcs_write(vmcs, VMCS_HOST_SYSENTER_EIP, hw_read_msr(IA32_MSR_SYSENTER_EIP));
    }

    if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.LoadEfer == 1) {
        vmcs_write(vmcs, VMCS_HOST_EFER, hw_read_msr(IA32_MSR_EFER));
    }

    if(vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl.Bits.LoadPat == 1) {
        vmcs_write(vmcs, VMCS_HOST_PAT, hw_read_msr(IA32_MSR_PAT));
    }

    exit_controls.Bits.Ia32eModeHost = 1;
    vmexit_control.vm_exit_ctrls.bit_request = exit_controls.Uint32;
    vmexit_control.vm_exit_ctrls.bit_mask = exit_controls.Uint32;
    gcpu_control_setup( gcpu, &vmexit_control );

    VMM_ASSERT(g_host_cpus);
    if (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE) {
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT(vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy( gcpu ), VMCS_MERGED) == vmcs)
        if ((g_host_cpus[cpu].vmexit_msr_load_count != 0) && (!hmm_hva_to_hpa((HVA)g_host_cpus[cpu].vmexit_msr_load_list, &host_msr_load_addr))) {
            VMM_LOG(mask_anonymous, level_trace,"%s:(%d):ASSERT: HVA to HPA conversion failed\n", __FUNCTION__, __LINE__);
            VMM_DEADLOOP();
        }
    }
    else {
        // Address remains HVA
        host_msr_load_addr = (UINT64)g_host_cpus[cpu].vmexit_msr_load_list;
    }

        // Assigning VMExit msr-load list
        vmcs_assign_vmexit_msr_load_list(vmcs, host_msr_load_addr, g_host_cpus[cpu].vmexit_msr_load_count);
}


// Set/Get VMXON Region pointer for the current CPU
void host_cpu_set_vmxon_region( HVA hva, HPA hpa, CPU_ID my_cpu_id)
{
    HOST_CPU_SAVE_AREA* hcpu = NULL;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( g_host_cpus );
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( my_cpu_id < g_max_host_cpus );
    hcpu = &(g_host_cpus[my_cpu_id]);
    hcpu->vmxon_region_hva = hva;
    hcpu->vmxon_region_hpa = hpa;
}

HVA  host_cpu_get_vmxon_region( HPA* hpa )
{
    CPU_ID              my_cpu_id = hw_cpu_id();
    HOST_CPU_SAVE_AREA* hcpu = NULL;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( g_host_cpus );
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( my_cpu_id < g_max_host_cpus );
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( hpa );

    hcpu = &(g_host_cpus[my_cpu_id]);

    *hpa = hcpu->vmxon_region_hpa;
    return hcpu->vmxon_region_hva;
}

void host_cpu_set_vmx_state( BOOLEAN value )
{
    CPU_ID              my_cpu_id = hw_cpu_id();
    HOST_CPU_SAVE_AREA* hcpu = NULL;

    VMM_ASSERT( g_host_cpus );
    VMM_ASSERT( my_cpu_id < g_max_host_cpus );

    hcpu = &(g_host_cpus[my_cpu_id]);
    if (value) {
        SET_VMX_IS_ON_FLAG( hcpu );
    }
    else {
        CLR_VMX_IS_ON_FLAG( hcpu );
    }
}

BOOLEAN host_cpu_get_vmx_state( void )
{
    CPU_ID              my_cpu_id = hw_cpu_id();
    HOST_CPU_SAVE_AREA* hcpu = NULL;

    VMM_ASSERT( g_host_cpus );
    VMM_ASSERT( my_cpu_id < g_max_host_cpus );

    hcpu = &(g_host_cpus[my_cpu_id]);

    return GET_VMX_IS_ON_FLAG( hcpu ) ? TRUE : FALSE;
}

void host_cpu_enable_usage_of_xmm_regs( void )
{
    EM64T_CR4                 cr4;

    // allow access to XMM registers (compiler assumes this for 64bit code)
    cr4.Uint64 = hw_read_cr4();
    cr4.Bits.OSFXSR = 1;
    hw_write_cr4( cr4.Uint64 );
}

void host_cpu_store_vmexit_gcpu(CPU_ID cpu_id, GUEST_CPU_HANDLE gcpu)
{
    if (cpu_id < g_max_host_cpus) {
        g_host_cpus[cpu_id].last_vmexit_gcpu = gcpu;

        VMM_DEBUG_CODE( vmm_trace(gcpu, "\n");)
    }
}

GUEST_CPU_HANDLE host_cpu_get_vmexit_gcpu(CPU_ID cpu_id)
{
    GUEST_CPU_HANDLE gcpu = NULL;

    if (cpu_id < g_max_host_cpus) {
        gcpu = g_host_cpus[cpu_id].last_vmexit_gcpu;
    }
    return gcpu;
}

/*
 *  Purpose: At VMEXIT DR7 is always overwrittern with 400h. This prevents to set
 *           hardware breakponits in host-running code across VMEXIT/VMENTER transitions.
 *           Two functions below allow to keep DR7, set by external debugger in cpu context,
 *           and apply it to hardware upon VMEXIT.
 */

void host_cpu_save_dr7(CPU_ID cpu_id)
{
    VMM_ASSERT(g_host_cpus);
    if (cpu_id < g_max_host_cpus) {
        g_host_cpus[cpu_id].host_dr7 = hw_read_dr(7);
    }
}

void host_cpu_restore_dr7(CPU_ID cpu_id)
{
    if (cpu_id < g_max_host_cpus) {
        if (0 != g_host_cpus[cpu_id].host_dr7) {
            hw_write_dr(7, g_host_cpus[cpu_id].host_dr7);
        }
    }
}

