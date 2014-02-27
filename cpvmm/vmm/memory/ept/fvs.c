/*
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
 */

#ifdef FAST_VIEW_SWITCH
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(FVS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(FVS_C, __condition)
#include "vmcs_init.h"
#include "ept.h"
#include "ept_hw_layer.h"
#include "host_memory_manager_api.h"
#include "scheduler.h"
#include "vmx_asm.h"
#include "ipc.h"
#include "vmx_ctrl_msrs.h"
#include "..\..\guest\guest_internal.h"
#include "..\..\guest\guest_cpu\guest_cpu_internal.h"
#include "isr.h"
#include "guest_cpu_vmenter_event.h"
#include "fvs.h"
#include "vmm_callback.h"
#include "common_types.h"
#include "profiling.h"

static
void fvs_init_eptp_switching(GUEST_DESCRIPTOR *guest);
static
HPA fvs_get_eptp_list_paddress(GUEST_CPU_HANDLE gcpu);
static
void fvs_enable_eptp_switching(CPU_ID from UNUSED,void* arg);
static
void fvs_disable_eptp_switching(CPU_ID from UNUSED,void* arg);

extern UINT32 vmexit_reason(void);
extern BOOLEAN vmcs_sw_shadow_disable[];

void fvs_initialize(GUEST_HANDLE guest, UINT32 number_of_host_processors)
{

    guest->fvs_desc = (FVS_DESCRIPTOR *) vmm_malloc(sizeof(FVS_DESCRIPTOR));

    VMM_ASSERT(guest->fvs_desc);
    guest->fvs_desc->num_of_cpus = number_of_host_processors;
    guest->fvs_desc->dummy_eptp_address = 0;
    guest->fvs_desc->eptp_list_paddress = vmm_malloc(sizeof(HPA) * number_of_host_processors);
    guest->fvs_desc->eptp_list_vaddress = vmm_malloc(sizeof(HVA) * number_of_host_processors);

    VMM_LOG(mask_anonymous, level_trace,
         "fvs desc allocated...=0x%016lX\n", guest->fvs_desc);
    fvs_init_eptp_switching(guest);
}

static
void fvs_init_eptp_switching(GUEST_DESCRIPTOR *guest)
{
    UINT32 i;

    for(i = 0; i < guest->fvs_desc->num_of_cpus; i++) {
        guest->fvs_desc->eptp_list_vaddress[i] = (HVA)vmm_page_alloc(1);
        vmm_memset((UINT64 *)guest->fvs_desc->eptp_list_vaddress[i], 0, PAGE_4KB_SIZE);
        VMM_ASSERT(guest->fvs_desc->eptp_list_vaddress[i]);
        if ( !hmm_hva_to_hpa(guest->fvs_desc->eptp_list_vaddress[i],
             &guest->fvs_desc->eptp_list_paddress[i]) ) {
            VMM_LOG(mask_anonymous, level_error,
                    "%s:(%d):ASSERT: HVA to HPA conversion failed\n",
                    __FUNCTION__, __LINE__);
            VMM_DEADLOOP();
        }
        VMM_LOG(mask_anonymous, level_trace,
                "eptp list allocated...vaddr=0x%016lX paddr=0x%016lX\n",
                guest->fvs_desc->eptp_list_vaddress[i],
                guest->fvs_desc->eptp_list_paddress[i]);
    }
}

BOOLEAN fvs_is_eptp_switching_supported(void)
{
    const VMCS_HW_CONSTRAINTS *hw_constraints = vmcs_hw_get_vmx_constraints();

    return (hw_constraints->eptp_switching_supported);
}

void fvs_guest_vmfunc_enable(GUEST_CPU_HANDLE gcpu)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 ctrls2;
    VMEXIT_CONTROL request;

    ctrls2.Uint32 = 0;
    vmm_zeromem(&request, sizeof(request));

    ctrls2.Bits.Vmfunc = 1;
    request.proc_ctrls2.bit_mask    = ctrls2.Uint32;
    request.proc_ctrls2.bit_request = UINT64_ALL_ONES;
    gcpu_control2_setup( gcpu, &request );
}

static
HPA fvs_get_eptp_list_paddress(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
    const VIRTUAL_CPU_ID *vcpuid = guest_vcpu(gcpu);

    VMM_ASSERT(guest);
    VMM_ASSERT(guest->fvs_desc);
    VMM_ASSERT(vcpuid);

    return(guest->fvs_desc->eptp_list_paddress[vcpuid->guest_cpu_id]);
}

BOOLEAN fvs_add_entry_to_eptp_list(GUEST_HANDLE guest,
                    HPA ept_root_hpa, UINT32 gaw, UINT64 index)
{
    UINT64 *hva = NULL;
    EPTP eptp;
    UINT32 ept_gaw = 0, i;

    VMM_ASSERT(guest->fvs_desc);
    
    if ( index < MAX_EPTP_ENTRIES ) {
        ept_gaw =  ept_hw_get_guest_address_width(gaw);
        if(ept_gaw == (UINT32) -1)
        {
            return FALSE;
        }
        eptp.Uint64 = ept_root_hpa;
        eptp.Bits.ETMT = ept_hw_get_ept_memory_type();
        eptp.Bits.GAW = ept_hw_get_guest_address_width_encoding(ept_gaw);
        eptp.Bits.Reserved = 0;
        VMM_LOG(mask_anonymous, level_trace,
            "adding eptp entry eptp=0x%016lX index=%d\n", eptp.Uint64, index);
    }
    else {
    	return FALSE;
    }

    for(i = 0; i < guest->fvs_desc->num_of_cpus; i++) {
        hva = (UINT64 *)guest->fvs_desc->eptp_list_vaddress[i];
        *(hva + index) = eptp.Uint64;
    }
    return TRUE;
}

BOOLEAN fvs_delete_entry_from_eptp_list(GUEST_HANDLE guest, UINT64 index)
{
    UINT64 *hva = NULL;
    UINT32 i;

    VMM_ASSERT(guest->fvs_desc);

    if ( index < MAX_EPTP_ENTRIES ) {
        VMM_LOG(mask_anonymous, level_trace,
    	    "deleting eptp entry at index=%d\n", index);
    }
    else {
    	return FALSE;
    }

    for(i = 0; i < guest->fvs_desc->num_of_cpus; i++) {
        hva = (UINT64 *)guest->fvs_desc->eptp_list_vaddress[i];
        *(hva + index) = 0;
    }

    return TRUE;
}

void fvs_vmfunc_vmcs_init(GUEST_CPU_HANDLE gcpu)
{
    UINT64 value;
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);

    value = vmcs_read(vmcs, VMCS_VMFUNC_CONTROL);
    VMM_LOG(mask_anonymous, level_trace,
                  "HW Vmfunc ctrl read value = 0x%016lX\n", value);
    BIT_CLR(value, EPTP_SWITCHING_BIT);
    VMM_LOG(mask_anonymous, level_trace,
                  "HW Vmfunc ctrl bitclr value = 0x%016lX\n", value);
    vmcs_write(vmcs, VMCS_VMFUNC_CONTROL, value);
    VMM_LOG(mask_anonymous, level_trace,
                  "EPTP switching disabled...0x%016lX\n", value);
}
#pragma warning( push )
#pragma warning (disable : 4100) // disable non-referenced formal parameters
static
void fvs_enable_eptp_switching(CPU_ID from UNUSED,void* arg)
{
    UINT64 value = 0;
    GUEST_HANDLE guest = (GUEST_HANDLE) arg;
    GUEST_CPU_HANDLE gcpu  =
                    scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    
    if ( fvs_is_eptp_switching_supported() ) {
        value = vmcs_read(vmcs, VMCS_VMFUNC_CONTROL);
        BIT_SET(value, EPTP_SWITCHING_BIT);
        vmcs_write(vmcs, VMCS_VMFUNC_CONTROL, value);
        vmcs_write(vmcs, VMCS_VMFUNC_EPTP_LIST_ADDRESS, 
                              fvs_get_eptp_list_paddress(gcpu));
    }
    
    gcpu->fvs_cpu_desc.enabled = TRUE;
    
    VMM_LOG(mask_anonymous, level_trace,
                    "EPTP switching enabled by IB-agent...0x%016lX\n", value);
}

static
void fvs_disable_eptp_switching(CPU_ID from UNUSED,void* arg)
{
    UINT64 value = 0;
    GUEST_HANDLE guest = (GUEST_HANDLE) arg;
    GUEST_CPU_HANDLE gcpu  =
                       scheduler_get_current_gcpu_for_guest(guest_get_id(guest));
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    
    if ( fvs_is_eptp_switching_supported() ) {    
        value = vmcs_read(vmcs, VMCS_VMFUNC_CONTROL);
        BIT_CLR(value, EPTP_SWITCHING_BIT);
        vmcs_write(vmcs, VMCS_VMFUNC_CONTROL, value);
        vmcs_write(vmcs, VMCS_VMFUNC_EPTP_LIST_ADDRESS, 0);
    }
    gcpu->fvs_cpu_desc.enabled = FALSE;
    VMM_LOG(mask_anonymous, level_trace,
                   "EPTP switching disabled by IB-agent...0x%016lX\n", value);
}
#pragma warning( pop )

void fvs_enable_fvs(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE guest = gcpu_guest_handle(gcpu);
    const VIRTUAL_CPU_ID *vcpuid = guest_vcpu(gcpu);
    UINT16 gcpu_id = 0;
    IPC_DESTINATION ipc_dest;

    VMM_ASSERT(vcpuid);
    VMM_ASSERT(guest->fvs_desc);
    gcpu_id = vcpuid->guest_cpu_id;
    
    fvs_enable_eptp_switching(gcpu_id, guest);
    vmm_zeromem(&ipc_dest, sizeof(ipc_dest));
    ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
    ipc_execute_handler_sync(ipc_dest, fvs_enable_eptp_switching, guest);

    VMM_LOG(mask_anonymous, level_trace,"Fast view switch enabled...\n");
}

void fvs_disable_fvs(GUEST_CPU_HANDLE gcpu)
{
	GUEST_HANDLE guest = gcpu_guest_handle(gcpu);
    const VIRTUAL_CPU_ID *vcpuid = guest_vcpu(gcpu);
    UINT16 gcpu_id = 0;
    IPC_DESTINATION ipc_dest;

    //paranoid check. If assertion fails, possible memory corruption.
    VMM_ASSERT(guest);
    VMM_ASSERT(vcpuid);
    VMM_ASSERT(guest->fvs_desc);
    gcpu_id = vcpuid->guest_cpu_id;

    fvs_disable_eptp_switching(gcpu_id, guest);
    vmm_zeromem(&ipc_dest, sizeof(ipc_dest));
    ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
    ipc_execute_handler_sync(ipc_dest, fvs_disable_eptp_switching, guest);

    VMM_LOG(mask_anonymous, level_trace,
                           "Fast view switch disabled...\n");
}

BOOLEAN fvs_is_fvs_enabled(GUEST_CPU_HANDLE gcpu)
{
    return (gcpu->fvs_cpu_desc.enabled);
}

UINT64 fvs_get_eptp_entry(GUEST_CPU_HANDLE gcpu, UINT64 index)
{
    GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
    const VIRTUAL_CPU_ID *vcpuid = guest_vcpu(gcpu);
    UINT64 *hva = NULL;

    VMM_ASSERT(guest);
    VMM_ASSERT(guest->fvs_desc);
    VMM_ASSERT(vcpuid);
    hva = (UINT64 *)guest->fvs_desc->eptp_list_vaddress[vcpuid->guest_cpu_id];

    if ( index < MAX_EPTP_ENTRIES ) {
         return(*(hva + index));
    } else {
        return(0);
    }
}

HPA *fvs_get_all_eptp_list_paddress(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE guest = gcpu_guest_handle(gcpu);

    VMM_ASSERT(guest);
    VMM_ASSERT(guest->fvs_desc);

    return guest->fvs_desc->eptp_list_paddress;
}

void fvs_save_resumed_eptp(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT  *vmcs = gcpu_get_vmcs(gcpu);

    gcpu->fvs_cpu_desc.vmentry_eptp = vmcs_read(vmcs, VMCS_EPTP_ADDRESS);

}

void fvs_vmexit_handler(GUEST_CPU_HANDLE gcpu)
{
    UINT64 r_eax, r_ecx, leptp;
    const VIRTUAL_CPU_ID* vcpu_id;
    REPORT_SET_ACTIVE_EPTP_DATA set_active_eptp_data;
    REPORT_FAST_VIEW_SWITCH_DATA fast_view_switch_data;
    VMCS_OBJECT  *vmcs;

    if (vmexit_reason() != Ia32VmxExitBasicReasonVmcallInstruction)
        return;

    VMM_ASSERT(gcpu);

    r_eax = gcpu_get_native_gp_reg(gcpu, IA32_REG_RAX);

    /* Check whether we drop because of fast view switch */
    if (r_eax != FAST_VIEW_SWITCH_LEAF)
        return;

    TMSL_PROFILING_API_ENTRY(TMSL_X_VMCALL_FVS, PROF_API_CALLER_IB);

    r_ecx = gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);
    vcpu_id = guest_vcpu( gcpu );
    /* Check whether view is valid */
    leptp = fvs_get_eptp_entry(gcpu, r_ecx); 
    set_active_eptp_data.eptp_list_index = r_ecx;
    set_active_eptp_data.update_hw = FALSE;
    if(leptp &&                           
        report_uvmm_event(UVMM_EVENT_SET_ACTIVE_EPTP, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), &set_active_eptp_data)) {
        VMM_LOG(mask_anonymous, level_trace,
                "Switch ept called %d\n", r_ecx);
        vmcs = gcpu_get_vmcs(gcpu);
        vmcs_write( vmcs, VMCS_EPTP_ADDRESS, leptp);
        gcpu_skip_guest_instruction(gcpu);
        nmi_window_update_before_vmresume(vmcs);
    }
    else {
        /* View is invalid report to handler */

        VMM_LOG(mask_anonymous, level_trace,
                "%s: view id=%d.Invalid view id requested.\n",
                __FUNCTION__,r_ecx);

        fast_view_switch_data.reg = r_ecx;
        report_uvmm_event(UVMM_EVENT_INVALID_FAST_VIEW_SWITCH, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&fast_view_switch_data);
        nmi_window_update_before_vmresume(gcpu_get_vmcs(gcpu));
        
    }
    TMSL_PROFILING_API_EXIT(TMSL_X_VMCALL_FVS, PROF_API_CALLER_IB);
    vmentry_func( FALSE );
} 

#endif

#ifdef INCLUDE_UNUSED_CODE
static 
void fvs_print_eptp_list(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE    guest = gcpu_guest_handle(gcpu);
    const VIRTUAL_CPU_ID *vcpuid = guest_vcpu(gcpu);
    UINT64 *hva;
    UINT64 index;

    VMM_ASSERT(vcpuid);
    hva = (UINT64 *)guest->fvs_desc->eptp_list_vaddress[vcpuid->guest_cpu_id];

    VMM_LOG(mask_anonymous, level_print_always,"\n");
    for(index=0;index<TOTAL_NUM_VIEWS;index++) {
        VMM_LOG(mask_anonymous, 
           level_print_always,"entry at index %d = 0x%016lX\n", 
           index, *(hva + index));
    }
    VMM_LOG(mask_anonymous, level_print_always,"\n");
}

#endif
