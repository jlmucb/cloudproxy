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

#ifndef _VMX_TEARDOWN_H_
#define _VMX_TEARDOWN_H_

#include "vmm_defs.h"
#include "vmm_objects.h"
#include "guest_cpu.h"
#include "vmcall_api.h"
#include "guest.h"
#include "gpm_api.h"
#include "guest_cpu.h"
#include "hw_vmx_utils.h"
#include "em64t_defs.h"
#include "hw_utils.h"
#include "ia32_defs.h"
#include "vmcs_init.h"
#include "host_memory_manager_api.h"
#include "vtd.h"
#include "vmm_dbg.h"
#include "hw_interlocked.h"

//8-Byte aligned
typedef struct VMM_TEARDOWN_PARAMS_S {
    UINT32  padding_four_bytes;
    UINT8   is_guest_x64_mode;           // guest mode: 1: x64 mode, 0: 32bit mode.
    UINT8   padding;
    UINT16  size_of_this_structure;      // size_of_this_structure 
	
	UINT64  session_id;                  // IN	
    UINT64  teardownthunk_gva;               // IN, teardown thunk entry of guest virtual address.
    UINT64  teardown_buffer_size;        // IN, teardown buffer size.
    UINT64  teardown_buffer_gva;         // IN, teardown buffer virtual address.
    UINT64  guest_states_storage_virt_addr;  // IN, virtual address of this guest states storage.
	UINT64  cr3_td_sm_32;					// IN, CR3 for teardown shared memory for 32 bits mode.
	UINT64  nonce;
} VMM_TEARDOWN_PARAMS;

// 53 - 8 bytes fields in the structure
// 424 bytes per core
// So for 80 cores, it requires 9 pages

typedef struct VMM_TEARDOWN_GUEST_STATES_S{
    UINT64 SIZE_OF_THIS_STRUCTURE;

    // gdtr contents    
    // if x64 -> EM64T_GDTR
    // else ia32 -> IA32_GDTR
    UINT64 GUEST_GDTR_LO;  
    UINT64 GUEST_GDTR_HI;

    // idtr contents    
    // if x64 -> EM64T_IDT_DESCRIPTOR
    // else ia32 -> IA32_IDT_DESCRIPTOR
    UINT64 GUEST_IDTR_LO;  
    UINT64 GUEST_IDTR_HI;

    // temp stack pointer used to switch cs
    UINT64 TEMP_STACK_POINTER;

    UINT64 ADDR_OF_TEARDOWN_THUNK;
    
    // general purpose registers
	UINT64 IA32_GP_RAX;
	UINT64 IA32_GP_RBX;
	UINT64 IA32_GP_RCX;
	UINT64 IA32_GP_RDX;
	UINT64 IA32_GP_RDI;
	UINT64 IA32_GP_RSI;
	UINT64 IA32_GP_RBP;
	UINT64 IA32_GP_RSP;
	UINT64 IA32_GP_R8;
	UINT64 IA32_GP_R9;
	UINT64 IA32_GP_R10;
	UINT64 IA32_GP_R11;
	UINT64 IA32_GP_R12;
	UINT64 IA32_GP_R13;
	UINT64 IA32_GP_R14;
	UINT64 IA32_GP_R15;

	UINT64 IA32_REG_RIP;
	UINT64 IA32_INSTR_LENTH;  // instruction length to the next one. 
	UINT64 IA32_REG_RFLAGS;

	// control registers
	UINT64 IA32_CR0;
	UINT64 IA32_CR3;
	UINT64 IA32_CR4;
	UINT64 IA32_CR8;

	// debug register
	UINT64 IA32_DR7;

	// segment
	UINT64 IA32_ES_SELECTOR;
	UINT64 IA32_CS_SELECTOR;
	UINT64 IA32_SS_SELECTOR;
	UINT64 IA32_DS_SELECTOR;
	UINT64 IA32_FS_SELECTOR;	
	UINT64 IA32_GS_SELECTOR;	
	UINT64 IA32_LDTR_SELECTOR;	
	UINT64 IA32_TR_SELECTOR;
	UINT64 IA32_GDTR_BASE;
	UINT64 IA32_GDTR_LIMIT;
	UINT64 IA32_IDTR_BASE;
	UINT64 IA32_IDTR_LIMIT;
	

	UINT64 IA32_MSR_DEBUG_CTL;
	UINT64 IA32_MSR_SYSENT_CS;
	UINT64 IA32_MSR_SYSENT_ESP;
	UINT64 IA32_MSR_SYSENT_EIP;

	//This field is supported only on logical processors that support the 1-setting of the 
	//"load IA32_PERF_GLOBAL_CTRL" VM-entry control.
	UINT64 IA32_MSR_PERF_GLB_CTL;
	

	//This field is supported only on logical processors that support the 1-setting of the 
	//"load IA32_PAT" VM-entry control.
	UINT64 IA32_MSR_PAT_REG;
	

	//This field is supported only on logical processors that support the 1-setting of the 
	//"load IA32_EFER" VM-entry control.
	UINT64 IA32_MSR_EFER_REG;
	

	// smbase
	UINT64 IA32_SMBASE; 

	// fs_base and gs_base
	UINT64 IA32_FS_BASE;		
	UINT64 IA32_GS_BASE;		
}VMM_TEARDOWN_GUEST_STATES;


#define COMPATIBILITY_CODE32_CS CODE32_GDT_ENTRY_OFFSET

// asm function
int  
call_teardown_thunk32( 
                     UINT64 current_guest_states_phy_addr,    // the virtual addr of storing current guest states.
                     UINT16 compatibility_cs,                 // code segement selector for compatitiliby mode.
                     UINT64 teardown_thunk_entry_phy_addr,    // virtual address of teardown thunk entry.
                     UINT64  cr3_td_sm_32,					  // CR3 for teardown shared memory for 32 bits mode
                     BOOLEAN cr4_is_pae_on                    // PAE mode flag
);

int  
call_teardown_thunk64(
                     UINT32 current_cpu_idx ,		        // cpuidx 
                     UINT64 current_guest_states_hva,		// the host virtual address of storing current guest states. 
                     UINT64 teardown_thunk_entry_hva		// teardown thunk host virtual address
                    );

void init_teardown_lock(void);
BOOLEAN vmexit_vmm_teardown(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_PARAMS *vmm_teardown_params);
BOOLEAN vmam_add_to_host_page_table(IN GUEST_CPU_HANDLE gcpu, IN UINT64 start_gva, IN UINT64 num_pages);

#endif
