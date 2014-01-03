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

#ifndef _VMM_API_H
#define _VMM_API_H

#include "vmm_defs.h"
#include "host_memory_manager_api.h"
#include "memory_address_mapper_api.h"
#include "list.h"
#ifdef VTLB_IS_SUPPORT
#include "vtlb_view.h"
#endif
#include "vmm_dbg.h"
#include "lock.h"
#include "fvs.h"
#include "ve.h"
#include "msr_defs.h"
#include "ipc.h"

// Control States
typedef enum {
    VMM_VPID                           = 0, //read/w directly
    VMM_EPTP_INDEX,
    VMM_CONTROL_VECTOR_PIN_EVENTS,
    VMM_CONTROL_VECTOR_PROCESSOR_EVENTS, // Special case - NmiWindow cannot be updated
                                         // using this value. Use special APIs to update
                                         // NmiWindow setting
    VMM_CONTROL2_VECTOR_PROCESSOR_EVENTS,
    VMM_EXCEPTION_BITMAP,
    VMM_CR3_TARGET_COUNT,
    VMM_CR0_MASK,
    VMM_CR4_MASK,
    VMM_CR0_READ_SHADOW,
    VMM_CR4_READ_SHADOW,
    VMM_PAGE_FAULT_ERROR_CODE_MASK,
    VMM_PAGE_FAULT_ERROR_CODE_MATCH,
    VMM_EXIT_CONTROL_VECTOR,
    VMM_EXIT_MSR_STORE_COUNT,
    VMM_EXIT_MSR_LOAD_COUNT,
    VMM_ENTER_CONTROL_VECTOR,
    VMM_ENTER_INTERRUPT_INFO,
    VMM_ENTER_EXCEPTION_ERROR_CODE,
    VMM_ENTER_INSTRUCTION_LENGTH,
    VMM_ENTER_MSR_LOAD_COUNT,
    VMM_IO_BITMAP_ADDRESS_A,
    VMM_IO_BITMAP_ADDRESS_B,
    VMM_MSR_BITMAP_ADDRESS,
    VMM_EXIT_MSR_STORE_ADDRESS,
    VMM_EXIT_MSR_LOAD_ADDRESS,
    VMM_ENTER_MSR_LOAD_ADDRESS,
    VMM_OSV_CONTROLLING_VMCS_ADDRESS,
    VMM_TSC_OFFSET,
    VMM_EXIT_INFO_GUEST_PHYSICAL_ADDRESS, //read only
    VMM_EXIT_INFO_INSTRUCTION_ERROR_CODE,
    VMM_EXIT_INFO_REASON,
    VMM_EXIT_INFO_EXCEPTION_INFO,
    VMM_EXIT_INFO_EXCEPTION_ERROR_CODE,
    VMM_EXIT_INFO_IDT_VECTORING,
    VMM_EXIT_INFO_IDT_VECTORING_ERROR_CODE,
    VMM_EXIT_INFO_INSTRUCTION_LENGTH,
    VMM_EXIT_INFO_INSTRUCTION_INFO,
    VMM_EXIT_INFO_QUALIFICATION,
    VMM_EXIT_INFO_IO_RCX,
    VMM_EXIT_INFO_IO_RSI,
    VMM_EXIT_INFO_IO_RDI,
    VMM_EXIT_INFO_IO_RIP,
    VMM_EXIT_INFO_GUEST_LINEAR_ADDRESS,//read only
    VMM_VIRTUAL_APIC_ADDRESS,
    VMM_APIC_ACCESS_ADDRESS,
    VMM_EXIT_TPR_THRESHOLD,
    VMM_EPTP_ADDRESS,
    VMM_CR3_TARGET_VALUE_0,
    VMM_CR3_TARGET_VALUE_1,
    VMM_CR3_TARGET_VALUE_2,
    VMM_CR3_TARGET_VALUE_3,
#ifdef FAST_VIEW_SWITCH
    VMM_VMFUNC_CONTROL,
    VMM_VMFUNC_EPTP_LIST_ADDRESS,
#endif
    //last
    NUM_OF_VMM_CONTROL_STATE
} VMM_CONTROL_STATE;

// Guest States
typedef enum {
    // START: GPRs
    /* GPRs should be at the start of this structure. Their value should match
     * the value in VMM_IA32_GP_REGISTERS structure.
     */
    VMM_GUEST_IA32_GP_RAX = 0,
    VMM_GUEST_IA32_GP_RBX,
    VMM_GUEST_IA32_GP_RCX,
    VMM_GUEST_IA32_GP_RDX,
    VMM_GUEST_IA32_GP_RDI,
    VMM_GUEST_IA32_GP_RSI,
    VMM_GUEST_IA32_GP_RBP,
    VMM_GUEST_IA32_GP_RSP,
    VMM_GUEST_IA32_GP_R8,
    VMM_GUEST_IA32_GP_R9,
    VMM_GUEST_IA32_GP_R10,
    VMM_GUEST_IA32_GP_R11,
    VMM_GUEST_IA32_GP_R12,
    VMM_GUEST_IA32_GP_R13,
    VMM_GUEST_IA32_GP_R14,
    VMM_GUEST_IA32_GP_R15,
    // END: GPRs
    // START: VMCS GUEST fields
    /* The following VMCS fields should match the VMCS_GUEST_xxx fields in
     * VMCS_FIELD structure.
     */
    VMM_GUEST_CR0,
    VMM_GUEST_CR3,
    VMM_GUEST_CR4,
    VMM_GUEST_DR7,
    VMM_GUEST_ES_SELECTOR,
    VMM_GUEST_ES_BASE,
    VMM_GUEST_ES_LIMIT,
    VMM_GUEST_ES_AR,
    VMM_GUEST_CS_SELECTOR,
    VMM_GUEST_CS_BASE,
    VMM_GUEST_CS_LIMIT,
    VMM_GUEST_CS_AR,
    VMM_GUEST_SS_SELECTOR,
    VMM_GUEST_SS_BASE,
    VMM_GUEST_SS_LIMIT,
    VMM_GUEST_SS_AR,
    VMM_GUEST_DS_SELECTOR,
    VMM_GUEST_DS_BASE,
    VMM_GUEST_DS_LIMIT,
    VMM_GUEST_DS_AR,
    VMM_GUEST_FS_SELECTOR,
    VMM_GUEST_FS_BASE,
    VMM_GUEST_FS_LIMIT,
    VMM_GUEST_FS_AR,
    VMM_GUEST_GS_SELECTOR,
    VMM_GUEST_GS_BASE,
    VMM_GUEST_GS_LIMIT,
    VMM_GUEST_GS_AR,
    VMM_GUEST_LDTR_SELECTOR,
    VMM_GUEST_LDTR_BASE,
    VMM_GUEST_LDTR_LIMIT,
    VMM_GUEST_LDTR_AR,
    VMM_GUEST_TR_SELECTOR,
    VMM_GUEST_TR_BASE,
    VMM_GUEST_TR_LIMIT,
    VMM_GUEST_TR_AR,
    VMM_GUEST_GDTR_BASE,
    VMM_GUEST_GDTR_LIMIT,
    VMM_GUEST_IDTR_BASE,
    VMM_GUEST_IDTR_LIMIT,
    VMM_GUEST_RSP,
    VMM_GUEST_RIP,
    VMM_GUEST_RFLAGS,
    VMM_GUEST_PEND_DBE,
    VMM_GUEST_WORKING_VMCS_PTR,
    VMM_GUEST_DEBUG_CONTROL,
    VMM_GUEST_INTERRUPTIBILITY,
    VMM_GUEST_SLEEP_STATE,
    VMM_GUEST_SMBASE,
    VMM_GUEST_SYSENTER_CS,
    VMM_GUEST_SYSENTER_ESP,
    VMM_GUEST_SYSENTER_EIP,
    VMM_GUEST_PAT,
    VMM_GUEST_EFER,
    VMM_GUEST_IA32_PERF_GLOBAL_CTRL,
    VMM_GUEST_PDPTR0,
    VMM_GUEST_PDPTR1,
    VMM_GUEST_PDPTR2,
    VMM_GUEST_PDPTR3,
    // END: VMCS GUEST fields
    // START: Other fields
    /* Any new fields independent of GPRs and VMCS should be added here.
     */
    VMM_GUEST_PREEMPTION_TIMER,
    VMM_GUEST_CR8, // Only valid for 64-bit, undefined behavior in 32-bit
    // END: Other fields
    NUM_OF_VMM_GUEST_STATE
} VMM_GUEST_STATE;

#ifdef INCLUDE_UNUSED_CODE
typedef enum {
    VMM_HOST_CR0              = 0,
    VMM_HOST_CR3,
    VMM_HOST_CR4,
    VMM_HOST_ES_SELECTOR,
    VMM_HOST_CS_SELECTOR,
    VMM_HOST_SS_SELECTOR,
    VMM_HOST_DS_SELECTOR,
    VMM_HOST_FS_SELECTOR,
    VMM_HOST_FS_BASE,
    VMM_HOST_GS_SELECTOR,
    VMM_HOST_GS_BASE,
    VMM_HOST_TR_SELECTOR,
    VMM_HOST_TR_BASE,
    VMM_HOST_GDTR_BASE,
    VMM_HOST_IDTR_BASE,
    VMM_HOST_RSP,
    VMM_HOST_RIP,
    VMM_HOST_SYSENTER_CS,
    VMM_HOST_SYSENTER_ESP,
    VMM_HOST_SYSENTER_EIP,
    VMM_HOST_PAT,
    VMM_HOST_EFER,
    VMM_HOST_IA32_PERF_GLOBAL_CTRL,
    //last
    NUM_OF_VMM_HOST_STATE
} VMM_HOST_STATE;
#endif

typedef union VMM_CONTROLS_U {
    struct {
        UINT64 mask;
        UINT64 value;
    } mask_value;
    struct {
        UINT64 gaw;
        UINT64 ept_root_table_hpa;
    } ept_value;
#ifdef INCLUDE_UNUSED_CODE
    struct {
        UINT64 cr3_count;
        UINT64 cr3_value[4];
    } cr3;
#endif
    UINT64 value;
} VMM_CONTROLS;

typedef struct _VMM_GUEST_STATE_VALUE {
	BOOLEAN skip_rip;  // For setting RIP
	                   // TRUE to skip instruction;
	                   // FALSE to set RIP to new value
	UINT8   padding[4];
	UINT64  value;
} VMM_GUEST_STATE_VALUE;

/*-------------------------------------------------------*
*  PURPOSE  : Get the value of given Guest State ID
*  ARGUMENTS: gcpu        (IN) -- Guest CPU Handle
*             GuestStateId(IN) -- Guest State ID
*             value       (OUT)-- Pointer of the Guest
*                                 State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
BOOLEAN vmm_get_vmcs_guest_state(GUEST_CPU_HANDLE gcpu, VMM_GUEST_STATE GuestStateId, VMM_GUEST_STATE_VALUE *value);


/*-------------------------------------------------------*
*  PURPOSE  : Set the value of given Guest State ID to the
*             given value
*  ARGUMENTS: gcpu        (IN) -- Guest CPU Handle
*             GuestStateId(IN) -- Guest State ID
*             value       (IN) -- Given Guest State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
BOOLEAN vmm_set_vmcs_guest_state(GUEST_CPU_HANDLE gcpu, VMM_GUEST_STATE GuestStateId, VMM_GUEST_STATE_VALUE value);


/*-------------------------------------------------------*
*  PURPOSE  : Get the value of given Control State ID
*  ARGUMENTS: gcpu          (IN) -- Guest CPU Handle
*             ControlStateId(IN) -- Control State ID
*             value         (IN) -- Pointer of the Given
*                                   Control State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
BOOLEAN vmm_get_vmcs_control_state(GUEST_CPU_HANDLE gcpu, VMM_CONTROL_STATE ControlStateId, VMM_CONTROLS* value);


/*-------------------------------------------------------*
*  PURPOSE  : Set the value of given Control State ID to
*             the given value
*  ARGUMENTS: gcpu          (IN) -- Guest CPU Handle
*             ControlStateId(IN) -- Control State ID
*             value         (IN) -- Pointer of the Given
*                                   Control State value
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
BOOLEAN vmm_set_vmcs_control_state(GUEST_CPU_HANDLE gcpu, VMM_CONTROL_STATE ControlStateId, VMM_CONTROLS* value);


/*-------------------------------------------------------*
*  PURPOSE  : Copy the given memory from given gva to
*             given hva
*  ARGUMENTS: gcpu(IN) -- Guest CPU Handle
*             gva (IN) -- Guest Virtual Address
*             size(IN) -- size of the range from gva
*             hva (IN) -- Pointer of Host Virtual Address
*  RETURNS  : 0 if successful
*-------------------------------------------------------*/
int copy_from_gva(GUEST_CPU_HANDLE gcpu, UINT64 gva, int size, UINT64 hva);


#endif //_VMM_API_H
