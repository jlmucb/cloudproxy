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

#ifndef _VMCS_INIT_H_
#define _VMCS_INIT_H_

#include "vmm_defs.h"
#include "vmx_ctrl_msrs.h"
#include "em64t_defs.h"
#include "vmcs_api.h"

//******************************************************************************
//
// Initialization of the VMCS hardware region
//
//******************************************************************************

typedef struct _VMCS_HW_CONSTRAINTS {
    PIN_BASED_VM_EXECUTION_CONTROLS         may1_pin_based_exec_ctrl;           // 1 for each bit that may be 1
    PIN_BASED_VM_EXECUTION_CONTROLS         may0_pin_based_exec_ctrl;           // 0 for each bit that may be 0
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS   may1_processor_based_exec_ctrl;     // 1 for each bit that may be 1
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS   may0_processor_based_exec_ctrl;     // 0 for each bit that may be 0
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2  may1_processor_based_exec_ctrl2;    // 1 for each bit that may be 1
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2  may0_processor_based_exec_ctrl2;    // 0 for each bit that may be 0
    VM_EXIT_CONTROLS                        may1_vm_exit_ctrl;                  // 1 for each bit that may be 1
    VM_EXIT_CONTROLS                        may0_vm_exit_ctrl;                  // 0 for each bit that may be 0
    VM_ENTRY_CONTROLS                       may1_vm_entry_ctrl;                 // 1 for each bit that may be 1
    VM_ENTRY_CONTROLS                       may0_vm_entry_ctrl;                 // 0 for each bit that may be 0
    EM64T_CR0                               may1_cr0;                           // 1 for each bit that may be 1
    EM64T_CR0                               may0_cr0;                           // 0 for each bit that may be 0
    EM64T_CR4                               may1_cr4;                           // 1 for each bit that may be 1
    EM64T_CR4                               may0_cr4;                           // 0 for each bit that may be 0

    UINT32                                  number_of_cr3_target_values;
    UINT32                                  max_msr_lists_size_in_bytes;
    UINT32                                  vmx_timer_length; // in TSC ticks
    UINT32                                  vmcs_revision;
    UINT32                                  mseg_revision_id;
    BOOLEAN                                 vm_entry_in_halt_state_supported;
    BOOLEAN                                 vm_entry_in_shutdown_state_supported;
    BOOLEAN                                 vm_entry_in_wait_for_sipi_state_supported;
    BOOLEAN                                 processor_based_exec_ctrl2_supported;
    BOOLEAN                                 ept_supported;
    BOOLEAN                                 unrestricted_guest_supported;
    BOOLEAN                                 vpid_supported;
#ifdef FAST_VIEW_SWITCH
    BOOLEAN                                 vmfunc_supported;
    BOOLEAN                                 eptp_switching_supported;
#endif
    BOOLEAN                                 ve_supported;

    IA32_VMX_EPT_VPID_CAP                   ept_vpid_capabilities;
} VMCS_HW_CONSTRAINTS;

typedef struct _VMCS_HW_FIXED {
    PIN_BASED_VM_EXECUTION_CONTROLS         fixed_1_pin_based_exec_ctrl;        // 1 for each fixed 1 bit
    PIN_BASED_VM_EXECUTION_CONTROLS         fixed_0_pin_based_exec_ctrl;        // 0 for each fixed 0 bit
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS   fixed_1_processor_based_exec_ctrl;  // 1 for each fixed 1 bit
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS   fixed_0_processor_based_exec_ctrl;  // 0 for each fixed 0 bit
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2  fixed_1_processor_based_exec_ctrl2; // 1 for each fixed 1 bit
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2  fixed_0_processor_based_exec_ctrl2; // 0 for each fixed 0 bit
    VM_EXIT_CONTROLS                        fixed_1_vm_exit_ctrl;               // 1 for each fixed 1 bit
    VM_EXIT_CONTROLS                        fixed_0_vm_exit_ctrl;               // 0 for each fixed 0 bit
    VM_ENTRY_CONTROLS                       fixed_1_vm_entry_ctrl;              // 1 for each fixed 1 bit
    VM_ENTRY_CONTROLS                       fixed_0_vm_entry_ctrl;              // 0 for each fixed 0 bit
    EM64T_CR0                               fixed_1_cr0;                        // 1 for each fixed 1 bit
    EM64T_CR0                               fixed_0_cr0;                        // 0 for each fixed 0 bit
    EM64T_CR4                               fixed_1_cr4;                        // 1 for each fixed 1 bit
    EM64T_CR4                               fixed_0_cr4;                        // 0 for each fixed 0 bit
} VMCS_HW_FIXED;

// global
extern VMCS_HW_FIXED* gp_vmx_fixed;
extern UINT64 g_vmx_fixed_1_cr0_save;


//------------------------------------------------------------------------------
//
// Init
//
//------------------------------------------------------------------------------
void vmcs_hw_init( void );

//------------------------------------------------------------------------------
//
// Check that current CPU is VMX-capable
//
//------------------------------------------------------------------------------
BOOLEAN vmcs_hw_is_cpu_vmx_capable( void );

//------------------------------------------------------------------------------
//
// Enable VT on the current CPU
//
//------------------------------------------------------------------------------
void vmcs_hw_vmx_on( void );

//------------------------------------------------------------------------------
//
// Disable VT on the current CPU
//
//------------------------------------------------------------------------------
void vmcs_hw_vmx_off( void );

//------------------------------------------------------------------------------
//
// Allocate and initialize VMCS region
//
// Returns 2 pointers:
//    Pointer to the allocated VMCS region (HVA)
//    Ponter to the same region (HPA)
//
//------------------------------------------------------------------------------
HVA vmcs_hw_allocate_region( HPA* hpa );

//------------------------------------------------------------------------------
//
// Allocate and initialize vmxon regions for all the processors 
// (called once only on BSP)
//
//------------------------------------------------------------------------------
BOOLEAN vmcs_hw_allocate_vmxon_regions( UINT16 max_host_cpus );



//------------------------------------------------------------------------------
//
// Get constraint values for various VMCS fields
//
//------------------------------------------------------------------------------
const VMCS_HW_CONSTRAINTS* vmcs_hw_get_vmx_constraints( void );

//------------------------------------------------------------------------------
//
// Make hw compliant
//
//  Ensure, that all bits that are 0 in may0 are also 0 in actual
//  Ensure, that all bits that are 1 in may1 are also 1 in actual
//
//------------------------------------------------------------------------------
INLINE
UINT32 vmcs_hw_make_compliant_pin_based_exec_ctrl( UINT32 value )
{
    value &= gp_vmx_fixed->fixed_0_pin_based_exec_ctrl.Uint32;
    value |= gp_vmx_fixed->fixed_1_pin_based_exec_ctrl.Uint32;
    return value;
}

INLINE
UINT32 vmcs_hw_make_compliant_processor_based_exec_ctrl( UINT32 value )
{
    value &= gp_vmx_fixed->fixed_0_processor_based_exec_ctrl.Uint32;
    value |= gp_vmx_fixed->fixed_1_processor_based_exec_ctrl.Uint32;
    return value;
}

INLINE
UINT32 vmcs_hw_make_compliant_processor_based_exec_ctrl2( UINT32 value )
{
    value &= gp_vmx_fixed->fixed_0_processor_based_exec_ctrl2.Uint32;
    value |= gp_vmx_fixed->fixed_1_processor_based_exec_ctrl2.Uint32;
    return value;
}

INLINE
UINT32 vmcs_hw_make_compliant_vm_exit_ctrl( UINT32 value )
{
    value &= gp_vmx_fixed->fixed_0_vm_exit_ctrl.Uint32;
    value |= gp_vmx_fixed->fixed_1_vm_exit_ctrl.Uint32;
    return value;
}

INLINE
UINT32 vmcs_hw_make_compliant_vm_entry_ctrl( UINT32 value )
{
    value &= gp_vmx_fixed->fixed_0_vm_entry_ctrl.Uint32;
    value |= gp_vmx_fixed->fixed_1_vm_entry_ctrl.Uint32;
    return value;
}

INLINE
UINT64 vmcs_hw_make_compliant_cr0( UINT64 value )
{
    value &= gp_vmx_fixed->fixed_0_cr0.Uint64;
    value |= gp_vmx_fixed->fixed_1_cr0.Uint64;
    return value;
}

INLINE
UINT64 vmcs_hw_make_compliant_cr4( UINT64 value )
{
    value &= gp_vmx_fixed->fixed_0_cr4.Uint64;
    value |= gp_vmx_fixed->fixed_1_cr4.Uint64;
    return value;
}

INLINE
UINT64 vmcs_hw_make_compliant_cr8( UINT64 value )
{
    value &= EM64T_CR8_VALID_BITS_MASK;
    return value;
}

#endif // _VMCS_INIT_H_
