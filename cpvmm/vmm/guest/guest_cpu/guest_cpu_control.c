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

#include "guest_cpu_internal.h"
//#include "vmcs_object.h"
#include "vmcs_api.h"
#include "vmcs_init.h"
#include "heap.h"
#include "vmx_vmcs.h"
#include "hw_utils.h"
#include "vmexit_msr.h"
#include "vmexit_io.h"
#include "vmcall.h"
#include "vmm_dbg.h"
#include "policy_manager.h"
#include "vmm_api.h"
#include "unrestricted_guest.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_CPU_CONTROL_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_CPU_CONTROL_C, __condition)

extern VMM_PAGING_POLICY g_pg_policy;
extern void disable_vmcs_load_save_for_msr (MSR_ID msr_index);
extern BOOLEAN is_cr4_osxsave_supported(void);

//******************************************************************************
//*
//* Main implementatuion idea:
//*   Count requests for each VmExit control bit. Require VmExit if at least
//*   one request is outstanding.
//*
//*
//*
//******************************************************************************

// global static vars that indicate host CPU support for extra controls
static BOOLEAN g_init_done = FALSE;
static BOOLEAN g_processor_ctrls2_supported = FALSE;

// -------------------------- types -----------------------------------------
typedef enum _EXCEPTIONS_POLICY_TYPE {
    EXCEPTIONS_POLICY_CATCH_NOTHING = 0,
    EXCEPTIONS_POLICY_CATCH_ALL,
} EXCEPTIONS_POLICY_TYPE;

// ---------------------------- globals -------------------------------------


// set bit for each fixed bit - either 0 or 1
#define GET_FIXED_MASK( type, mask, func )                                      \
    {                                                                           \
        type fixed1, fixed0;                                                    \
        fixed1 = (func)( 0 );                                                   \
        fixed0 = (func)( (type)-1 );                                            \
        (mask) = fixed1 | ~fixed0;                                              \
    }

// init with minimal value
#define GET_MINIMAL_VALUE( value, func )  (value) = (func)( 0 )

// return fixed0 values
#define GET_FIXED0( func ) (func)( UINT32_ALL_ONES )

#define MAY_BE_SET1( fixed, defaul, bit ) (!(fixed.Bits.bit) || defaul.Bits.bit)

// get final field settings
////#define GET_FINAL_SETTINGS( gcpu, field, final_mask )                           
////    (((UINT64)(final_mask) | (gcpu)->vmexit_setup.field.enforce_1_settings)    
////                           & (gcpu)->vmexit_setup.field.enforce_0_settings)


#define APPLY_ZEROES(__value, __zeroes) ((__value) & (__zeroes))
#define APPLY_ONES(__value, __ones) ((__value) | (__ones))
#define APPLY_ZEROES_AND_ONES(__value, __zeroes, __ones) \
    APPLY_ZEROES(APPLY_ONES(__value, __ones), __zeroes)


#define GET_FINAL_SETTINGS( gcpu, field, final_mask )                           \
    (((UINT64)(final_mask) | (gcpu)->vmexit_setup.field.minimal_1_settings)     \
                           & (gcpu)->vmexit_setup.field.minimal_0_settings)


/*----------------- Forward Declarations for Local Functions -----------------*/

static void gcpu_exceptions_settings_enforce_on_hw(GUEST_CPU_HANDLE  gcpu, UINT32 zeroes, UINT32 ones);
static void gcpu_exceptions_settings_restore_on_hw(GUEST_CPU_HANDLE  gcpu);
static void gcpu_proc_ctrls_enforce_on_hw(GUEST_CPU_HANDLE gcpu, UINT32 zeroes, UINT32 ones);
static void gcpu_proc_ctrls_restore_on_hw(GUEST_CPU_HANDLE gcpu);
static void gcpu_cr0_mask_enforce_on_hw(GUEST_CPU_HANDLE gcpu, UINT64 zeroes, UINT64 ones);
static void gcpu_set_enter_ctrls_for_addons( GUEST_CPU_HANDLE gcpu, UINT32 value, UINT32 bits_untouched );

//static void gcpu_guest_cpu_mode_enforce_on_hw(GUEST_CPU_HANDLE gcpu);
//static void gcpu_guest_cpu_mode_restore_on_hw(GUEST_CPU_HANDLE gcpu);




// ---------------------------- internal funcs  -----------------------------

static void set_minimal_cr0_reg_mask( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    UINT64 fixed;

    GET_FIXED_MASK( UINT64, fixed, vmcs_hw_make_compliant_cr0 );

    field->minimal_1_settings = (fixed | GCPU_CR0_VMM_CONTROLLED_BITS);

    if (global_policy_is_cache_dis_virtualized())
        field->minimal_1_settings |= CR0_CD;

    field->minimal_0_settings = UINT64_ALL_ONES;
}

static void set_minimal_cr4_reg_mask( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    UINT64 fixed;

    GET_FIXED_MASK( UINT64, fixed, vmcs_hw_make_compliant_cr4 );

    if( is_unrestricted_guest_supported() )
    	field->minimal_1_settings = fixed | CR4_SMXE;
    else
		field->minimal_1_settings = (fixed | GCPU_CR4_VMM_CONTROLLED_BITS);
    field->minimal_0_settings = UINT64_ALL_ONES;

    if (is_cr4_osxsave_supported())
		field->minimal_1_settings = field->minimal_1_settings | CR4_OSXSAVE;
}

static void set_minimal_pin_ctrls( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    PIN_BASED_VM_EXECUTION_CONTROLS pin_ctrl, pin_ctrl_fixed;

    GET_FIXED_MASK( UINT32, pin_ctrl_fixed.Uint32,
                    vmcs_hw_make_compliant_pin_based_exec_ctrl );

    GET_MINIMAL_VALUE( pin_ctrl.Uint32,
                    vmcs_hw_make_compliant_pin_based_exec_ctrl );


    // do not exit on external interrupts
    VMM_ASSERT( pin_ctrl.Bits.ExternalInterrupt == 0 );

    // setup all NMIs to be processed by VMM
    // gcpu receive only virtual NMIs
    VMM_ASSERT( MAY_BE_SET1(pin_ctrl_fixed, pin_ctrl, Nmi ));
    pin_ctrl.Bits.Nmi = 1;

    VMM_ASSERT( MAY_BE_SET1(pin_ctrl_fixed, pin_ctrl, VirtualNmi ));
    pin_ctrl.Bits.VirtualNmi = 1;

    field->minimal_1_settings = pin_ctrl.Uint32;
    field->minimal_0_settings = GET_FIXED0( vmcs_hw_make_compliant_pin_based_exec_ctrl );
}

static void set_minimal_processor_ctrls( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS proc_ctrl, proc_ctrl_fixed;

    GET_FIXED_MASK( UINT32, proc_ctrl_fixed.Uint32,
                    vmcs_hw_make_compliant_processor_based_exec_ctrl );

    GET_MINIMAL_VALUE( proc_ctrl.Uint32,
                    vmcs_hw_make_compliant_processor_based_exec_ctrl );

    // do not use TSC offsetting
    VMM_ASSERT( proc_ctrl.Bits.UseTscOffsetting == 0 );

    // do not exit on halt instruction
    VMM_ASSERT( proc_ctrl.Bits.Hlt == 0 );

    // do not exit on invalidate page
    VMM_ASSERT( proc_ctrl.Bits.Invlpg == 0 );

    // do not exit on mwait
    VMM_ASSERT( proc_ctrl.Bits.Mwait == 0 );

    // do not exit on rdpmc instruction
    VMM_ASSERT( proc_ctrl.Bits.Rdpmc == 0 );

    // do not exit on rdtsc instruction
    VMM_ASSERT( proc_ctrl.Bits.Rdtsc == 0 );

    // do not exit on CR8 access
    VMM_ASSERT( proc_ctrl.Bits.Cr8Load == 0 );
    VMM_ASSERT( proc_ctrl.Bits.Cr8Store == 0 );

    // do not exit use TPR shadow
    VMM_ASSERT( proc_ctrl.Bits.TprShadow == 0 );

    // do not exit on debug registers access
    VMM_ASSERT( proc_ctrl.Bits.MovDr == 0 );

    // do not exit on I/O ports access
    VMM_ASSERT( proc_ctrl.Bits.UnconditionalIo == 0 );
    VMM_ASSERT( proc_ctrl.Bits.ActivateIoBitmaps == 0 );

    // do not exit on monitor instruction
    VMM_ASSERT( proc_ctrl.Bits.Monitor == 0 );

    // do not exit on pause instruction
    VMM_ASSERT( proc_ctrl.Bits.Pause == 0 );

	VMM_LOG(mask_anonymous, level_trace,"%s:: %d \n", __FUNCTION__, g_pg_policy);
	if (g_pg_policy == POL_PG_EPT)
	{
        //VMM_LOG(mask_anonymous, level_trace,"%s:VMEXIT BITS= %X\n", __FUNCTION__, proc_ctrl.Uint32);
        proc_ctrl.Bits.Cr3Load = 0;
        proc_ctrl.Bits.Cr3Store = 0;
       //VMM_LOG(mask_anonymous, level_trace,"%s:VMEXIT BITS= %X\n", __FUNCTION__, proc_ctrl.Uint32);
	}


    // if processor_ctrls2 may be enabled, enable them immediately
    // to simplify processing
    VMM_ASSERT(
       g_processor_ctrls2_supported ==
        (0 != MAY_BE_SET1(proc_ctrl_fixed, proc_ctrl, SecondaryControls )));

    if (g_processor_ctrls2_supported)
    {
        proc_ctrl.Bits.SecondaryControls = 1;
    }

    field->minimal_1_settings = proc_ctrl.Uint32;
    field->minimal_0_settings = GET_FIXED0( vmcs_hw_make_compliant_processor_based_exec_ctrl );
}

static void set_minimal_processor_ctrls2( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 proc_ctrl2, proc_ctrl2_fixed;

    if (!g_processor_ctrls2_supported)
    {
        return;
    }

    GET_FIXED_MASK( UINT32, proc_ctrl2_fixed.Uint32,
                    vmcs_hw_make_compliant_processor_based_exec_ctrl2 );

    GET_MINIMAL_VALUE( proc_ctrl2.Uint32,
                    vmcs_hw_make_compliant_processor_based_exec_ctrl2 );

    //
    // enable rdtscp instruction if CPUID.80000001H.EDX[27] reports it is supported
    // if "Enable RDTSCP" is 0, execution of RDTSCP in non-root mode will trigger #UD
    // Notes:
    //   1. Currently, "RDTSC existing" and "use TSC Offsetting" both are ZEROs, since 
    //      vmm doesn't virtualize TSC
    //   2. Current setting makes RDTSCP operate as normally, and no vmexits happen. 
    //      Besides, vmm doesn't use/modify IA32_TSC_AUX.
    //   3. If we want to add virtual TSC and support, and virtualization of IA32_TSC_AUX, 
    //      current settings must be changed per request.
    //
    if(proc_ctrl2.Bits.EnableRDTSCP == 0) {
        
        // set EnableRDTSCP bit if rdtscp is supported        
        if(is_rdtscp_supported()){
            proc_ctrl2.Bits.EnableRDTSCP = 1;
        }
    }


    //
    //INVPCID. Behavior of the INVPCID instruction is determined first
    //by the setting of the “enable INVPCID” VM-execution control:
    //— If the “enable INVPCID” VM-execution control is 0, 
    //  INVPCID causes an invalid-opcode exception (#UD).
    //— If the “enable INVPCID” VM-execution control is 1, 
    //  treatment is based on the setting of the “INVLPG exiting” VM-execution control:
    //  1) If the “INVLPG exiting” VM-execution control is 0, INVPCID operates normally.
    //     (this setting is selected)
    //  2) If the “INVLPG exiting” VM-execution control is 1, INVPCID causes a VM exit.
    //
    if(proc_ctrl2.Bits.EnableINVPCID == 0){

        // set EnableINVPCID bit if INVPCID is supported  
        if(is_invpcid_supported()){
            proc_ctrl2.Bits.EnableINVPCID = 1;
        }        
    }

    field->minimal_1_settings = proc_ctrl2.Uint32;
    field->minimal_0_settings = GET_FIXED0( vmcs_hw_make_compliant_processor_based_exec_ctrl2 );
}


static void set_minimal_exceptions_map( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    IA32_VMCS_EXCEPTION_BITMAP exceptions;

    exceptions.Uint32 = 0;

    // Machine Check: let guest IDT handle the MCE unless vmm has special concern
    //exceptions.Bits.MC = 1;

    // Page Faults
    // exceptions.Bits.PF = 1;   not required for EPT. for VTLB/FPT should be enabled explicitely

    field->minimal_1_settings = exceptions.Uint32;
    field->minimal_0_settings = UINT64_ALL_ONES;
}

static void set_minimal_exit_ctrls( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    VM_EXIT_CONTROLS ctrl, ctrl_fixed;

    GET_FIXED_MASK( UINT32, ctrl_fixed.Uint32,
                    vmcs_hw_make_compliant_vm_exit_ctrl );

    GET_MINIMAL_VALUE( ctrl.Uint32,
                    vmcs_hw_make_compliant_vm_exit_ctrl );

    // do not acknowledge interrupts on exit
    VMM_ASSERT( ctrl.Bits.AcknowledgeInterruptOnExit == 0 );

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveCr0AndCr4 ));
    ctrl.Bits.SaveCr0AndCr4 = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveCr3 ));
    ctrl.Bits.SaveCr3 = 1;

    if ( MAY_BE_SET1(ctrl_fixed, ctrl, SaveDebugControls )) {
    	ctrl.Bits.SaveDebugControls = 1;
    }

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveSegmentRegisters ));
    ctrl.Bits.SaveSegmentRegisters = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveEspEipEflags ));
    ctrl.Bits.SaveEspEipEflags = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SavePendingDebugExceptions ));
    ctrl.Bits.SavePendingDebugExceptions = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveInterruptibilityInformation ));
    ctrl.Bits.SaveInterruptibilityInformation = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveActivityState ));
    ctrl.Bits.SaveActivityState = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveWorkingVmcsPointer ));
    ctrl.Bits.SaveWorkingVmcsPointer = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadCr0AndCr4 ));
    ctrl.Bits.LoadCr0AndCr4 = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadCr3 ));
    ctrl.Bits.LoadCr3 = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadSegmentRegisters ));
    ctrl.Bits.LoadSegmentRegisters = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadEspEip ));
    ctrl.Bits.LoadEspEip = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadEspEip ));
    ctrl.Bits.LoadEspEip = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, SaveSysEnterMsrs ));

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadSysEnterMsrs ));

    if( MAY_BE_SET1(ctrl_fixed, ctrl, SaveEfer )) {
    	ctrl.Bits.SaveEfer = 1;
    }

    if( MAY_BE_SET1(ctrl_fixed, ctrl, LoadEfer )) {
    	ctrl.Bits.LoadEfer = 1;
    }

    if ( MAY_BE_SET1(ctrl_fixed, ctrl, Load_IA32_PERF_GLOBAL_CTRL )) {
    	ctrl.Bits.Load_IA32_PERF_GLOBAL_CTRL = 1;
    }

    if ( MAY_BE_SET1(ctrl_fixed, ctrl, SavePat )) {
    	ctrl.Bits.SavePat = 1;
    }

    if( MAY_BE_SET1(ctrl_fixed, ctrl, LoadPat )) {
    	ctrl.Bits.LoadPat = 1;
    }

    field->minimal_1_settings = ctrl.Uint32;
    field->minimal_0_settings = GET_FIXED0( vmcs_hw_make_compliant_vm_exit_ctrl );
}

static void set_minimal_entry_ctrls( GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* field )
{
    VM_ENTRY_CONTROLS ctrl, ctrl_fixed;

    GET_FIXED_MASK( UINT32, ctrl_fixed.Uint32,
                    vmcs_hw_make_compliant_vm_entry_ctrl );

    GET_MINIMAL_VALUE( ctrl.Uint32,
                    vmcs_hw_make_compliant_vm_entry_ctrl );

    // we are out of SMM
    VMM_ASSERT( ctrl.Bits.EntryToSmm == 0 );
    VMM_ASSERT( ctrl.Bits.TearDownSmmMonitor == 0 );

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadCr0AndCr4 ));
    ctrl.Bits.LoadCr0AndCr4 = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadCr3 ));
    ctrl.Bits.LoadCr3 = 1;

    if( MAY_BE_SET1(ctrl_fixed, ctrl, LoadDebugControls )) {
    	ctrl.Bits.LoadDebugControls = 1;
    }

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadSegmentRegisters ));
    ctrl.Bits.LoadSegmentRegisters = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadEspEipEflags ));
    ctrl.Bits.LoadEspEipEflags = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadPendingDebugExceptions ));
    ctrl.Bits.LoadPendingDebugExceptions = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadInterruptibilityInformation ));
    ctrl.Bits.LoadInterruptibilityInformation = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadActivityState ));
    ctrl.Bits.LoadActivityState = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadWorkingVmcsPointer ));
    ctrl.Bits.LoadWorkingVmcsPointer = 1;

    VMM_ASSERT( MAY_BE_SET1(ctrl_fixed, ctrl, LoadSysEnterMsrs ));

    if( MAY_BE_SET1(ctrl_fixed, ctrl, LoadEfer )) {
    	ctrl.Bits.LoadEfer = 1;
    }

    if ( MAY_BE_SET1(ctrl_fixed, ctrl, LoadPat )) {
    	ctrl.Bits.LoadPat = 1;
    }

    field->minimal_1_settings = ctrl.Uint32;
     field->minimal_0_settings = GET_FIXED0( vmcs_hw_make_compliant_vm_entry_ctrl );
}

static void init_minimal_controls( GUEST_CPU_HANDLE gcpu )
{
    // perform init
    if (g_init_done == FALSE)
    {
        g_init_done = TRUE;
        g_processor_ctrls2_supported =
            vmcs_hw_get_vmx_constraints()->processor_based_exec_ctrl2_supported;
    }

    set_minimal_cr0_reg_mask    ( &(gcpu->vmexit_setup.cr0) );
    set_minimal_cr4_reg_mask    ( &(gcpu->vmexit_setup.cr4) );
    set_minimal_pin_ctrls       ( &(gcpu->vmexit_setup.pin_ctrls) );
    set_minimal_processor_ctrls ( &(gcpu->vmexit_setup.processor_ctrls) );
    set_minimal_processor_ctrls2( &(gcpu->vmexit_setup.processor_ctrls2) );
    set_minimal_exceptions_map  ( &(gcpu->vmexit_setup.exceptions_ctrls) );
    set_minimal_entry_ctrls     ( &(gcpu->vmexit_setup.vm_entry_ctrls) );
    set_minimal_exit_ctrls      ( &(gcpu->vmexit_setup.vm_exit_ctrls) );
}

//
// Get 64bit mask + flags set. For each 1-bit in mask consult flags bit.
// If flags bit is 1 - increase count, esle - decrease count
// Return bit set with 1bit for each non-zero counter
static
UINT64 gcpu_update_control_counters( UINT64 flags, UINT64 mask,
                                     GCPU_VMEXIT_CONTROL_FIELD_COUNTERS* counters )
{
    UINT32 idx;

    while ( mask )
    {
        idx = (UINT32)-1;

        hw_scan_bit_forward64( &idx, mask );
        // VMM_LOG(mask_anonymous, level_trace,"gcpu_update_control_counters: flags = 0x%0X, idx=%d, mask = 0x%0X\n", flags, idx, mask);

        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT( idx < 64 );
        BIT_CLR64( mask, idx );

        if (1 == BIT_GET64( flags, idx ))
        {
            if (0 == counters->counters[idx])
            {
                BIT_SET64( counters->bit_field, idx );
            }

            // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
            VMM_ASSERT( counters->counters[idx] < 255 );
            ++(counters->counters[idx]);
        }
        else
        {
            // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
            VMM_ASSERT( counters->counters[idx] > 0 );
            --(counters->counters[idx]);

            if (0 == counters->counters[idx])
            {
                BIT_CLR64( counters->bit_field, idx );
            }
        }
    }

    return counters->bit_field;
}

INLINE
UINT64 calculate_cr0_reg_mask( GUEST_CPU_HANDLE gcpu, UINT64 request, UINT64 bitmask )
{
    UINT64 final_mask;

    final_mask = gcpu_update_control_counters(
                        request,
                        bitmask,
                        &(gcpu->vmexit_setup.cr0));
//VMM_LOG(mask_anonymous, level_trace,"calculate_cr0_reg_mask: final_mask=%P\n", final_mask);
    return GET_FINAL_SETTINGS( gcpu, cr0, final_mask );
}

void gcpu_set_cr0_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT64 value )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    if (vmcs_read( vmcs, VMCS_CR0_MASK ) != value)
    {
//VMM_LOG(mask_anonymous, level_trace,"set_cr0_reg_mask: value=%P\n", value);
        vmcs_write( vmcs, VMCS_CR0_MASK, value );
    }
}

UINT64 gcpu_get_cr0_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);

    VMM_ASSERT(vmcs);

    return vmcs_read( vmcs, VMCS_CR0_MASK );
}

INLINE
UINT64 calculate_cr4_reg_mask( GUEST_CPU_HANDLE gcpu, UINT64 request, UINT64 bitmask )
{
    UINT64 final_mask;

    final_mask = gcpu_update_control_counters(
                        request,
                        bitmask,
                        &(gcpu->vmexit_setup.cr4));

//VMM_LOG(mask_anonymous, level_trace,"calculate_cr4_reg_mask: final_mask=%P\n", final_mask);
    return GET_FINAL_SETTINGS( gcpu, cr4, final_mask );
}

void gcpu_set_cr4_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT64 value )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    if (vmcs_read( vmcs, VMCS_CR4_MASK ) != value )
    {
//VMM_LOG(mask_anonymous, level_trace,"set_cr4_reg_mask: value=%P\n", value);
        vmcs_write( vmcs, VMCS_CR4_MASK, value );
    }
}

UINT64 gcpu_get_cr4_reg_mask_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    return vmcs_read( vmcs, VMCS_CR4_MASK );
}


INLINE
UINT32 calculate_pin_ctrls( GUEST_CPU_HANDLE gcpu, UINT32 request, UINT32 bitmask )
{
    UINT32 final_mask;

    final_mask = (UINT32)gcpu_update_control_counters(
                            request,
                            bitmask,
                            &(gcpu->vmexit_setup.pin_ctrls));

//VMM_LOG(mask_anonymous, level_trace,"calculate_pin_ctrls: final_mask=%P\n", final_mask);
    return (UINT32)GET_FINAL_SETTINGS( gcpu, pin_ctrls, final_mask );
}

void gcpu_set_pin_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT64 value )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    if (vmcs_read( vmcs, VMCS_CONTROL_VECTOR_PIN_EVENTS ) != value)
    {
//VMM_LOG(mask_anonymous, level_trace,"set_pin_ctrls: value=%P\n", value);
        vmcs_write( vmcs, VMCS_CONTROL_VECTOR_PIN_EVENTS, value );
    }
}

UINT64 gcpu_get_pin_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    return vmcs_read( vmcs, VMCS_CONTROL_VECTOR_PIN_EVENTS );
}

static
UINT32 calculate_processor_ctrls( GUEST_CPU_HANDLE gcpu, UINT32 request, UINT32 bitmask )
{
    UINT32 final_mask;

    final_mask = (UINT32)gcpu_update_control_counters(
                            request,
                            bitmask,
                            &(gcpu->vmexit_setup.processor_ctrls));

//VMM_LOG(mask_anonymous, level_trace,"calculate_processor_ctrls: final_mask=%P\n", final_mask);
    return (UINT32)GET_FINAL_SETTINGS( gcpu, processor_ctrls, final_mask );
}

void gcpu_set_processor_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT64 value )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    UINT64 proc_control_temp;
    VMM_ASSERT(vmcs);

    proc_control_temp = vmcs_read( vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS );

    if ( proc_control_temp != value )
    {
        vmcs_write( vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS, (value & ~0x8000000) | (proc_control_temp & 0x8000000));
    }
}

UINT64 gcpu_get_processor_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    return vmcs_read( vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS );
}

static
UINT32 calculate_processor_ctrls2( GUEST_CPU_HANDLE gcpu, UINT32 request, UINT32 bitmask )
{
    UINT32 final_mask;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( g_processor_ctrls2_supported == TRUE );

    final_mask = (UINT32)gcpu_update_control_counters(
                            request,
                            bitmask,
                            &(gcpu->vmexit_setup.processor_ctrls2));

//VMM_LOG(mask_anonymous, level_trace,"calculate_processor_ctrls2: final_mask=%P\n", final_mask);
    return (UINT32)GET_FINAL_SETTINGS( gcpu, processor_ctrls2, final_mask );
}

void gcpu_set_processor_ctrls2_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT64 value )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(vmcs);

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( g_processor_ctrls2_supported == TRUE );

    if (vmcs_read( vmcs, VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS ) != value )
    {
//VMM_LOG(mask_anonymous, level_trace,"set_processor_ctrls2: value=%P\n", value);
        vmcs_write( vmcs, VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS, value );
    }
}

UINT64 gcpu_get_processor_ctrls2_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    VMM_ASSERT( g_processor_ctrls2_supported == TRUE );

    return vmcs_read( vmcs, VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS );
}

INLINE
UINT32 calculate_exceptions_map( GUEST_CPU_HANDLE gcpu, UINT32 request, UINT32 bitmask,
                                 EXCEPTIONS_POLICY_TYPE* pf_policy)
{
    IA32_VMCS_EXCEPTION_BITMAP exceptions;

    VMM_ASSERT( pf_policy );

    exceptions.Uint32 = (UINT32)gcpu_update_control_counters(
                                request,
                                bitmask,
                                &(gcpu->vmexit_setup.exceptions_ctrls));

    *pf_policy = (exceptions.Bits.PF) ?
            EXCEPTIONS_POLICY_CATCH_ALL : EXCEPTIONS_POLICY_CATCH_NOTHING;

//VMM_LOG(mask_anonymous, level_trace,"calculate_exceptions_map: exceptions.Uint32=%P\n", exceptions.Uint32);
    return (UINT32)GET_FINAL_SETTINGS( gcpu, exceptions_ctrls, exceptions.Uint32 );
}

void gcpu_set_exceptions_map_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT64 value)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    if (vmcs_read( vmcs, VMCS_EXCEPTION_BITMAP ) != value )
    {
//        VMM_LOG(mask_anonymous, level_trace,"set_exceptions_map CPU#%d: value=%P\n", hw_cpu_id(), value);
        vmcs_write( vmcs, VMCS_EXCEPTION_BITMAP, value );
    }

}

void gcpu_get_pf_error_code_mask_and_match_layered(GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32* pf_mask, UINT32* pf_match)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    *pf_mask = (UINT32)vmcs_read(vmcs, VMCS_PAGE_FAULT_ERROR_CODE_MASK);
    *pf_match = (UINT32)vmcs_read(vmcs, VMCS_PAGE_FAULT_ERROR_CODE_MATCH);
}

void gcpu_set_pf_error_code_mask_and_match_layered(GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32 pf_mask, UINT32 pf_match)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    vmcs_write(vmcs, VMCS_PAGE_FAULT_ERROR_CODE_MASK, pf_mask);
    vmcs_write(vmcs, VMCS_PAGE_FAULT_ERROR_CODE_MATCH, pf_match);
}

UINT64 gcpu_get_exceptions_map_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    return vmcs_read( vmcs, VMCS_EXCEPTION_BITMAP );
}

INLINE
UINT32 calculate_exit_ctrls( GUEST_CPU_HANDLE gcpu, UINT32 request, UINT32 bitmask )
{
    UINT32 final_mask;

    final_mask = (UINT32)gcpu_update_control_counters(
                            request,
                            bitmask,
                            &(gcpu->vmexit_setup.vm_exit_ctrls));

//VMM_LOG(mask_anonymous, level_trace,"calculate_exit_ctrls: final_mask=%P\n", final_mask);
    return (UINT32)GET_FINAL_SETTINGS( gcpu, vm_exit_ctrls, final_mask );
}

void gcpu_set_exit_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32 value )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    if (vmcs_read( vmcs, VMCS_EXIT_CONTROL_VECTOR ) != value )
    {
        vmcs_write( vmcs, VMCS_EXIT_CONTROL_VECTOR, value );
    }
}

UINT32 gcpu_get_exit_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    return (UINT32) vmcs_read( vmcs, VMCS_EXIT_CONTROL_VECTOR );
}

INLINE
UINT32 calculate_enter_ctrls( GUEST_CPU_HANDLE gcpu, UINT32 request, UINT32 bitmask )
{
    UINT32 final_mask;

    final_mask = (UINT32)gcpu_update_control_counters(
                            request,
                            bitmask,
                            &(gcpu->vmexit_setup.vm_entry_ctrls));

//VMM_LOG(mask_anonymous, level_trace,"calculate_enter_ctrls: final_mask=%P\n", final_mask);
    return (UINT32)GET_FINAL_SETTINGS( gcpu, vm_entry_ctrls, final_mask );
}

void gcpu_set_enter_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level, UINT32 value )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    if (vmcs_read( vmcs, VMCS_ENTER_CONTROL_VECTOR ) != value )
    {
//VMM_LOG(mask_anonymous, level_trace,"set_enter_ctrls: value=%P\n", value);
        vmcs_write( vmcs, VMCS_ENTER_CONTROL_VECTOR, value );
    }
}

static
void gcpu_set_enter_ctrls_for_addons( GUEST_CPU_HANDLE gcpu, UINT32 value, UINT32 bits_untouched )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, VMCS_LEVEL_0);
    VMM_ASSERT(vmcs);
    vmcs_update(vmcs, VMCS_ENTER_CONTROL_VECTOR, value, ~bits_untouched);
}



UINT32 gcpu_get_enter_ctrls_layered( GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs_layered(gcpu, level);
    VMM_ASSERT(vmcs);

    return  (UINT32)vmcs_read( vmcs, VMCS_ENTER_CONTROL_VECTOR );
}

static
void request_vmexit_on_cr0(       GUEST_CPU_HANDLE gcpu,
                                  UINT64       bit_request,
                                  UINT64       bit_mask )

{
    UINT64              cr0_mask;

    VMCS_OBJECT* vmcs;
    UINT64 cr0_value, cr0_read_shadow_value;

    cr0_mask = calculate_cr0_reg_mask( gcpu, bit_request, bit_mask );
    gcpu_set_cr0_reg_mask_layered( gcpu, VMCS_LEVEL_0, cr0_mask );

    vmcs= gcpu_get_vmcs(gcpu);
    cr0_value  = vmcs_read(vmcs, VMCS_GUEST_CR0);
    cr0_read_shadow_value  = vmcs_read(vmcs, VMCS_CR0_READ_SHADOW);
    
    //   Clear the mask bits that it has been set in cr0 minimal_1_settings,
    //   since these bits are controlled by the host.
    cr0_mask = cr0_mask & ~(gcpu)->vmexit_setup.cr0.minimal_1_settings;

    //1. Keep the original shadow bit corresponding the zero bit in the 
    //   cr0_mask.
    //2. Update the shadow bit based on the cr0 value correspoinding the
    //   set bit in the cr0_mask.
    vmcs_write(vmcs, VMCS_CR0_READ_SHADOW, (cr0_read_shadow_value & ~cr0_mask)
                    |(cr0_value & cr0_mask));
}

static
void request_vmexit_on_cr4(       GUEST_CPU_HANDLE gcpu,
                                  UINT64       bit_request,
                                  UINT64       bit_mask )
{
    UINT64              cr4_mask;

    VMCS_OBJECT* vmcs;
    UINT64 cr4_value, cr4_read_shadow_value;

    cr4_mask = calculate_cr4_reg_mask( gcpu, bit_request, bit_mask );
    gcpu_set_cr4_reg_mask_layered( gcpu, VMCS_LEVEL_0, cr4_mask );

    vmcs= gcpu_get_vmcs(gcpu);
    cr4_value  = vmcs_read(vmcs, VMCS_GUEST_CR4);
    cr4_read_shadow_value  = vmcs_read(vmcs, VMCS_CR4_READ_SHADOW);

    //   Clear the mask bits that it has been set in cr4 minimal_1_settings,
    //   since these bits are controlled by the host.
    cr4_mask = cr4_mask & ~(gcpu)->vmexit_setup.cr4.minimal_1_settings;

    //1. Keep the original shadow bit corresponding the zero bit in the 
    //   cr4_mask.
    //2. Update the shadow bit based on the cr4 value correspoinding the
    //   set bit in the cr4_mask.
    vmcs_write(vmcs, VMCS_CR4_READ_SHADOW, (cr4_read_shadow_value & ~cr4_mask)
                    |(cr4_value & cr4_mask));

}

static
void update_pfs_setup( GUEST_CPU_HANDLE gcpu, EXCEPTIONS_POLICY_TYPE policy )
{
	IA32_VMCS_EXCEPTION_BITMAP exceptions;
    // setup page faults
    
    exceptions.Uint32 = (UINT32)gcpu_get_exceptions_map_layered( gcpu, VMCS_LEVEL_0);
    switch (policy)
    {
        case EXCEPTIONS_POLICY_CATCH_NOTHING:
            // do not exit on Page Faults at all
            gcpu_set_pf_error_code_mask_and_match_layered(gcpu, VMCS_LEVEL_0, 0, ((exceptions.Bits.PF) ? ((UINT32)-1) : 0));
            break;

        case EXCEPTIONS_POLICY_CATCH_ALL:
            // do exit on all Page Faults
            gcpu_set_pf_error_code_mask_and_match_layered(gcpu, VMCS_LEVEL_0, 0, ((exceptions.Bits.PF) ? 0 : ((UINT32)-1)));
            break;

        default:
            VMM_LOG(mask_anonymous, level_trace,"update_pfs_setup: Unknown policy type: %d\n", policy);
            VMM_ASSERT( FALSE );
    }
}

static
void request_vmexit_on_exceptions(GUEST_CPU_HANDLE gcpu,
                                  UINT32       bit_request,
                                  UINT32       bit_mask )
{
    UINT32                  except_map;
    EXCEPTIONS_POLICY_TYPE  pf_policy;

    except_map = calculate_exceptions_map(  gcpu, bit_request, bit_mask, &pf_policy );
    gcpu_set_exceptions_map_layered( gcpu, VMCS_LEVEL_0, except_map);
    update_pfs_setup(gcpu, pf_policy);
}

static
void request_vmexit_on_pin_ctrls( GUEST_CPU_HANDLE gcpu,
                                  UINT32       bit_request,
                                  UINT32       bit_mask )
{
    UINT32              pin_ctrls;

    pin_ctrls = calculate_pin_ctrls( gcpu, bit_request, bit_mask );
    gcpu_set_pin_ctrls_layered( gcpu, VMCS_LEVEL_0, pin_ctrls );
}

static
void request_vmexit_on_proc_ctrls(GUEST_CPU_HANDLE gcpu,
                                  UINT32       bit_request,
                                  UINT32       bit_mask )
{
    UINT32              proc_ctrls;

    proc_ctrls = calculate_processor_ctrls( gcpu, bit_request, bit_mask );
    gcpu_set_processor_ctrls_layered( gcpu, VMCS_LEVEL_0, proc_ctrls );
}

static
void request_vmexit_on_proc_ctrls2(GUEST_CPU_HANDLE gcpu,
                                  UINT32       bit_request,
                                  UINT32       bit_mask )
{
    UINT32              proc_ctrls2;

    if (g_processor_ctrls2_supported)
    {
        proc_ctrls2 = calculate_processor_ctrls2( gcpu, bit_request, bit_mask );
        gcpu_set_processor_ctrls2_layered( gcpu, VMCS_LEVEL_0, proc_ctrls2 );
    }
}

static
void request_vmexit_on_vm_enter_ctrls(
                                  GUEST_CPU_HANDLE gcpu,
                                  UINT32       bit_request,
                                  UINT32       bit_mask )
{
    UINT32            vm_enter_ctrls;
    VM_ENTRY_CONTROLS dont_touch;

    /* Do not change IA32e Guest mode here. It is changed as part of EFER!!!!!
    */
    dont_touch.Uint32 = 0;
    dont_touch.Bits.Ia32eModeGuest = 1;

    vm_enter_ctrls = calculate_enter_ctrls( gcpu, bit_request, bit_mask );
    gcpu_set_enter_ctrls_for_addons( gcpu, vm_enter_ctrls, dont_touch.Uint32);
}

static
void request_vmexit_on_vm_exit_ctrls(
                                  GUEST_CPU_HANDLE gcpu,
                                  UINT32       bit_request,
                                  UINT32       bit_mask )
{
    UINT32              vm_exit_ctrls;

    vm_exit_ctrls = calculate_exit_ctrls( gcpu, bit_request, bit_mask );
    gcpu_set_exit_ctrls_layered( gcpu, VMCS_LEVEL_0, vm_exit_ctrls );
}

static
void gcpu_apply_ctrols2( GUEST_CPU_HANDLE gcpu )
{
    request_vmexit_on_proc_ctrls2( gcpu, 0, 0 );
}

static
void gcpu_apply_all( GUEST_CPU_HANDLE gcpu )
{
//    VMM_LOG(mask_anonymous, level_trace,"gcpu_apply_all CPU#%d\n", hw_cpu_id());
    request_vmexit_on_pin_ctrls( gcpu, 0, 0 );
    request_vmexit_on_proc_ctrls( gcpu, 0, 0 );
    request_vmexit_on_proc_ctrls2( gcpu, 0, 0 );
    request_vmexit_on_exceptions( gcpu, 0, 0 );
    request_vmexit_on_vm_exit_ctrls( gcpu, 0, 0 );
    request_vmexit_on_vm_enter_ctrls( gcpu, 0, 0 );
    request_vmexit_on_cr0( gcpu, 0, 0 );
    request_vmexit_on_cr4( gcpu, 0, 0 );
}

//
// Setup minimal controls for Guest CPU
//
static
void gcpu_minimal_controls( GUEST_CPU_HANDLE gcpu )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    UINT32       idx;
    const VMCS_HW_CONSTRAINTS* vmx_constraints = vmcs_hw_get_vmx_constraints();

    VMM_ASSERT( vmcs );

    init_minimal_controls( gcpu );
    gcpu_apply_all( gcpu );

    //
    // Disable CR3 Target Values by setting the count to 0
    //
    //
    // Disable CR3 Target Values by setting the count to 0 and all the values to 0xFFFFFFFF
    //
    vmcs_write( vmcs, VMCS_CR3_TARGET_COUNT, 0);
    for (idx = 0; idx < vmx_constraints->number_of_cr3_target_values; ++idx)
    {
        vmcs_write(vmcs, (VMCS_FIELD)VMCS_CR3_TARGET_VALUE(idx), UINT64_ALL_ONES);
    }

    //
    // Set additional required fields
    //
    vmcs_write( vmcs, VMCS_GUEST_WORKING_VMCS_PTR, UINT64_ALL_ONES );

    vmcs_write(vmcs, VMCS_GUEST_SYSENTER_CS, hw_read_msr(IA32_MSR_SYSENTER_CS));
    vmcs_write(vmcs, VMCS_GUEST_SYSENTER_ESP, hw_read_msr(IA32_MSR_SYSENTER_ESP));
    vmcs_write(vmcs, VMCS_GUEST_SYSENTER_EIP, hw_read_msr(IA32_MSR_SYSENTER_EIP));
    vmcs_write(vmcs, VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, hw_read_msr(IA32_MSR_PERF_GLOBAL_CTRL));
}

// ---------------------------- APIs  ---------------------------------------

//----------------------------------------------------------------------------
//
// Apply default policy to gcpu
//
//----------------------------------------------------------------------------
void guest_cpu_control_setup( GUEST_CPU_HANDLE gcpu )
{
    //VMM_ASSERT( 0 == hw_cpu_id() );
    VMM_ASSERT( gcpu );

    lock_initialize( &(gcpu->vmexit_setup.lock) );

    gcpu_minimal_controls( gcpu );

    msr_vmexit_activate(gcpu);
    io_vmexit_activate(gcpu);
}

void gcpu_temp_exceptions_setup( GUEST_CPU_HANDLE gcpu,
                                 GCPU_TEMP_EXCEPTIONS_SETUP action )
{
    // TODO: Rewrite!!!
    // TODO: THIS WILL NOT WORK
    VMM_ASSERT( FALSE );

    switch (action)
    {
    case GCPU_TEMP_EXIT_ON_INTR_UNBLOCK:
        {
            PROCESSOR_BASED_VM_EXECUTION_CONTROLS proc_ctrl;

            proc_ctrl.Uint32 = 0;
            proc_ctrl.Bits.VirtualInterrupt = 1;

//            gcpu->vmexit_setup.processor_ctrls.enforce_1_settings |= proc_ctrl.Uint32;
//            gcpu->vmexit_setup.processor_ctrls.enforce_0_settings |= proc_ctrl.Uint32;
            //VMM_LOG(mask_anonymous, level_trace,"GCPU_TEMP_EXIT_ON_INTR_UNBLOCK CPU#%d\n", hw_cpu_id());
            request_vmexit_on_proc_ctrls( gcpu, 0, 0);
        }
        break;

    case GCPU_TEMP_NO_EXIT_ON_INTR_UNBLOCK:
        {
            PROCESSOR_BASED_VM_EXECUTION_CONTROLS proc_ctrl;

            proc_ctrl.Uint32 = 0;
            proc_ctrl.Bits.VirtualInterrupt = 1;

//            gcpu->vmexit_setup.processor_ctrls.enforce_1_settings &= ~(UINT64)proc_ctrl.Uint32;
//            gcpu->vmexit_setup.processor_ctrls.enforce_0_settings |= proc_ctrl.Uint32;
            //VMM_LOG(mask_anonymous, level_trace,"GCPU_TEMP_NO_EXIT_ON_INTR_UNBLOCK CPU#%d\n", hw_cpu_id());
            request_vmexit_on_proc_ctrls( gcpu, 0, 0);
        }
        break;

    default:
        VMM_LOG(mask_anonymous, level_trace,"Unknown GUEST_TEMP_EXCEPTIONS_SETUP action: %d\n", action);
        VMM_DEADLOOP();
    }
}

void gcpu_control_setup_only( GUEST_CPU_HANDLE gcpu, const VMEXIT_CONTROL* request )
{
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( gcpu );
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( request );

    lock_acquire( &(gcpu->vmexit_setup.lock) );

    if (request->cr0.bit_mask != 0)
    {
        gcpu_update_control_counters( request->cr0.bit_request,
                                      request->cr0.bit_mask,
                                      &(gcpu->vmexit_setup.cr0) );
    }

    if (request->cr4.bit_mask != 0)
    {
        gcpu_update_control_counters( request->cr4.bit_request,
                                      request->cr4.bit_mask,
                                      &(gcpu->vmexit_setup.cr4) );
    }

    if (request->exceptions.bit_mask != 0)
    {
        gcpu_update_control_counters( request->exceptions.bit_request,
                                      request->exceptions.bit_mask,
                                      &(gcpu->vmexit_setup.exceptions_ctrls) );
    }

    if (request->pin_ctrls.bit_mask != 0)
    {
        gcpu_update_control_counters( request->pin_ctrls.bit_request,
                                      request->pin_ctrls.bit_mask,
                                      &(gcpu->vmexit_setup.pin_ctrls) );
    }

    if (request->proc_ctrls.bit_mask != 0)
    {
        gcpu_update_control_counters( request->proc_ctrls.bit_request,
                                      request->proc_ctrls.bit_mask,
                                      &(gcpu->vmexit_setup.processor_ctrls) );
    }

    if (request->proc_ctrls2.bit_mask != 0)
    {
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT( g_processor_ctrls2_supported == TRUE );

        gcpu_update_control_counters( request->proc_ctrls2.bit_request,
                                      request->proc_ctrls2.bit_mask,
                                      &(gcpu->vmexit_setup.processor_ctrls2) );
    }

    if (request->vm_enter_ctrls.bit_mask != 0)
    {
        gcpu_update_control_counters( request->vm_enter_ctrls.bit_request,
                                      request->vm_enter_ctrls.bit_mask,
                                      &(gcpu->vmexit_setup.vm_entry_ctrls) );
    }

    if (request->vm_exit_ctrls.bit_mask != 0)
    {
        gcpu_update_control_counters( request->vm_exit_ctrls.bit_request,
                                      request->vm_exit_ctrls.bit_mask,
                                      &(gcpu->vmexit_setup.vm_exit_ctrls) );
    }

    lock_release( &(gcpu->vmexit_setup.lock) );

}

void gcpu_control_apply_only( GUEST_CPU_HANDLE gcpu )
{
    lock_acquire( &(gcpu->vmexit_setup.lock) );
    gcpu_apply_all( gcpu );
    lock_release( &(gcpu->vmexit_setup.lock) );
}

void gcpu_control2_apply_only( GUEST_CPU_HANDLE gcpu )
{
    lock_acquire( &(gcpu->vmexit_setup.lock) );
    gcpu_apply_ctrols2( gcpu );
    lock_release( &(gcpu->vmexit_setup.lock) );
}

BOOLEAN gcpu_cr3_virtualized( GUEST_CPU_HANDLE gcpu )
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS proc_ctrl;

    proc_ctrl.Uint32 = (UINT32)(gcpu->vmexit_setup.processor_ctrls.bit_field);
    return (proc_ctrl.Bits.Cr3Store && proc_ctrl.Bits.Cr3Load);
}


////////////////////////////////////////////////////
////////////////////////////////////////////////////

/*
*   Enforce settings on hardware VMCS only
*   these changes are not reflected in vmcs#0
*/
void gcpu_enforce_settings_on_hardware(
    GUEST_CPU_HANDLE            gcpu,
    GCPU_TEMP_EXCEPTIONS_SETUP  action)
{
    switch (action)
    {
    case GCPU_TEMP_EXCEPTIONS_EXIT_ON_ALL:
        // enforce all exceptions vmexit
        gcpu_exceptions_settings_enforce_on_hw(gcpu, UINT32_ALL_ONES, UINT32_ALL_ONES);
        break;

    case GCPU_TEMP_EXIT_ON_PF_AND_CR3:
        {
            PROCESSOR_BASED_VM_EXECUTION_CONTROLS proc_ctrl;
            IA32_VMCS_EXCEPTION_BITMAP            exceptions;

            // enforce all PF vmexits
            exceptions.Uint32 = 0;
            exceptions.Bits.PF = 1;
            gcpu_exceptions_settings_enforce_on_hw(gcpu, UINT32_ALL_ONES, exceptions.Uint32);

            // enforce CR3 access vmexit
            proc_ctrl.Uint32  = 0;
            proc_ctrl.Bits.Cr3Load = 1;
            proc_ctrl.Bits.Cr3Store = 1;
            gcpu_proc_ctrls_enforce_on_hw(gcpu, UINT32_ALL_ONES, proc_ctrl.Uint32);
        }
        break;

    case GCPU_TEMP_EXCEPTIONS_RESTORE_ALL:
        // reset to normal exceptions vmexit
        gcpu_exceptions_settings_restore_on_hw(gcpu);
        break;

    case GCPU_TEMP_RESTORE_PF_AND_CR3:
        // reset to normal exceptions vmexit
        gcpu_exceptions_settings_restore_on_hw(gcpu);
        // reset to normal CR3 vmexits
        gcpu_proc_ctrls_restore_on_hw(gcpu);
        break;

    case GCPU_TEMP_CR0_NO_EXIT_ON_WP:
        // do not vmexit when guest changes CR0.WP bit
        gcpu_cr0_mask_enforce_on_hw(gcpu,
                BITMAP_GET64(UINT64_ALL_ONES, ~CR0_WP), // clr CR0_WP bit only
                0);                                     // not set requirements
        break;

    case GCPU_TEMP_CR0_RESTORE_WP:
        // do vmexit when guest changes CR0.WP bit
        gcpu_cr0_mask_enforce_on_hw(gcpu,
                UINT64_ALL_ONES,                        // no clr requirements
                CR0_WP);                                // set CR0_WP bit only
        break;

    default:
        VMM_LOG(mask_anonymous, level_trace,"Unknown GUEST_TEMP_EXCEPTIONS_SETUP action: %d\n", action);
        // BEFORE_VMLAUNCH. This case should not happen.
        VMM_DEADLOOP();
    }

}

static
void gcpu_exceptions_settings_enforce_on_hw(
        GUEST_CPU_HANDLE  gcpu,
        UINT32            zeroes,
        UINT32            ones
        )
{
    IA32_VMCS_EXCEPTION_BITMAP exceptions;
    exceptions.Uint32 = (UINT32)gcpu_get_exceptions_map_layered( gcpu, VMCS_MERGED);
    exceptions.Uint32 = APPLY_ZEROES_AND_ONES(exceptions.Uint32, zeroes, ones);
    exceptions.Uint32 = (UINT32)GET_FINAL_SETTINGS(gcpu, exceptions_ctrls, exceptions.Uint32);
    gcpu_set_exceptions_map_layered( gcpu, VMCS_MERGED, exceptions.Uint32);
    update_pfs_setup(gcpu, exceptions.Bits.PF ? EXCEPTIONS_POLICY_CATCH_ALL : EXCEPTIONS_POLICY_CATCH_NOTHING);
}

static
void gcpu_exceptions_settings_restore_on_hw(GUEST_CPU_HANDLE  gcpu)
{
    if ( ! gcpu_is_vmcs_layered(gcpu))
    {
        IA32_VMCS_EXCEPTION_BITMAP exceptions;
        exceptions.Uint32 = (UINT32)gcpu->vmexit_setup.exceptions_ctrls.bit_field;
        exceptions.Uint32 = (UINT32)GET_FINAL_SETTINGS(gcpu, exceptions_ctrls, exceptions.Uint32);
        gcpu_set_exceptions_map_layered(gcpu, VMCS_MERGED, exceptions.Uint32);
        update_pfs_setup(gcpu, exceptions.Bits.PF ? EXCEPTIONS_POLICY_CATCH_ALL : EXCEPTIONS_POLICY_CATCH_NOTHING);
    }
}

static
void gcpu_proc_ctrls_enforce_on_hw(GUEST_CPU_HANDLE   gcpu,
                                   UINT32             zeroes,
                                   UINT32             ones)
{
    UINT32 proc_ctrls = (UINT32)gcpu_get_processor_ctrls_layered(gcpu, VMCS_MERGED);
    proc_ctrls = APPLY_ZEROES_AND_ONES(proc_ctrls, zeroes, ones);
    proc_ctrls = (UINT32)GET_FINAL_SETTINGS(gcpu, processor_ctrls, proc_ctrls);
    gcpu_set_processor_ctrls_layered(gcpu, VMCS_MERGED, proc_ctrls);
}

static
void gcpu_proc_ctrls_restore_on_hw(GUEST_CPU_HANDLE   gcpu)
{
    if ( ! gcpu_is_vmcs_layered(gcpu))
    {
        UINT32 proc_ctrls = (UINT32)gcpu->vmexit_setup.processor_ctrls.bit_field;
        proc_ctrls = (UINT32)GET_FINAL_SETTINGS(gcpu, processor_ctrls, proc_ctrls);
        gcpu_set_processor_ctrls_layered(gcpu, VMCS_MERGED, proc_ctrls);
    }
}

static
void gcpu_cr0_mask_enforce_on_hw(GUEST_CPU_HANDLE   gcpu,
                                 UINT64             zeroes,
                                 UINT64             ones)
{
    UINT64 cr0_mask = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_MERGED);
    cr0_mask = APPLY_ZEROES_AND_ONES(cr0_mask, zeroes, ones);
    cr0_mask = GET_FINAL_SETTINGS(gcpu, cr0, cr0_mask);
    gcpu_set_cr0_reg_mask_layered(gcpu, VMCS_MERGED, cr0_mask);
}

extern UINT64 ept_get_eptp(GUEST_CPU_HANDLE gcpu);
extern BOOLEAN ept_set_eptp(GUEST_CPU_HANDLE gcpu, UINT64 ept_root_table_hpa, UINT32 gaw);
extern GUEST_CPU_HANDLE scheduler_get_current_gcpu_for_guest( GUEST_ID guest_id );

BOOLEAN vmm_get_vmcs_control_state(GUEST_CPU_HANDLE gcpu, VMM_CONTROL_STATE ControlStateId, VMM_CONTROLS* value)
{
	VMCS_OBJECT* vmcs;
	VMCS_FIELD vmcs_field_id;

	VMM_ASSERT(gcpu);

	vmcs = gcpu_get_vmcs(gcpu);
	VMM_ASSERT(vmcs);

	if(!value || (UINT32)ControlStateId > (UINT32)NUM_OF_VMM_CONTROL_STATE - 1)
		return FALSE;

	// VMCS_FIELD and VMM_CONTROL_STATE are not identically mapped.
	if(ControlStateId < VMM_CR3_TARGET_VALUE_0){
		vmcs_field_id = (VMCS_FIELD)ControlStateId;
	}else{
		vmcs_field_id = (VMCS_FIELD)(VMCS_CR3_TARGET_VALUE_0 + (ControlStateId - VMM_CR3_TARGET_VALUE_0));
	}

	switch (vmcs_field_id){
	case VMCS_CONTROL_VECTOR_PIN_EVENTS:
		value->value = gcpu_get_pin_ctrls_layered(gcpu, VMCS_MERGED);
		break;
	case VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS:
		value->value = gcpu_get_processor_ctrls_layered(gcpu, VMCS_MERGED);
		break;
	case VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS:
		value->value = gcpu_get_processor_ctrls2_layered(gcpu, VMCS_MERGED);
		break;
	case VMCS_EXCEPTION_BITMAP:
		value->value = gcpu_get_exceptions_map_layered(gcpu, VMCS_MERGED);
		break;
	case VMCS_PAGE_FAULT_ERROR_CODE_MASK:
	case VMCS_PAGE_FAULT_ERROR_CODE_MATCH:
		gcpu_get_pf_error_code_mask_and_match_layered(gcpu, VMCS_MERGED, (UINT32*)&(value->mask_value.mask), (UINT32*)&(value->mask_value.value));
		break;
	case VMCS_CR0_MASK:
		value->value = gcpu_get_cr0_reg_mask_layered(gcpu, VMCS_MERGED);
		break;
	case VMCS_CR4_MASK:
		value->value = gcpu_get_cr4_reg_mask_layered(gcpu, VMCS_MERGED);
		break;
	case VMCS_EXIT_CONTROL_VECTOR:
		value->value = gcpu_get_exit_ctrls_layered(gcpu,VMCS_MERGED);
		break;
	case VMCS_EPTP_ADDRESS:
		value->value = ept_get_eptp(gcpu);
		break;

	default:
		value->value = vmcs_read(vmcs, vmcs_field_id);
		break;
	}

	return TRUE;
}

BOOLEAN vmm_set_vmcs_control_state(GUEST_CPU_HANDLE gcpu, VMM_CONTROL_STATE ControlStateId, VMM_CONTROLS* value)
{
	VMCS_OBJECT* vmcs;
	VMCS_FIELD vmcs_field_id;
#ifdef INCLUDE_UNUSED_CODE
	UINT64 cr3_count = 0;
#endif

	VMM_ASSERT(gcpu);

	vmcs = gcpu_get_vmcs(gcpu);
	VMM_ASSERT(vmcs);

	if(!value || (UINT32)ControlStateId > (UINT32)NUM_OF_VMM_CONTROL_STATE - 1)
		return FALSE;

	// VMCS_FIELD and VMM_CONTROL_STATE are not identically mapped.
	if(ControlStateId < VMM_CR3_TARGET_VALUE_0){
		vmcs_field_id = (VMCS_FIELD)ControlStateId;
	}else{
		vmcs_field_id = (VMCS_FIELD)(VMCS_CR3_TARGET_VALUE_0 + (ControlStateId - VMM_CR3_TARGET_VALUE_0));
	}

	switch (vmcs_field_id){
	case VMCS_CONTROL_VECTOR_PIN_EVENTS:
		request_vmexit_on_pin_ctrls(gcpu, (UINT32)(value->mask_value.value), (UINT32)(value->mask_value.mask));
		break;
	case VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS:
		if(value->mask_value.mask)
		    request_vmexit_on_proc_ctrls(gcpu, (UINT32)(value->mask_value.value), (UINT32)(value->mask_value.mask));
		else
			vmcs_write(vmcs, VMCS_CONTROL_VECTOR_PROCESSOR_EVENTS, value->mask_value.value);
		break;
	case VMCS_CONTROL2_VECTOR_PROCESSOR_EVENTS:
		request_vmexit_on_proc_ctrls2(gcpu, (UINT32)(value->mask_value.value), (UINT32)(value->mask_value.mask));
		break;
	case VMCS_EXCEPTION_BITMAP:
		request_vmexit_on_exceptions(gcpu, (UINT32)(value->mask_value.value), (UINT32)(value->mask_value.mask));
		break;
	case VMCS_CR0_MASK:
		if(value->mask_value.mask  || ( (!value->mask_value.mask) && (!value->mask_value.value)))
		    request_vmexit_on_cr0(gcpu, (UINT32)(value->mask_value.value), (UINT32)(value->mask_value.mask));
		else
			vmcs_write(vmcs, VMCS_CR0_MASK, value->mask_value.value);
		break;
	case VMCS_CR4_MASK:
		if(value->mask_value.mask  || ( (!value->mask_value.mask) && (!value->mask_value.value)))
		    request_vmexit_on_cr4(gcpu, (UINT32)(value->mask_value.value), (UINT32)(value->mask_value.mask));
		else
			vmcs_write(vmcs, VMCS_CR4_MASK, value->mask_value.value);
		break;
	case VMCS_EXIT_CONTROL_VECTOR:
		gcpu_set_exit_ctrls_layered(gcpu,VMCS_MERGED, (UINT32)(value->value));
		break;
	case VMCS_MSR_BITMAP_ADDRESS:
		vmcs_write(vmcs, VMCS_MSR_BITMAP_ADDRESS, value->value);
		break;
    case VMCS_EPTP_INDEX:
        vmcs_write(vmcs, VMCS_EPTP_INDEX, value->value);
        break;
	case VMCS_EPTP_ADDRESS:
		return ept_set_eptp(gcpu, value->ept_value.ept_root_table_hpa, (UINT32)(value->ept_value.gaw));
#ifdef INCLUDE_UNUSED_CODE
	case VMCS_CR3_TARGET_COUNT:
		vmcs_write(vmcs, VMCS_CR3_TARGET_COUNT, value->cr3.cr3_count);
		break;
	case VMCS_CR3_TARGET_VALUE_0:
		cr3_count = vmcs_read(vmcs, VMCS_CR3_TARGET_COUNT);
		if(!cr3_count)
			return FALSE;
		vmcs_write(vmcs, VMCS_CR3_TARGET_VALUE_0, value->cr3.cr3_value[0]);
		break;
	case VMCS_CR3_TARGET_VALUE_1:
		cr3_count = vmcs_read(vmcs, VMCS_CR3_TARGET_COUNT);
		if(cr3_count < 2)
			return FALSE;
		vmcs_write(vmcs, VMCS_CR3_TARGET_VALUE_1, value->cr3.cr3_value[1]);
		break;
	case VMCS_CR3_TARGET_VALUE_2:
		cr3_count = vmcs_read(vmcs, VMCS_CR3_TARGET_COUNT);
		if(cr3_count < 3)
			return FALSE;
		vmcs_write(vmcs, VMCS_CR3_TARGET_VALUE_2, value->cr3.cr3_value[2]);
		break;
	case VMCS_CR3_TARGET_VALUE_3:
		cr3_count = vmcs_read(vmcs, VMCS_CR3_TARGET_COUNT);
		if(cr3_count < 4)
			return FALSE;
		vmcs_write(vmcs, VMCS_CR3_TARGET_VALUE_3, value->cr3.cr3_value[3]);
		break;
#endif
	case VMCS_PAGE_FAULT_ERROR_CODE_MATCH:
		//add new func in vmm
		//TBD
		return FALSE;
	case VMCS_VPID:
	case VMCS_PAGE_FAULT_ERROR_CODE_MASK:
	case VMCS_ENTER_CONTROL_VECTOR:
	case VMCS_ENTER_INTERRUPT_INFO:
	case VMCS_ENTER_EXCEPTION_ERROR_CODE:
	case VMCS_ENTER_INSTRUCTION_LENGTH:
		// Not supported. Will support later if required. TBD.
		return FALSE;

	default:
		// Not supported or read-only.
		return FALSE;
	}

	return TRUE;
}
