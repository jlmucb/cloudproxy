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

#include "vmcs_init.h"
#include "vmx_ctrl_msrs.h"
#include "vmx_vmcs.h"
#include "vmm_phys_mem_types.h"
#include "hw_utils.h"
#include "heap.h"
#include "libc.h"
#include "gpm_api.h"
#include "host_memory_manager_api.h"
#include "host_cpu.h"
#include "hw_vmx_utils.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMCS_INIT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMCS_INIT_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define MAX_32BIT_NUMBER 0x0FFFFFFFF
#define MASK_PE_PG_OFF_UNRESTRICTED_GUEST 0xFFFFFFFF7FFFFFFE


// Initialization of the VMCS
static IA32_VMX_CAPABILITIES g_vmx_capabilities;
void* g_vmx_capabilities_ptr = &g_vmx_capabilities;
static VMCS_HW_CONSTRAINTS   g_vmx_constraints;
static VMCS_HW_FIXED         g_vmx_fixed;
VMCS_HW_FIXED* gp_vmx_fixed = &g_vmx_fixed;
UINT64 g_vmx_fixed_1_cr0_save;

static BOOLEAN g_init_done = FALSE;

void print_vmx_capabilities( void );


// #define VMCS_REGION_SIZE g_vmx_capabilities.VmcsRevisionIdentifier.Bits.VmcsRegionSize
#define VMCS_REGION_SIZE (g_vmx_capabilities.VmcsRevisionIdentifier.Uint64&0x77777777)
#define VMCS_ABOVE_4G_SUPPORTED                                                 \
    (g_vmx_capabilities.VmcsRevisionIdentifier.Bits.PhysicalAddressWidth != 1)
#define VMCS_MAX_SIZE_OF_MSR_LISTS                                              \
    (g_vmx_capabilities.MiscellaneousData.Bits.MsrListsMaxSize + 1)*512
#define VMCS_MEMORY_TYPE    vmcs_memory_type()
#define VMCS_REVISION g_vmx_capabilities.VmcsRevisionIdentifier.Bits.RevisionIdentifier

#ifdef DEBUG
#define VMCS_FIXED_BIT_2_CHAR( field_name, bit_name )                           \
    fx_bit_2_char(g_vmx_fixed.fixed_0_ ## field_name .Bits. bit_name,        \
                  g_vmx_fixed.fixed_1_ ## field_name .Bits. bit_name)

INLINE char fx_bit_2_char( UINT32 mb0, UINT32 mb1 )
{
    return (mb0 != mb1) ? 'X' : (mb0 == 0) ? '0' : '1';
}
#endif

#define CAP_BIT_TO_CHAR( field_name, bit_name ) ((g_vmx_capabilities.field_name).Bits.bit_name + '0')


static void fill_vmx_capabilities( void )
{
#ifdef JLMDEBUG1
    bprint("At fill_vmx_capabilities 0x%016x\n", 
            g_vmx_capabilities.VmcsRevisionIdentifier.Uint64);
#endif
    g_vmx_capabilities.VmcsRevisionIdentifier.Uint64 = 
            hw_read_msr(IA32_MSR_VMCS_REVISION_IDENTIFIER_INDEX);
    g_vmx_capabilities.PinBasedVmExecutionControls.Uint64 = 
            hw_read_msr(IA32_MSR_PIN_BASED_VM_EXECUTION_CONTROLS_INDEX);
    g_vmx_capabilities.ProcessorBasedVmExecutionControls.Uint64 = 
            hw_read_msr(IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS_INDEX);
    g_vmx_capabilities.EptVpidCapabilities.Uint64 = 0;

    if (g_vmx_capabilities.ProcessorBasedVmExecutionControls.Bits.MayBeSetToOne.Bits.SecondaryControls) {
        g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Uint64= 
            hw_read_msr(IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS2_INDEX);

        if (g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Bits.EnableEPT
            || g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Bits.EnableVPID) {
            g_vmx_capabilities.EptVpidCapabilities.Uint64 = 
            hw_read_msr(IA32_MSR_EPT_VPID_CAP_INDEX);
        }
    }
    g_vmx_capabilities.VmExitControls.Uint64 = 
                hw_read_msr(IA32_MSR_VM_EXIT_CONTROLS_INDEX);
    g_vmx_capabilities.VmEntryControls.Uint64 = hw_read_msr(IA32_MSR_VM_ENTRY_CONTROLS_INDEX);
    g_vmx_capabilities.MiscellaneousData.Uint64 = 
                hw_read_msr(IA32_MSR_MISCELLANEOUS_DATA_INDEX);
    g_vmx_capabilities.Cr0MayBeSetToZero.Uint64 = 
                hw_read_msr(IA32_MSR_CR0_ALLOWED_ZERO_INDEX);
    g_vmx_capabilities.Cr0MayBeSetToOne.Uint64  = 
                hw_read_msr(IA32_MSR_CR0_ALLOWED_ONE_INDEX);
    g_vmx_capabilities.Cr4MayBeSetToZero.Uint64 = 
                hw_read_msr(IA32_MSR_CR4_ALLOWED_ZERO_INDEX);
    g_vmx_capabilities.Cr4MayBeSetToOne.Uint64  = 
                hw_read_msr(IA32_MSR_CR4_ALLOWED_ONE_INDEX);

    VMM_ASSERT( VMCS_REGION_SIZE != 0 );
    g_vmx_constraints.may1_pin_based_exec_ctrl.Uint32 = 
          g_vmx_capabilities.PinBasedVmExecutionControls.Bits.MayBeSetToOne.Uint32;
    g_vmx_constraints.may0_pin_based_exec_ctrl.Uint32 = 
          g_vmx_capabilities.PinBasedVmExecutionControls.Bits.MayBeSetToZero.Uint32;
    g_vmx_constraints.may1_processor_based_exec_ctrl.Uint32 = 
          g_vmx_capabilities.ProcessorBasedVmExecutionControls.Bits.MayBeSetToOne.Uint32;
    g_vmx_constraints.may0_processor_based_exec_ctrl.Uint32 = 
          g_vmx_capabilities.ProcessorBasedVmExecutionControls.Bits.MayBeSetToZero.Uint32;
    g_vmx_constraints.may1_processor_based_exec_ctrl2.Uint32 = 
          g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Uint32;
    g_vmx_constraints.may0_processor_based_exec_ctrl2.Uint32 = 
          g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToZero.Uint32;
    g_vmx_constraints.may1_vm_exit_ctrl.Uint32 = 
          g_vmx_capabilities.VmExitControls.Bits.MayBeSetToOne.Uint32;
    g_vmx_constraints.may0_vm_exit_ctrl.Uint32 = 
          g_vmx_capabilities.VmExitControls.Bits.MayBeSetToZero.Uint32;
    g_vmx_constraints.may1_vm_entry_ctrl.Uint32 = 
          g_vmx_capabilities.VmEntryControls.Bits.MayBeSetToOne.Uint32;
    g_vmx_constraints.may0_vm_entry_ctrl.Uint32 = 
          g_vmx_capabilities.VmEntryControls.Bits.MayBeSetToZero.Uint32;
    g_vmx_constraints.may1_cr0.Uint64 = g_vmx_capabilities.Cr0MayBeSetToOne.Uint64;
    g_vmx_constraints.may0_cr0.Uint64 = g_vmx_capabilities.Cr0MayBeSetToZero.Uint64;
    g_vmx_constraints.may1_cr4.Uint64 = g_vmx_capabilities.Cr4MayBeSetToOne.Uint64;
    g_vmx_constraints.may0_cr4.Uint64 = g_vmx_capabilities.Cr4MayBeSetToZero.Uint64;
    g_vmx_constraints.number_of_cr3_target_values = 
          g_vmx_capabilities.MiscellaneousData.Bits.NumberOfCr3TargetValues;
    g_vmx_constraints.max_msr_lists_size_in_bytes= VMCS_MAX_SIZE_OF_MSR_LISTS;
    g_vmx_constraints.vmx_timer_length  = g_vmx_capabilities.MiscellaneousData.Bits.PreemptionTimerLength;
    g_vmx_constraints.vmcs_revision  = VMCS_REVISION;
    g_vmx_constraints.mseg_revision_id = 
          g_vmx_capabilities.MiscellaneousData.Bits.MsegRevisionIdentifier;
    g_vmx_constraints.vm_entry_in_halt_state_supported = 
          g_vmx_capabilities.MiscellaneousData.Bits.EntryInHaltStateSupported;
    g_vmx_constraints.vm_entry_in_shutdown_state_supported  = 
          g_vmx_capabilities.MiscellaneousData.Bits.EntryInShutdownStateSupported;
    g_vmx_constraints.vm_entry_in_wait_for_sipi_state_supported = 
          g_vmx_capabilities.MiscellaneousData.Bits.EntryInWaitForSipiStateSupported;
    g_vmx_constraints.processor_based_exec_ctrl2_supported = 
          g_vmx_capabilities.ProcessorBasedVmExecutionControls.Bits.MayBeSetToOne.Bits.SecondaryControls;
    g_vmx_constraints.ept_supported = 
          g_vmx_constraints.processor_based_exec_ctrl2_supported &&
          g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Bits.EnableEPT;
    g_vmx_constraints.unrestricted_guest_supported = 
          g_vmx_constraints.processor_based_exec_ctrl2_supported &&
          g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Bits.UnrestrictedGuest;
    g_vmx_constraints.vpid_supported = g_vmx_constraints.processor_based_exec_ctrl2_supported &&
          g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Bits.EnableVPID;
#ifdef FAST_VIEW_SWITCH
    g_vmx_constraints.vmfunc_supported  = 
          g_vmx_constraints.processor_based_exec_ctrl2_supported &&
          g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Bits.Vmfunc;
    if ( g_vmx_constraints.vmfunc_supported ) {
        g_vmx_capabilities.VmFuncControls.Uint64 = 
                hw_read_msr(IA32_MSR_VMX_VMFUNC_CTRL);
        VMM_LOG(mask_anonymous, level_trace,"VmFuncCtrl                                   = %18P\n",g_vmx_capabilities.VmFuncControls.Uint64);
        if( g_vmx_capabilities.VmFuncControls.Bits.EptpSwitching ) {
            g_vmx_constraints.eptp_switching_supported = g_vmx_constraints.vmfunc_supported && g_vmx_capabilities.VmFuncControls.Bits.EptpSwitching ;
            VMM_LOG(mask_anonymous, level_trace,"EPTP switching supported...");
        }
    }
#endif
    g_vmx_constraints.ve_supported  = 
                g_vmx_constraints.processor_based_exec_ctrl2_supported &&
                g_vmx_capabilities.ProcessorBasedVmExecutionControls2.Bits.MayBeSetToOne.Bits.VE;
    if (g_vmx_constraints.ve_supported) {
    	VMM_LOG(mask_anonymous, level_trace,"VE supported...\n");
    }
    g_vmx_constraints.ept_vpid_capabilities = g_vmx_capabilities.EptVpidCapabilities;

    // determine fixed values
    g_vmx_fixed.fixed_1_pin_based_exec_ctrl.Uint32= 
                g_vmx_constraints.may0_pin_based_exec_ctrl.Uint32&
                g_vmx_constraints.may1_pin_based_exec_ctrl.Uint32;
    g_vmx_fixed.fixed_0_pin_based_exec_ctrl.Uint32= 
                g_vmx_constraints.may0_pin_based_exec_ctrl.Uint32|
                g_vmx_constraints.may1_pin_based_exec_ctrl.Uint32;
    g_vmx_fixed.fixed_1_processor_based_exec_ctrl.Uint32 =
                g_vmx_constraints.may0_processor_based_exec_ctrl.Uint32 &
                g_vmx_constraints.may1_processor_based_exec_ctrl.Uint32;
    g_vmx_fixed.fixed_0_processor_based_exec_ctrl.Uint32 =
                g_vmx_constraints.may0_processor_based_exec_ctrl.Uint32 |
                g_vmx_constraints.may1_processor_based_exec_ctrl.Uint32;
    g_vmx_fixed.fixed_1_processor_based_exec_ctrl2.Uint32 =
                g_vmx_constraints.may0_processor_based_exec_ctrl2.Uint32 &
                g_vmx_constraints.may1_processor_based_exec_ctrl2.Uint32;
    g_vmx_fixed.fixed_0_processor_based_exec_ctrl2.Uint32 =
                g_vmx_constraints.may0_processor_based_exec_ctrl2.Uint32 |
                g_vmx_constraints.may1_processor_based_exec_ctrl2.Uint32;
    g_vmx_fixed.fixed_1_vm_exit_ctrl.Uint32 = 
                g_vmx_constraints.may0_vm_exit_ctrl.Uint32 &
                g_vmx_constraints.may1_vm_exit_ctrl.Uint32;
    g_vmx_fixed.fixed_0_vm_exit_ctrl.Uint32 = 
                g_vmx_constraints.may0_vm_exit_ctrl.Uint32 |
                g_vmx_constraints.may1_vm_exit_ctrl.Uint32;
    g_vmx_fixed.fixed_1_vm_entry_ctrl.Uint32= 
                g_vmx_constraints.may0_vm_entry_ctrl.Uint32 &
                g_vmx_constraints.may1_vm_entry_ctrl.Uint32;
    g_vmx_fixed.fixed_0_vm_entry_ctrl.Uint32= 
                g_vmx_constraints.may0_vm_entry_ctrl.Uint32 |
                g_vmx_constraints.may1_vm_entry_ctrl.Uint32;
    g_vmx_fixed.fixed_1_cr0.Uint64  = g_vmx_constraints.may0_cr0.Uint64 &
                                      g_vmx_constraints.may1_cr0.Uint64;
    // If unrestricted guest is supported FIXED1 value should not have PG and PE 
    if (g_vmx_constraints.unrestricted_guest_supported){
    	g_vmx_fixed.fixed_1_cr0.Uint64 &= MASK_PE_PG_OFF_UNRESTRICTED_GUEST;
    }
    g_vmx_fixed.fixed_0_cr0.Uint64  = g_vmx_constraints.may0_cr0.Uint64 |
                                      g_vmx_constraints.may1_cr0.Uint64;
    g_vmx_fixed.fixed_1_cr4.Uint64 = g_vmx_constraints.may0_cr4.Uint64 &
                                              g_vmx_constraints.may1_cr4.Uint64;
    g_vmx_fixed.fixed_0_cr4.Uint64 = g_vmx_constraints.may0_cr4.Uint64 |
                                     g_vmx_constraints.may1_cr4.Uint64;
#ifdef JLMDEBUG1
   bprint(" fixed_0_cr0 fixed_1_cr0 fixed_0_cr4 fixed_1_cr4: 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
         g_vmx_fixed.fixed_0_cr0.Uint64, g_vmx_fixed.fixed_1_cr0.Uint64,
         g_vmx_fixed.fixed_0_cr4.Uint64, g_vmx_fixed.fixed_1_cr4.Uint64);
   bprint("gp_vmx_fixed: 0x%016lx\n", gp_vmx_fixed);
   bprint("Revision Identifiers 0x%016x\n", 
            g_vmx_capabilities.VmcsRevisionIdentifier.Uint64);
#endif
    VMM_DEBUG_CODE( print_vmx_capabilities() );
}

INLINE VMM_PHYS_MEM_TYPE vmcs_memory_type( void )
{
    switch (g_vmx_capabilities.VmcsRevisionIdentifier.Bits.VmcsMemoryType) {
        case 0: return( VMM_PHYS_MEM_UNCACHABLE );
        case 6: return( VMM_PHYS_MEM_WRITE_BACK );
        default:;
    }

    VMM_LOG(mask_anonymous, level_trace,"FATAL: Unsupported memory type for VMCS region in IA32_VMX_CAPABILITIES\n");
    VMM_ASSERT( FALSE );
    return VMM_PHYS_MEM_UNDEFINED;
}
#ifdef DEBUG
// Print capabilities
static void print_vmx_capabilities( void )
{
    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"---------------- Discovered VMX capabilities --------------\n");
    VMM_LOG(mask_anonymous, level_trace,"Legend:\n");
    VMM_LOG(mask_anonymous, level_trace,"    X - may  be set to 0 or 1\n");
    VMM_LOG(mask_anonymous, level_trace,"    0 - must be set to 0\n");
    VMM_LOG(mask_anonymous, level_trace,"    1 - must be set to 1\n");

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"Raw data values\n");
    VMM_LOG(mask_anonymous, level_trace,"===================================================== ==========================\n");
    VMM_LOG(mask_anonymous, level_trace,"VmcsRevisionIdentifier                              = %18P\n",g_vmx_capabilities.VmcsRevisionIdentifier.Uint64);
    VMM_LOG(mask_anonymous, level_trace,"PinBasedVmExecutionControls - may be set to 0       = %P\n",g_vmx_constraints.may0_pin_based_exec_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"PinBasedVmExecutionControls - may be set to 1       = %P\n",g_vmx_constraints.may1_pin_based_exec_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"ProcessorBasedVmExecutionControls - may be set to 0 = %P\n",g_vmx_constraints.may0_processor_based_exec_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"ProcessorBasedVmExecutionControls - may be set to 1 = %P\n",g_vmx_constraints.may1_processor_based_exec_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"ProcessorBasedVmExecutionControls2 - may be set to 0= %P\n",g_vmx_constraints.may0_processor_based_exec_ctrl2.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"ProcessorBasedVmExecutionControls2 - may be set to 1= %P\n",g_vmx_constraints.may1_processor_based_exec_ctrl2.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"VmExitControls - may be set to 0                    = %P\n",g_vmx_constraints.may0_vm_exit_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"VmExitControls - may be set to 1                    = %P\n",g_vmx_constraints.may1_vm_exit_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"VmEntryControls - may be set to 0                   = %P\n",g_vmx_constraints.may0_vm_entry_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"VmEntryControls - may be set to 1                   = %P\n",g_vmx_constraints.may1_vm_entry_ctrl.Uint32);
    VMM_LOG(mask_anonymous, level_trace,"MiscellaneousData                                   = %18P\n",g_vmx_capabilities.MiscellaneousData.Uint64);
    VMM_LOG(mask_anonymous, level_trace,"Cr0MayBeSetToZero                                   = %18P\n",g_vmx_capabilities.Cr0MayBeSetToZero.Uint64);
    VMM_LOG(mask_anonymous, level_trace,"Cr0MayBeSetToOne                                    = %18P\n",g_vmx_capabilities.Cr0MayBeSetToOne.Uint64);
    VMM_LOG(mask_anonymous, level_trace,"Cr4MayBeSetToZero                                   = %18P\n",g_vmx_capabilities.Cr4MayBeSetToZero.Uint64);
    VMM_LOG(mask_anonymous, level_trace,"Cr4MayBeSetToOne                                    = %18P\n",g_vmx_capabilities.Cr4MayBeSetToOne.Uint64);
    VMM_LOG(mask_anonymous, level_trace,"EptVPIDCapabilities                                 = %18P\n",g_vmx_capabilities.EptVpidCapabilities.Uint64);

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"Global data                                 Values\n");
    VMM_LOG(mask_anonymous, level_trace,"========================================= ===================\n");
    VMM_LOG(mask_anonymous, level_trace,"VMCS Revision Identifier                  = 0x%08X\n",    g_vmx_capabilities.VmcsRevisionIdentifier.Bits.RevisionIdentifier);
    VMM_LOG(mask_anonymous, level_trace,"VMCS Region Size                          = %d bytes\n",  g_vmx_capabilities.VmcsRevisionIdentifier.Bits.VmcsRegionSize);
    VMM_LOG(mask_anonymous, level_trace,"Physical Address Width                    = %d\n",        g_vmx_capabilities.VmcsRevisionIdentifier.Bits.PhysicalAddressWidth);
    VMM_LOG(mask_anonymous, level_trace,"Dual Monitor SMIs                         = %d\n",        g_vmx_capabilities.VmcsRevisionIdentifier.Bits.DualMonitorSystemManagementInterrupts);
    VMM_LOG(mask_anonymous, level_trace,"VMCS memory type                          = %s (%d)\n",        (vmcs_memory_type() == VMM_PHYS_MEM_UNCACHABLE) ? "UC" : "WB",  vmcs_memory_type());
    VMM_LOG(mask_anonymous, level_trace,"VMCS Instr Info on IO is Valid            = %c\n",        g_vmx_capabilities.VmcsRevisionIdentifier.Bits.VmcsInstructionInfoFieldOnIOisValid + '0' );
    VMM_LOG(mask_anonymous, level_trace,"VMX Timer Length                          = %d TSC ticks\n",  1 << g_vmx_capabilities.MiscellaneousData.Bits.PreemptionTimerLength);
    VMM_LOG(mask_anonymous, level_trace,"VmEntry in HLT State Supported            = %c\n",        g_vmx_constraints.vm_entry_in_halt_state_supported + '0');
    VMM_LOG(mask_anonymous, level_trace,"VmEntry in SHUTDOWN State Supported       = %c\n",        g_vmx_constraints.vm_entry_in_shutdown_state_supported + '0');
    VMM_LOG(mask_anonymous, level_trace,"VmEntry in Wait-For-SIPI State Supported  = %c\n",        g_vmx_constraints.vm_entry_in_wait_for_sipi_state_supported + '0');
    VMM_LOG(mask_anonymous, level_trace,"Number of CR3 Target Values               = %d\n",        g_vmx_constraints.number_of_cr3_target_values);
    VMM_LOG(mask_anonymous, level_trace,"Max Size of MSR Lists                     = %d bytes\n",  g_vmx_constraints.max_msr_lists_size_in_bytes);
    VMM_LOG(mask_anonymous, level_trace,"MSEG Revision Identifier                  = 0x%08x\n",    g_vmx_capabilities.MiscellaneousData.Bits.MsegRevisionIdentifier);

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"Pin-Based VM Execution Controls        Value\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"ExternalInterrupt                        %c\n",VMCS_FIXED_BIT_2_CHAR( pin_based_exec_ctrl, ExternalInterrupt ));
    VMM_LOG(mask_anonymous, level_trace,"HostInterrupt                            %c\n",VMCS_FIXED_BIT_2_CHAR( pin_based_exec_ctrl, HostInterrupt     ));
    VMM_LOG(mask_anonymous, level_trace,"Init                                     %c\n",VMCS_FIXED_BIT_2_CHAR( pin_based_exec_ctrl, Init              ));
    VMM_LOG(mask_anonymous, level_trace,"Nmi                                      %c\n",VMCS_FIXED_BIT_2_CHAR( pin_based_exec_ctrl, Nmi               ));
    VMM_LOG(mask_anonymous, level_trace,"Sipi                                     %c\n",VMCS_FIXED_BIT_2_CHAR( pin_based_exec_ctrl, Sipi              ));
    VMM_LOG(mask_anonymous, level_trace,"VirtualNmi                               %c\n",VMCS_FIXED_BIT_2_CHAR( pin_based_exec_ctrl, VirtualNmi        ));
    VMM_LOG(mask_anonymous, level_trace,"VmxTimer                                 %c\n",VMCS_FIXED_BIT_2_CHAR( pin_based_exec_ctrl, VmxTimer          ));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"Processor-Based VM Execution Controls  Value\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"SoftwareInterrupt                        %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, SoftwareInterrupt));
    VMM_LOG(mask_anonymous, level_trace,"TripleFault                              %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, TripleFault      ));
    VMM_LOG(mask_anonymous, level_trace,"VirtualInterrupt                         %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, VirtualInterrupt ));
    VMM_LOG(mask_anonymous, level_trace,"UseTscOffsetting                         %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, UseTscOffsetting ));
    VMM_LOG(mask_anonymous, level_trace,"TaskSwitch                               %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, TaskSwitch       ));
    VMM_LOG(mask_anonymous, level_trace,"Cpuid                                    %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Cpuid            ));
    VMM_LOG(mask_anonymous, level_trace,"GetSec                                   %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, GetSec           ));
    VMM_LOG(mask_anonymous, level_trace,"Hlt                                      %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Hlt              ));
    VMM_LOG(mask_anonymous, level_trace,"Invd                                     %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Invd             ));
    VMM_LOG(mask_anonymous, level_trace,"Invlpg                                   %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Invlpg           ));
    VMM_LOG(mask_anonymous, level_trace,"Mwait                                    %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Mwait            ));
    VMM_LOG(mask_anonymous, level_trace,"Rdpmc                                    %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Rdpmc            ));
    VMM_LOG(mask_anonymous, level_trace,"Rdtsc                                    %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Rdtsc            ));
    VMM_LOG(mask_anonymous, level_trace,"Rsm                                      %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Rsm              ));
    VMM_LOG(mask_anonymous, level_trace,"VmInstruction                            %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, VmInstruction    ));
    VMM_LOG(mask_anonymous, level_trace,"Cr3Load                                  %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Cr3Load          ));
    VMM_LOG(mask_anonymous, level_trace,"Cr3Store                                 %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Cr3Store         ));
    VMM_LOG(mask_anonymous, level_trace,"UseCr3Mask                               %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, UseCr3Mask       ));
    VMM_LOG(mask_anonymous, level_trace,"UseCr3ReadShadow                         %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, UseCr3ReadShadow ));
    VMM_LOG(mask_anonymous, level_trace,"Cr8Load                                  %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Cr8Load          ));
    VMM_LOG(mask_anonymous, level_trace,"Cr8Store                                 %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Cr8Store         ));
    VMM_LOG(mask_anonymous, level_trace,"TprShadow                                %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, TprShadow        ));
    VMM_LOG(mask_anonymous, level_trace,"NmiWindow                                %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, NmiWindow        ));
    VMM_LOG(mask_anonymous, level_trace,"MovDr                                    %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, MovDr            ));
    VMM_LOG(mask_anonymous, level_trace,"UnconditionalIo                          %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, UnconditionalIo  ));
    VMM_LOG(mask_anonymous, level_trace,"ActivateIoBitmaps                        %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, ActivateIoBitmaps));
    VMM_LOG(mask_anonymous, level_trace,"MsrProtection                            %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, MsrProtection    ));
    VMM_LOG(mask_anonymous, level_trace,"MonitorTrapFlag                          %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, MonitorTrapFlag  ));
    VMM_LOG(mask_anonymous, level_trace,"UseMsrBitmaps                            %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, UseMsrBitmaps    ));
    VMM_LOG(mask_anonymous, level_trace,"Monitor                                  %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Monitor          ));
    VMM_LOG(mask_anonymous, level_trace,"Pause                                    %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, Pause            ));
    VMM_LOG(mask_anonymous, level_trace,"SecondaryControls                        %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl, SecondaryControls));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"Processor-Based VM Execution Controls2  Value\n");
    VMM_LOG(mask_anonymous, level_trace,"(Valid only if SecondaryControls is not fixed 0)\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"VirtualizeAPIC                           %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, VirtualizeAPIC ));
    VMM_LOG(mask_anonymous, level_trace,"EnableEPT                                %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, EnableEPT ));
    VMM_LOG(mask_anonymous, level_trace,"Unrestricted Guest                       %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, UnrestrictedGuest ));
    VMM_LOG(mask_anonymous, level_trace,"DescriptorTableExiting                   %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, DescriptorTableExiting ));
    VMM_LOG(mask_anonymous, level_trace,"EnableRDTSCP                             %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, EnableRDTSCP ));
    VMM_LOG(mask_anonymous, level_trace,"EnableINVPCID                            %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, EnableINVPCID ));
    VMM_LOG(mask_anonymous, level_trace,"ShadowApicMsrs                           %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, ShadowApicMsrs ));
    VMM_LOG(mask_anonymous, level_trace,"EnableVPID                               %c\n",VMCS_FIXED_BIT_2_CHAR( processor_based_exec_ctrl2, EnableVPID ));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"VM Exit Controls                       Value\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"SaveCr0AndCr4                            %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveCr0AndCr4                  ));
    VMM_LOG(mask_anonymous, level_trace,"SaveCr3                                  %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveCr3                        ));
    VMM_LOG(mask_anonymous, level_trace,"SaveDebugControls                        %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveDebugControls              ));
    VMM_LOG(mask_anonymous, level_trace,"SaveSegmentRegisters                     %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveSegmentRegisters           ));
    VMM_LOG(mask_anonymous, level_trace,"SaveEspEipEflags                         %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveEspEipEflags               ));
    VMM_LOG(mask_anonymous, level_trace,"SavePendingDebugExceptions               %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SavePendingDebugExceptions     ));
    VMM_LOG(mask_anonymous, level_trace,"SaveInterruptibilityInformation          %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveInterruptibilityInformation));
    VMM_LOG(mask_anonymous, level_trace,"SaveActivityState                        %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveActivityState              ));
    VMM_LOG(mask_anonymous, level_trace,"SaveWorkingVmcsPointer                   %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveWorkingVmcsPointer         ));
    VMM_LOG(mask_anonymous, level_trace,"Ia32eModeHost                            %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, Ia32eModeHost                  ));
    VMM_LOG(mask_anonymous, level_trace,"LoadCr0AndCr4                            %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, LoadCr0AndCr4                  ));
    VMM_LOG(mask_anonymous, level_trace,"LoadCr3                                  %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, LoadCr3                        ));
    VMM_LOG(mask_anonymous, level_trace,"LoadSegmentRegisters                     %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, LoadSegmentRegisters           ));
    VMM_LOG(mask_anonymous, level_trace,"LoadEspEip                               %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, LoadEspEip                     ));
    VMM_LOG(mask_anonymous, level_trace,"AcknowledgeInterruptOnExit               %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, AcknowledgeInterruptOnExit     ));
    VMM_LOG(mask_anonymous, level_trace,"SaveSysEnterMsrs                         %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveSysEnterMsrs               ));
    VMM_LOG(mask_anonymous, level_trace,"LoadSysEnterMsrs                         %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, LoadSysEnterMsrs               ));
    VMM_LOG(mask_anonymous, level_trace,"SavePat                                  %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SavePat                        ));
    VMM_LOG(mask_anonymous, level_trace,"LoadPat                                  %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, LoadPat                        ));
    VMM_LOG(mask_anonymous, level_trace,"SaveEfer                                 %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveEfer                       ));
    VMM_LOG(mask_anonymous, level_trace,"LoadEfer                                 %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, LoadEfer                       ));
    VMM_LOG(mask_anonymous, level_trace,"SaveVmxTimer                             %c\n",VMCS_FIXED_BIT_2_CHAR( vm_exit_ctrl, SaveVmxTimer                   ));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"VM Entry Controls                      Value\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"LoadCr0AndCr4                            %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadCr0AndCr4                  ));
    VMM_LOG(mask_anonymous, level_trace,"LoadCr3                                  %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadCr3                        ));
    VMM_LOG(mask_anonymous, level_trace,"LoadDebugControls                        %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadDebugControls              ));
    VMM_LOG(mask_anonymous, level_trace,"LoadSegmentRegisters                     %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadSegmentRegisters           ));
    VMM_LOG(mask_anonymous, level_trace,"LoadEspEipEflags                         %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadEspEipEflags               ));
    VMM_LOG(mask_anonymous, level_trace,"LoadPendingDebugExceptions               %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadPendingDebugExceptions     ));
    VMM_LOG(mask_anonymous, level_trace,"LoadInterruptibilityInformation          %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadInterruptibilityInformation));
    VMM_LOG(mask_anonymous, level_trace,"LoadActivityState                        %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadActivityState              ));
    VMM_LOG(mask_anonymous, level_trace,"LoadWorkingVmcsPointer                   %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadWorkingVmcsPointer         ));
    VMM_LOG(mask_anonymous, level_trace,"Ia32eModeGuest                           %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, Ia32eModeGuest                 ));
    VMM_LOG(mask_anonymous, level_trace,"EntryToSmm                               %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, EntryToSmm                     ));
    VMM_LOG(mask_anonymous, level_trace,"TearDownSmmMonitor                       %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, TearDownSmmMonitor             ));
    VMM_LOG(mask_anonymous, level_trace,"LoadSysEnterMsrs                         %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadSysEnterMsrs               ));
    VMM_LOG(mask_anonymous, level_trace,"LoadPat                                  %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadPat                        ));
    VMM_LOG(mask_anonymous, level_trace,"LoadEfer                                 %c\n",VMCS_FIXED_BIT_2_CHAR( vm_entry_ctrl, LoadEfer                       ));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"Cr0 Bits                               Value\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"PE                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, PE ));
    VMM_LOG(mask_anonymous, level_trace,"MP                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, MP ));
    VMM_LOG(mask_anonymous, level_trace,"EM                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, EM ));
    VMM_LOG(mask_anonymous, level_trace,"TS                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, TS ));
    VMM_LOG(mask_anonymous, level_trace,"ET                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, ET ));
    VMM_LOG(mask_anonymous, level_trace,"NE                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, NE ));
    VMM_LOG(mask_anonymous, level_trace,"WP                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, WP ));
    VMM_LOG(mask_anonymous, level_trace,"AM                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, AM ));
    VMM_LOG(mask_anonymous, level_trace,"NW                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, NW ));
    VMM_LOG(mask_anonymous, level_trace,"CD                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, CD ));
    VMM_LOG(mask_anonymous, level_trace,"PG                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr0, PG ));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"Cr4 Bits                               Value\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"VME                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, VME        ));
    VMM_LOG(mask_anonymous, level_trace,"PVI                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, PVI        ));
    VMM_LOG(mask_anonymous, level_trace,"TSD                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, TSD        ));
    VMM_LOG(mask_anonymous, level_trace,"DE                                       %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, DE         ));
    VMM_LOG(mask_anonymous, level_trace,"PSE                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, PSE        ));
    VMM_LOG(mask_anonymous, level_trace,"PAE                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, PAE        ));
    VMM_LOG(mask_anonymous, level_trace,"MCE                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, MCE        ));
    VMM_LOG(mask_anonymous, level_trace,"PGE                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, PGE        ));
    VMM_LOG(mask_anonymous, level_trace,"PCE                                      %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, PCE        ));
    VMM_LOG(mask_anonymous, level_trace,"OSFXSR                                   %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, OSFXSR     ));
    VMM_LOG(mask_anonymous, level_trace,"OSXMMEXCPT                               %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, OSXMMEXCPT ));
    VMM_LOG(mask_anonymous, level_trace,"VMXE                                     %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, VMXE       ));
    VMM_LOG(mask_anonymous, level_trace,"SMXE                                     %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, SMXE       ));
    VMM_LOG(mask_anonymous, level_trace,"OSXSAVE                                  %c\n",VMCS_FIXED_BIT_2_CHAR( cr4, OSXSAVE    ));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"EPT & VPID Capabilities                Value\n");
    VMM_LOG(mask_anonymous, level_trace,"(Valid only if EnableEPT or EnableVPID is not fixed 0)\n");
    VMM_LOG(mask_anonymous, level_trace,"=====================================  =====\n");
    VMM_LOG(mask_anonymous, level_trace,"X_only                                   %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, X_only                  ));
    VMM_LOG(mask_anonymous, level_trace,"W_only                                   %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, W_only                  ));
    VMM_LOG(mask_anonymous, level_trace,"W_and_X_only                             %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, W_and_X_only            ));
    VMM_LOG(mask_anonymous, level_trace,"GAW_21_bit                               %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, GAW_21_bit              ));
    VMM_LOG(mask_anonymous, level_trace,"GAW_30_bit                               %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, GAW_30_bit              ));
    VMM_LOG(mask_anonymous, level_trace,"GAW_39_bit                               %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, GAW_39_bit              ));
    VMM_LOG(mask_anonymous, level_trace,"GAW_48_bit                               %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, GAW_48_bit              ));
    VMM_LOG(mask_anonymous, level_trace,"GAW_57_bit                               %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, GAW_57_bit              ));
    VMM_LOG(mask_anonymous, level_trace,"UC                                       %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, UC                      ));
    VMM_LOG(mask_anonymous, level_trace,"WC                                       %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, WC                      ));
    VMM_LOG(mask_anonymous, level_trace,"WT                                       %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, WT                      ));
    VMM_LOG(mask_anonymous, level_trace,"WP                                       %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, WP                      ));
    VMM_LOG(mask_anonymous, level_trace,"WB                                       %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, WB                      ));
    VMM_LOG(mask_anonymous, level_trace,"SP_21_bit                                %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, SP_21_bit               ));
    VMM_LOG(mask_anonymous, level_trace,"SP_30_bit                                %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, SP_30_bit               ));
    VMM_LOG(mask_anonymous, level_trace,"SP_39_bit                                %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, SP_39_bit               ));
    VMM_LOG(mask_anonymous, level_trace,"SP_48_bit                                %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, SP_48_bit               ));
    VMM_LOG(mask_anonymous, level_trace,"InveptSupported                          %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InveptSupported         ));
    VMM_LOG(mask_anonymous, level_trace,"InveptIndividualAddress                  %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InveptIndividualAddress ));
    VMM_LOG(mask_anonymous, level_trace,"InveptContextWide                        %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InveptContextWide       ));
    VMM_LOG(mask_anonymous, level_trace,"InveptAllContexts                        %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InveptAllContexts       ));
    VMM_LOG(mask_anonymous, level_trace,"InvvpidSupported                         %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InvvpidSupported        ));
    VMM_LOG(mask_anonymous, level_trace,"InvvpidIndividualAddress                 %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InvvpidIndividualAddress));
    VMM_LOG(mask_anonymous, level_trace,"InvvpidContextWide                       %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InvvpidContextWide      ));
    VMM_LOG(mask_anonymous, level_trace,"InvvpidAllContexts                       %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InvvpidAllContexts      ));
    VMM_LOG(mask_anonymous, level_trace,"InvvpidAllContextsPreservingGlobals      %c\n",CAP_BIT_TO_CHAR( EptVpidCapabilities, InvvpidAllContextsPreservingGlobals));

    VMM_LOG(mask_anonymous, level_trace,"\n");
    VMM_LOG(mask_anonymous, level_trace,"---------------- End of Discovered VMX capabilities --------------\n");
    VMM_LOG(mask_anonymous, level_trace,"\n");
}
#endif //DEBUG


//      interface functions

void vmcs_hw_init( void )
{
    if (g_init_done) {
#ifdef JLMDEBUG1
        bprint("vmcs_hw_init returning\n");
#endif
        return;
    }
    vmm_memset(&g_vmx_capabilities, 0, sizeof(g_vmx_capabilities));
    vmm_memset(&g_vmx_constraints, 0, sizeof(g_vmx_constraints));
    vmm_memset(&g_vmx_fixed, 0, sizeof(g_vmx_fixed));
    g_init_done = TRUE;
    fill_vmx_capabilities();
}


// Allocate VMCS region
HVA vmcs_hw_allocate_region(HPA* hpa)
{
    HVA             hva = 0;
    IA32_VMX_VMCS*  vmcs = 0;

#ifdef JLMDEBUG1
    bprint("vmcs_hw_allocate_region\n");
#endif
    VMM_ASSERT( hpa );
    // allocate the VMCS area
    // the area must be 4K page aligned and zeroed
    hva = (HVA)vmm_memory_alloc(VMCS_REGION_SIZE);
    if(hva == 0) {
#ifdef JLMDEBUG
        bprint("vmm_memory_alloc(%llu) failed\n", VMCS_REGION_SIZE);
        UINT64 check= hw_read_msr(IA32_MSR_VMCS_REVISION_IDENTIFIER_INDEX);
        bprint("read MSR_VMCS_REVISION_IDENTIFIER: %llx\n", check);
        LOOP_FOREVER
#endif
    }
    VMM_ASSERT(hva);
    if (!hmm_hva_to_hpa(hva, hpa)) {
        VMM_LOG(mask_anonymous, level_trace,
                "%s:(%d):ASSERT: HVA to HPA conversion failed\n", 
                __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }
#ifdef JLMDEBUG
    bprint("vmcs_hw_allocate_region after hmm_hva_to_hpa %llx\n", hva);
#endif
    // check VMCS memory type
    VMM_ASSERT(hmm_does_memory_range_have_specified_memory_type(
                 *hpa, VMCS_REGION_SIZE, VMCS_MEMORY_TYPE ) == TRUE);
    vmcs = (IA32_VMX_VMCS*)hva;
    vmcs->RevisionIdentifier = VMCS_REVISION;
    // unmap VMCS region from the host memory
#if 0
    if(!hmm_unmap_hpa(*hpa, ALIGN_FORWARD(VMCS_REGION_SIZE, PAGE_4KB_SIZE), FALSE)) {
        VMM_LOG(mask_anonymous, level_trace,"ERROR: failed to unmap VMCS\n");
        VMM_DEADLOOP();
    }
#endif
    return hva;
}


// allocate vmxon regions for all processors at once
// must be called once only on BSP before vmx_on on any APs.
BOOLEAN vmcs_hw_allocate_vmxon_regions(UINT16 max_host_cpus)
{
    HVA     vmxon_region_hva = 0;
    HPA     vmxon_region_hpa = 0;
    UINT16  cpu_idx = 0;

    VMM_ASSERT( max_host_cpus );
    
    for(cpu_idx = 0; cpu_idx < max_host_cpus; cpu_idx ++ ) {
        vmxon_region_hva = vmcs_hw_allocate_region(&vmxon_region_hpa);
        host_cpu_set_vmxon_region(vmxon_region_hva, vmxon_region_hpa, cpu_idx);
    }
    return TRUE;
}


//
// get constraints
//
const VMCS_HW_CONSTRAINTS* vmcs_hw_get_vmx_constraints( void )
{
    if (! g_init_done) {
        vmcs_hw_init();
    }
    return &g_vmx_constraints;
}


// Check that current CPU is VMX-capable
BOOLEAN vmcs_hw_is_cpu_vmx_capable( void )
{
    CPUID_INFO_STRUCT cpuid_info;
    IA32_MSR_OPT_IN   opt_in;
    BOOLEAN           ok = FALSE;
#ifdef JLMDEBUG1
    bprint("vmcs_hw_is_cpu_vmx_capable\n");
#endif

    // 1. CPUID[EAX=1] should have VMX feature == 1
    // 2. OPT_IN (FEATURE_CONTROL) MSR should have
    //     either EnableVmxonOutsideSmx == 1 or
    //     Lock == 0
    cpuid( &cpuid_info, 1 );
    if ((CPUID_VALUE_ECX( cpuid_info ) & IA32_CPUID_ECX_VMX) == 0) {
        VMM_LOG(mask_anonymous, level_trace,"ASSERT: CPUID[EAX=1] indicates that Host CPU #%d does not support VMX!\n",
                 hw_cpu_id());
        return FALSE;
    }
    opt_in.Uint64 = hw_read_msr( IA32_MSR_OPT_IN_INDEX );
    ok = ((opt_in.Bits.EnableVmxonOutsideSmx == 1) || (opt_in.Bits.Lock == 0));
    VMM_DEBUG_CODE({
        if (!ok) {
            VMM_LOG(mask_anonymous, level_trace,"ASSERT: OPT_IN (FEATURE_CONTROL) MSR indicates that somebody locked-out VMX on Host CPU #%d\n",
                     hw_cpu_id());
        }
    })
    return ok;
}


// Enable VT on the current CPU
void vmcs_hw_vmx_on( void )
{
    IA32_MSR_OPT_IN   opt_in;
    EM64T_CR4         cr4;
    HVA               vmxon_region_hva = 0;
    HPA               vmxon_region_hpa = 0;
    int               vmx_ret= 0;

#ifdef JLMDEBUG
   bprint("vmcs_hw_vmx_on\n");
#endif

    // Enable VMX in CR4
    cr4.Uint64 = hw_read_cr4();
    cr4.Bits.VMXE = 1;
    hw_write_cr4(cr4.Uint64);
    // Enable VMX outside SMM in OPT_IN (FEATURE_CONTROL) MSR and lock it
    opt_in.Uint64 = hw_read_msr(IA32_MSR_OPT_IN_INDEX);
    VMM_ASSERT( (opt_in.Bits.Lock == 0) || (opt_in.Bits.EnableVmxonOutsideSmx == 1) );
    if (opt_in.Bits.Lock == 0) {
        opt_in.Bits.EnableVmxonOutsideSmx = 1;
        opt_in.Bits.Lock = 1;
        hw_write_msr(IA32_MSR_OPT_IN_INDEX, opt_in.Uint64);
    }
    vmxon_region_hva = host_cpu_get_vmxon_region(&vmxon_region_hpa);
#ifdef JLMDEBUG
    bprint("vmxon_hpa: %llx, vmxon_region_hva: %llx\n",
            vmxon_region_hpa,  vmxon_region_hva);
    // not that the region with address vmxon_region_hva
    // has been unmapped, so we cant print it.
#endif
    if(!vmxon_region_hva || !vmxon_region_hpa) {
        VMM_LOG(mask_anonymous, level_trace,
                "ASSERT: VMXON failed with getting vmxon_region address\n");
        VMM_DEADLOOP();
    }
    vmx_ret = vmx_on(&vmxon_region_hpa);
#ifdef JLMDEBUG
    if(vmx_ret==0) {
        bprint("vmxon succeeded\n");
    }
    else {
        bprint("vmxon failed %d\n", vmx_ret);
        LOOP_FOREVER
    }
#endif
    switch(vmx_ret) {
        case HW_VMX_SUCCESS:
            host_cpu_set_vmx_state( TRUE );
            break;
        case HW_VMX_FAILED_WITH_STATUS:
            VMM_LOG(mask_anonymous, level_trace,
                "ASSERT: VMXON failed with HW_VMX_FAILED_WITH_STATUS error\n");
            VMM_DEADLOOP();
            VMM_BREAKPOINT();
        case HW_VMX_FAILED:
        default:
            VMM_LOG(mask_anonymous, level_trace,"ASSERT: VMXON failed with HW_VMX_FAILED error\n");
            VMM_DEADLOOP();
            VMM_BREAKPOINT();
    }
}


// Disable VT on the current CPU
void vmcs_hw_vmx_off( void )
{
    if (host_cpu_get_vmx_state() == FALSE) {
        return;
    }
    vmx_off();
    host_cpu_set_vmx_state( FALSE );
}

