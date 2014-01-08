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

/*
  IA32 VMX Read Only MSR Definitions
*/

#ifndef _VMX_CTRL_MSRS_H_
#define _VMX_CTRL_MSRS_H_

#include "vmm_defs.h"
#include "em64t_defs.h"

//
// VMX Capabilities are declared in bit 5 of ECX retured from CPUID
//
#define IA32_CPUID_ECX_VMX                                    0x20

//
// VMX MSR Indexes
//
#define IA32_MSR_OPT_IN_INDEX                                 0x3A
#define IA32_MSR_MSEG_INDEX                                   0x9B
#define IA32_MSR_VMX_BASIC_INDEX                              0x480
#define IA32_MSR_PIN_BASED_VM_EXECUTION_CONTROLS_INDEX        0x481
#define IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS_INDEX  0x482
#define IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS2_INDEX 0x48B
#define IA32_MSR_VM_EXIT_CONTROLS_INDEX                       0x483
#define IA32_MSR_VM_ENTRY_CONTROLS_INDEX                      0x484
#define IA32_MSR_MISCELLANEOUS_DATA_INDEX                     0x485
#define IA32_MSR_CR0_ALLOWED_ZERO_INDEX                       0x486
#define IA32_MSR_CR0_ALLOWED_ONE_INDEX                        0x487
#define IA32_MSR_CR4_ALLOWED_ZERO_INDEX                       0x488
#define IA32_MSR_CR4_ALLOWED_ONE_INDEX                        0x489
#define IA32_MSR_VMX_VMCS_ENUM                                0x48A
#define IA32_MSR_EPT_VPID_CAP_INDEX                           0x48C
#define IA32_MSR_TRUE_PINBASED_CTLS_INDEX                     0x48D
#define IA32_MSR_TRUE_PROCBASED_CTLS_INDEX                    0x48E
#define IA32_MSR_TRUE_EXIT_CTLS_INDEX                         0x48F
#define IA32_MSR_TRUE_ENTRY_CTLS_INDEX                        0x490
#ifdef FAST_VIEW_SWITCH
#define IA32_MSR_VMX_VMFUNC_CTRL                              0x491
#endif

#define IA32_MSR_VMX_FIRST                              0x480
#ifdef FAST_VIEW_SWITCH
#define IA32_MSR_VMX_LAST                               0x491
#else
#define IA32_MSR_VMX_LAST                               0x490
#endif


// synonyms
#define IA32_MSR_VMCS_REVISION_IDENTIFIER_INDEX IA32_MSR_VMX_BASIC_INDEX

#pragma PACK_ON

//
// VMX MSR Structure - IA32_MSR_OPT_IN_INDEX - Index 0x3A
//
typedef union {
  struct {
    UINT32  Lock:1;                    // 0=Unlocked, 1=Locked
    UINT32  EnableVmxonInSmx:1;        // 0=Disabled, 1=Enabled
    UINT32  EnableVmxonOutsideSmx:1;   // 0=Disabled, 1=Enabled
    UINT32  Reserved_0:5;
    UINT32  SenterEnables:8;
    UINT32  Reserved_1:16;
    UINT32  Reserved_2:32;
  } Bits;
  struct {
    UINT32  Lower;
    UINT32  Upper;
  } Uint32;
  UINT64  Uint64;
} IA32_MSR_OPT_IN;

//
// VMX MSR Structure - IA32_MSR_MSEG_INDEX - Index 0x9B
//
typedef union {
  struct {
    UINT32  Valid:1;                   // 0=Invalid, 1=Valid
    UINT32  Reserved_0:11;
    UINT32  MsegBaseAddress:20;
    UINT32  Reserved_1:32;
  } Bits;
  UINT64  Uint64;
} IA32_MSR_MSEG;

//
// VMX MSR Structure - IA32_MSR_VMCS_REVISION_IDENTIFIER_INDEX - Index 0x480
//
typedef union {
  struct {
    UINT32  RevisionIdentifier:32;                      // bits 0-31
    UINT32  VmcsRegionSize:13;                          // bits 32-44
    UINT32  Reserved1_0:3;                              // bits 45-47
    UINT32  PhysicalAddressWidth:1;                     // bit  48
    UINT32  DualMonitorSystemManagementInterrupts:1;    // bit  49
    UINT32  VmcsMemoryType:4;                           // bits 50:53
    UINT32  VmcsInstructionInfoFieldOnIOisValid:1;      // bit  54
    UINT32  Reserved2_0:9;                              // bits 55-63
  } Bits;
  UINT64  Uint64;
} IA32_MSR_VMCS_REVISION_IDENTIFIER;

//
// VMX MSR Structure - IA32_MSR_PIN_BASED_VM_EXECUTION_CONTROLS_INDEX - Index 0x481
//
typedef union {
  struct {
    UINT32  ExternalInterrupt:1;  // 0=No VmExit from ext int
    UINT32  HostInterrupt:1;
    UINT32  Init:1;
    UINT32  Nmi:1;
    UINT32  Sipi:1;
    UINT32  VirtualNmi:1;
    UINT32  VmxTimer:1;
    UINT32  Reserved_1:25;
  } Bits;
  UINT32  Uint32;
} PIN_BASED_VM_EXECUTION_CONTROLS;

typedef union {
  struct {
    PIN_BASED_VM_EXECUTION_CONTROLS  MayBeSetToZero; // Bits, that have 0 values may be set to 0 in VMCS
    PIN_BASED_VM_EXECUTION_CONTROLS  MayBeSetToOne;  // Bits, that have 1 values may be set to 1 in VMCS
  } Bits;
  UINT64  Uint64;
} IA32_MSR_PIN_BASED_VM_EXECUTION_CONTROLS;

//
// VMX MSR Structure - IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS_INDEX - Index 0x482
//
typedef union {
  struct {
    UINT32  SoftwareInterrupt:1;
    UINT32  TripleFault:1;
    UINT32  VirtualInterrupt:1; // InterruptWindow
    UINT32  UseTscOffsetting:1;
    UINT32  TaskSwitch:1;
    UINT32  Cpuid:1;
    UINT32  GetSec:1;
    UINT32  Hlt:1;
    UINT32  Invd:1;
    UINT32  Invlpg:1;
    UINT32  Mwait:1;
    UINT32  Rdpmc:1;
    UINT32  Rdtsc:1;
    UINT32  Rsm:1;
    UINT32  VmInstruction:1;
    UINT32  Cr3Load:1;
    UINT32  Cr3Store:1;
    UINT32  UseCr3Mask:1;
    UINT32  UseCr3ReadShadow:1;
    UINT32  Cr8Load:1;
    UINT32  Cr8Store:1;
    UINT32  TprShadow:1;
    UINT32  NmiWindow:1;
    UINT32  MovDr:1;
    UINT32  UnconditionalIo:1;
    UINT32  ActivateIoBitmaps:1;
    UINT32  MsrProtection:1;
    UINT32  MonitorTrapFlag:1;
    UINT32  UseMsrBitmaps:1;
    UINT32  Monitor:1;
    UINT32  Pause:1;
    UINT32  SecondaryControls:1;
  } Bits;
  UINT32  Uint32;
} PROCESSOR_BASED_VM_EXECUTION_CONTROLS;

typedef union {
  struct {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS  MayBeSetToZero; // Bits, that have 0 values may be set to 0 in VMCS
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS  MayBeSetToOne;  // Bits, that have 1 values may be set to 1 in VMCS
  } Bits;
  UINT64  Uint64;
} IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS;

//
// VMX MSR Structure - IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS2_INDEX - Index 0x48B
//
typedef union {
  struct {
    UINT32  VirtualizeAPIC:1;
    UINT32  EnableEPT:1;
    UINT32  DescriptorTableExiting:1;
    UINT32  EnableRDTSCP:1;
    UINT32  ShadowApicMsrs:1;
    UINT32  EnableVPID:1;
    UINT32  WBINVD:1;
    UINT32  UnrestrictedGuest:1;
    UINT32  Reserved_0:4;
    UINT32  EnableINVPCID:1;
    UINT32  Vmfunc:1;	// bit 13
    UINT32  Reserved_1:4;
    UINT32  VE:1;		// bit 18
    UINT32  Reserved_2:13;
  } Bits;
  UINT32  Uint32;
} PROCESSOR_BASED_VM_EXECUTION_CONTROLS2;

typedef union {
  struct {
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2  MayBeSetToZero; // Bits, that have 0 values may be set to 0 in VMCS
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS2  MayBeSetToOne;  // Bits, that have 1 values may be set to 1 in VMCS
  } Bits;
  UINT64  Uint64;
} IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS2;

//
// VMX MSR Structure - IA32_MSR_VM_EXIT_CONTROLS_INDEX - Index 0x483
//
typedef union {
  struct {
    UINT32  SaveCr0AndCr4:1;
    UINT32  SaveCr3:1;
    UINT32  SaveDebugControls:1;
    UINT32  SaveSegmentRegisters:1;
    UINT32  SaveEspEipEflags:1;
    UINT32  SavePendingDebugExceptions:1;
    UINT32  SaveInterruptibilityInformation:1;
    UINT32  SaveActivityState:1;
    UINT32  SaveWorkingVmcsPointer:1;
    UINT32  Ia32eModeHost:1;
    UINT32  LoadCr0AndCr4:1;
    UINT32  LoadCr3:1;
    UINT32  Load_IA32_PERF_GLOBAL_CTRL:1;
    UINT32  LoadSegmentRegisters:1;
    UINT32  LoadEspEip:1;
    UINT32  AcknowledgeInterruptOnExit:1;
    UINT32  SaveSysEnterMsrs:1;
    UINT32  LoadSysEnterMsrs:1;
    UINT32  SavePat:1;
    UINT32  LoadPat:1;
    UINT32  SaveEfer:1;
    UINT32  LoadEfer:1;
    UINT32  SaveVmxTimer:1;
    UINT32  Reserved_2:9;
  } Bits;
  UINT32  Uint32;
} VM_EXIT_CONTROLS;

typedef union {
  struct {
    VM_EXIT_CONTROLS  MayBeSetToZero; // Bits, that have 0 values may be set to 0 in VMCS
    VM_EXIT_CONTROLS  MayBeSetToOne;  // Bits, that have 1 values may be set to 1 in VMCS
  } Bits;
  UINT64  Uint64;
} IA32_MSR_VM_EXIT_CONTROLS;

//
// VMX MSR Structure - IA32_MSR_VM_ENTRY_CONTROLS_INDEX - Index 0x484
//
typedef union {
  struct {
    UINT32  LoadCr0AndCr4:1;
    UINT32  LoadCr3:1;
    UINT32  LoadDebugControls:1;
    UINT32  LoadSegmentRegisters:1;
    UINT32  LoadEspEipEflags:1;
    UINT32  LoadPendingDebugExceptions:1;
    UINT32  LoadInterruptibilityInformation:1;
    UINT32  LoadActivityState:1;
    UINT32  LoadWorkingVmcsPointer:1;
    UINT32  Ia32eModeGuest:1;
    UINT32  EntryToSmm:1;
    UINT32  TearDownSmmMonitor:1;
    UINT32  LoadSysEnterMsrs:1;
    UINT32  Load_IA32_PERF_GLOBAL_CTRL:1;
    UINT32  LoadPat:1;
    UINT32  LoadEfer:1;
    UINT32  Reserved_1:16;
  } Bits;
  UINT32  Uint32;
} VM_ENTRY_CONTROLS;

typedef union {
  struct {
    VM_ENTRY_CONTROLS  MayBeSetToZero; // Bits, that have 0 values may be set to 0 in VMCS
    VM_ENTRY_CONTROLS  MayBeSetToOne;  // Bits, that have 1 values may be set to 1 in VMCS
  } Bits;
  UINT64  Uint64;
} IA32_MSR_VM_ENTRY_CONTROLS;

//
// VMX MSR Structure - IA32_MSR_MISCELLANEOUS_DATA_INDEX - Index 0x485
//
typedef union {
  struct {
    UINT32  PreemptionTimerLength:5; // in TSC ticks
    UINT32  Reserved_0:1;
    UINT32  EntryInHaltStateSupported:1;
    UINT32  EntryInShutdownStateSupported:1;
    UINT32  EntryInWaitForSipiStateSupported:1;
    UINT32  Reserved_1:7;
    UINT32  NumberOfCr3TargetValues:9;
    UINT32  MsrListsMaxSize:3; // If this value is N, the max supported msr list is 512*(N+1)
    UINT32  Reserved_2:4;
    UINT32  MsegRevisionIdentifier:32;
  } Bits;
  UINT64  Uint64;
} IA32_MSR_MISCELLANEOUS_DATA;

typedef union {
    struct {
        // RWX support
        UINT32 X_only:1;
        UINT32 W_only:1;
        UINT32 W_and_X_only:1;
        // GAW support
        UINT32 GAW_21_bit:1;
        UINT32 GAW_30_bit:1;
        UINT32 GAW_39_bit:1;
        UINT32 GAW_48_bit:1;
        UINT32 GAW_57_bit:1;
        // EMT support
        UINT32 UC:1;
        UINT32 WC:1;
        UINT32 Reserved0:2;
        UINT32 WT:1;
        UINT32 WP:1;
        UINT32 WB:1;
        UINT32 Reserved1:1;
        // SP support
        UINT32 SP_21_bit:1;
        UINT32 SP_30_bit:1;
        UINT32 SP_39_bit:1;
        UINT32 SP_48_bit:1;

        UINT32 InveptSupported:1;
        UINT32 Reserved2:3;
        // INVEPT Support
        UINT32 InveptIndividualAddress:1;
        UINT32 InveptContextWide:1;
        UINT32 InveptAllContexts:1;
        UINT32 Reserved3:5;

        UINT32 InvvpidSupported:1;
        UINT32 Reserved4:7;
        // INVVPID Support
        UINT32 InvvpidIndividualAddress:1;
        UINT32 InvvpidContextWide:1;
        UINT32 InvvpidAllContexts:1;
        UINT32 InvvpidAllContextsPreservingGlobals:1;
        UINT32 Reserved5:4;

        UINT32 Reserved6:16;
    } Bits;
    UINT64 Uint64;
} IA32_VMX_EPT_VPID_CAP;

//
// VMX MSR Structure - IA32_MSR_CR0_ALLOWED_ZERO_INDEX, IA32_MSR_CR0_ALLOWED_ONE_INDEX - Index 0x486, 0x487
//
typedef EM64T_CR0 IA32_MSR_CR0;

//
// VMX MSR Structure - IA32_MSR_CR4_ALLOWED_ZERO_INDEX, IA32_MSR_CR4_ALLOWED_ONE_INDEX - Index 0x488, 0x489
//
typedef EM64T_CR4 IA32_MSR_CR4;

#ifdef FAST_VIEW_SWITCH
//
// VMX MSR Structure - IA32_MSR_VMFUNC_CTRL - Index 0x491
//
typedef union {
  struct {
    UINT32  EptpSwitching:1;
    UINT32  Reserved_0:31;
    UINT32  Reserved_1:32;
  } Bits;
  UINT64  Uint64;
} IA32_MSR_VMFUNC_CTRL;

typedef enum _VMFUNC_BITS {
  EPTP_SWITCHING_BIT = 0,
} VMFUNC_BITS;
#endif
#pragma PACK_OFF

//
// Structure containing the complete set of VMX MSR Values
//
typedef struct {
  IA32_MSR_VMCS_REVISION_IDENTIFIER               VmcsRevisionIdentifier;
  IA32_MSR_PIN_BASED_VM_EXECUTION_CONTROLS        PinBasedVmExecutionControls;
  IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS  ProcessorBasedVmExecutionControls;
  IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS2 ProcessorBasedVmExecutionControls2;
  IA32_MSR_VM_EXIT_CONTROLS                       VmExitControls;
  IA32_MSR_VM_ENTRY_CONTROLS                      VmEntryControls;
  IA32_MSR_MISCELLANEOUS_DATA                     MiscellaneousData;
  IA32_MSR_CR0                                    Cr0MayBeSetToZero;
  IA32_MSR_CR0                                    Cr0MayBeSetToOne;
  IA32_MSR_CR4                                    Cr4MayBeSetToZero;
  IA32_MSR_CR4                                    Cr4MayBeSetToOne;
  IA32_VMX_EPT_VPID_CAP                           EptVpidCapabilities;
#ifdef FAST_VIEW_SWITCH
  IA32_MSR_VMFUNC_CTRL                            VmFuncControls;
#endif
} IA32_VMX_CAPABILITIES;

#endif  // _VMX_CTRL_MSRS_H_
