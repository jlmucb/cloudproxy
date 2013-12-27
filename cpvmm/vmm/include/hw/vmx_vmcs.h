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

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

/*
  IA32 VMX Virtual Machine Control Structure Definitions
*/
#ifndef _VMX_VMCS_H_
#define _VMX_VMCS_H_

#include "vmm_defs.h"

#pragma PACK_ON

//
// VMCS bit positions for
// Primary Processor-Based VM-Execution Controls
// 
#define PPBVMX_CTL_UNCONDITION_IO_EXIT    24
#define PPBVMX_CTL_USE_IO_BITMAPS         25

//
// VMCS Register Indexes
//
#define VM_X_VPID                               0x00000000
#define VM_X_EPTP_INDEX                         0x00000004
#define VM_X_CONTROL_VECTOR_PIN_EVENTS          0x00004000
#define VM_X_CONTROL_VECTOR_PROCESSOR_EVENTS    0x00004002
#define VM_X_CONTROL2_VECTOR_PROCESSOR_EVENTS   0x0000401E
#define VM_X_EXCEPTION_BITMAP                   0x00004004
#define VM_X_CR3_TARGET_COUNT                   0x0000400A
#define VM_X_CR0_MASK                           0x00006000
#define VM_X_CR3_MASK                           0x00006208
#define VM_X_CR4_MASK                           0x00006002
#define VM_X_CR0_READ_SHADOW                    0x00006004
#define VM_X_CR3_READ_SHADOW                    0x0000620C
#define VM_X_CR4_READ_SHADOW                    0x00006006
#define VM_X_CR3_TARGET_VAL_BASE                0x00006008  // 6008-6206
#define VM_X_CR3_TARGET_VALUE(_x)               (VM_X_CR3_TARGET_VAL_BASE + (_x) * 2)
#define VM_X_PAGE_FAULT_ERROR_CODE_MASK         0x00004006
#define VM_X_PAGE_FAULT_ERROR_CODE_MATCH        0x00004008
#define VM_EXIT_CONTROL_VECTOR                  0x0000400C
#define VM_EXIT_TPR_THRESHOLD                   0x0000401C
#define VM_EXIT_MSR_STORE_COUNT                 0x0000400E
#define VM_EXIT_MSR_LOAD_COUNT                  0x00004010
#define VM_ENTER_CONTROL_VECTOR                 0x00004012
#define VM_ENTER_MSR_LOAD_COUNT                 0x00004014
#define VM_ENTER_INTERRUPT_INFO                 0x00004016
#define VM_ENTER_EXCEPTION_ERROR_CODE           0x00004018
#define VM_ENTER_INSTRUCTION_LENGTH             0x0000401A
#define VM_X_IO_BITMAP_ADDRESS_A                0x00002000
#define VM_X_IO_BITMAP_ADDRESS_A_HIGH           0x00002001
#define VM_X_IO_BITMAP_ADDRESS_B                0x00002002
#define VM_X_IO_BITMAP_ADDRESS_B_HIGH           0x00002003
#define VM_X_MSR_BITMAP_ADDRESS                 0x00002004
#define VM_X_MSR_BITMAP_ADDRESS_HIGH            0x00002005
#define VM_EXIT_MSR_STORE_ADDRESS               0x00002006
#define VM_EXIT_MSR_STORE_ADDRESS_HIGH          0x00002007
#define VM_EXIT_MSR_LOAD_ADDRESS                0x00002008
#define VM_EXIT_MSR_LOAD_ADDRESS_HIGH           0x00002009
#define VM_ENTER_MSR_LOAD_ADDRESS               0x0000200A
#define VM_ENTER_MSR_LOAD_ADDRESS_HIGH          0x0000200B
#define VM_X_OSV_CONTROLLING_VMCS_ADDRESS       0x0000200C
#define VM_X_OSV_CONTROLLING_VMCS_ADDRESS_HIGH  0x0000200D
#define VM_X_TSC_OFFSET                         0x00002010
#define VM_X_TSC_OFFSET_HIGH                    0x00002011
#define VM_X_VIRTUAL_APIC_ADDRESS               0x00002012
#define VM_X_VIRTUAL_APIC_ADDRESS_HIGH          0x00002013
#define VM_X_APIC_ACCESS_ADDRESS                0x00002014
#define VM_X_APIC_ACCESS_ADDRESS_HIGH           0x00002015
#ifdef FAST_VIEW_SWITCH
#define VM_X_VMFUNC_CONTROL                     0x00002018
#define VM_X_VMFUNC_CONTROL_HIGH                0x00002019
#define VM_X_VMFUNC_EPTP_LIST_ADDRESS           0x00002024
#define VM_X_VMFUNC_EPTP_LIST_ADDRESS_HIGH      0x00002025
#endif
#define VM_X_VE_INFO_ADDRESS                    0x0000202A
#define VM_X_VE_INFO_ADDRESS_HIGH               0x0000202B
#define VM_X_EPTP_ADDRESS                       0x0000201A
#define VM_X_EPTP_ADDRESS_HIGH                  0x0000201B
#define VM_X_PREEMTION_TIMER                    0x0000482E
#define VM_EXIT_PHYSICAL_ADDRESS                0x00002400
#define VM_EXIT_PHYSICAL_ADDRESS_HIGH           0x00002401
#define VM_EXIT_INFO_INSTRUCTION_ERROR_CODE     0x00004400
#define VM_EXIT_INFO_REASON                     0x00004402
#define VM_EXIT_INFO_EXCEPTION_INFO             0x00004404
#define VM_EXIT_INFO_EXCEPTION_ERROR_CODE       0x00004406
#define VM_EXIT_INFO_IDT_VECTORING              0x00004408
#define VM_EXIT_INFO_IDT_VECTORING_ERROR_CODE   0x0000440A
#define VM_EXIT_INFO_INSTRUCTION_LENGTH         0x0000440C
#define VM_EXIT_INFO_INSTRUCTION_INFO           0x0000440E
#define VM_EXIT_INFO_QUALIFICATION              0x00006400
#define VM_EXIT_INFO_IO_RCX                     0x00006402
#define VM_EXIT_INFO_IO_RSI                     0x00006404
#define VM_EXIT_INFO_IO_RDI                     0x00006406
#define VM_EXIT_INFO_IO_RIP                     0x00006408
#define VM_EXIT_INFO_GUEST_LINEAR_ADDRESS       0x0000640A
#define GUEST_CR0                               0x00006800
#define GUEST_CR3                               0x00006802
#define GUEST_CR4                               0x00006804
#define GUEST_DR7                               0x0000681A
#define GUEST_ES_SELECTOR                       0x00000800
#define GUEST_ES_BASE                           0x00006806
#define GUEST_ES_LIMIT                          0x00004800
#define GUEST_ES_AR                             0x00004814
#define GUEST_CS_SELECTOR                       0x00000802
#define GUEST_CS_BASE                           0x00006808
#define GUEST_CS_LIMIT                          0x00004802
#define GUEST_CS_AR                             0x00004816
#define GUEST_SS_SELECTOR                       0x00000804
#define GUEST_SS_BASE                           0x0000680A
#define GUEST_SS_LIMIT                          0x00004804
#define GUEST_SS_AR                             0x00004818
#define GUEST_DS_SELECTOR                       0x00000806
#define GUEST_DS_BASE                           0x0000680C
#define GUEST_DS_LIMIT                          0x00004806
#define GUEST_DS_AR                             0x0000481A
#define GUEST_FS_SELECTOR                       0x00000808
#define GUEST_FS_BASE                           0x0000680E
#define GUEST_FS_LIMIT                          0x00004808
#define GUEST_FS_AR                             0x0000481C
#define GUEST_GS_SELECTOR                       0x0000080A
#define GUEST_GS_BASE                           0x00006810
#define GUEST_GS_LIMIT                          0x0000480A
#define GUEST_GS_AR                             0x0000481E
#define GUEST_LDTR_SELECTOR                     0x0000080C
#define GUEST_LDTR_BASE                         0x00006812
#define GUEST_LDTR_LIMIT                        0x0000480C
#define GUEST_LDTR_AR                           0x00004820
#define GUEST_TR_SELECTOR                       0x0000080E
#define GUEST_TR_BASE                           0x00006814
#define GUEST_TR_LIMIT                          0x0000480E
#define GUEST_TR_AR                             0x00004822
#define GUEST_GDTR_BASE                         0x00006816
#define GUEST_GDTR_LIMIT                        0x00004810
#define GUEST_IDTR_BASE                         0x00006818
#define GUEST_IDTR_LIMIT                        0x00004812
#define GUEST_ESP                               0x0000681C
#define GUEST_EIP                               0x0000681E
#define GUEST_EFLAGS                            0x00006820
#define GUEST_PEND_DBE                          0x00006822
#define GUEST_WORKING_VMCS_PTR                  0x00002800
#define GUEST_WORKING_VMCS_PTR_HIGH             0x00002801
#define GUEST_DEBUG_CONTROL                     0x00002802
#define GUEST_DEBUG_CONTROL_HIGH                0x00002803
#define GUEST_INTERRUPTIBILITY                  0x00004824
#define GUEST_SLEEP_STATE                       0x00004826
#define GUEST_SMBASE                            0x00004828
#define GUEST_SYSENTER_CS                       0x0000482A
#define GUEST_SYSENTER_ESP                      0x00006824
#define GUEST_SYSENTER_EIP                      0x00006826
#define GUEST_PAT                               0x00002804
#define GUEST_PAT_HIGH                          0x00002805
#define GUEST_EFER                              0x00002806
#define GUEST_EFER_HIGH                         0x00002807
#define GUEST_IA32_PERF_GLOBAL_CTRL             0x00002808
#define GUEST_IA32_PERF_GLOBAL_CTRL_HIGH        0x00002809
#define GUEST_PDPTR0                            0x0000280A
#define GUEST_PDPTR0_HIGH                       0x0000280B
#define GUEST_PDPTR1                            0x0000280C
#define GUEST_PDPTR1_HIGH                       0x0000280D
#define GUEST_PDPTR2                            0x0000280E
#define GUEST_PDPTR2_HIGH                       0x0000280F
#define GUEST_PDPTR3                            0x00002810
#define GUEST_PDPTR3_HIGH                       0x00002811
#define HOST_CR0                                0x00006C00
#define HOST_CR3                                0x00006C02
#define HOST_CR4                                0x00006C04
#define HOST_ES_SELECTOR                        0x00000C00
#define HOST_CS_SELECTOR                        0x00000C02
#define HOST_SS_SELECTOR                        0x00000C04
#define HOST_DS_SELECTOR                        0x00000C06
#define HOST_FS_SELECTOR                        0x00000C08
#define HOST_FS_BASE                            0x00006C06
#define HOST_GS_SELECTOR                        0x00000C0A
#define HOST_GS_BASE                            0x00006C08
#define HOST_TR_SELECTOR                        0x00000C0C
#define HOST_TR_BASE                            0x00006C0A
#define HOST_GDTR_BASE                          0x00006C0C
#define HOST_IDTR_BASE                          0x00006C0E
#define HOST_ESP                                0x00006C14
#define HOST_EIP                                0x00006C16
#define HOST_SYSENTER_CS                        0x00004C00
#define HOST_SYSENTER_ESP                       0x00006C10
#define HOST_SYSENTER_EIP                       0x00006C12
#define HOST_PAT                                0x00002C00
#define HOST_PAT_HIGH                           0x00002C01
#define HOST_EFER                               0x00002C02
#define HOST_EFER_HIGH                          0x00002C03
#define HOST_IA32_PERF_GLOBAL_CTRL              0x00002C04
#define HOST_IA32_PERF_GLOBAL_CTRL_HIGH         0x00002C05
#define VMCS_NO_COMPONENT                       0x0000FFFF

//
// VMX Error Codes
//
#define VMX_ARCH_NO_INSTRUCTION_ERROR                                  0   // VMxxxxx
#define VMX_ARCH_VMCALL_IN_ROOT_ERROR                                  1   // VMCALL
#define VMX_ARCH_VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR                2   // VMCLEAR
#define VMX_ARCH_VMCLEAR_WITH_CURRENT_CONTROLLING_PTR_ERROR            3   // VMCLEAR
#define VMX_ARCH_VMLAUNCH_WITH_NON_CLEAR_VMCS_ERROR                    4   // VMLAUNCH
#define VMX_ARCH_VMRESUME_WITH_NON_LAUNCHED_VMCS_ERROR                 5   // VMRESUME
#define VMX_ARCH_VMRESUME_WITH_NON_CHILD_VMCS_ERROR                    6   // VMRESUME
#define VMX_ARCH_VMENTER_BAD_CONTROL_FIELD_ERROR                       7   // VMENTER
#define VMX_ARCH_VMENTER_BAD_MONITOR_STATE_ERROR                       8   // VMENTER
#define VMX_ARCH_VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR                9   // VMPTRLD
#define VMX_ARCH_VMPTRLD_WITH_CURRENT_CONTROLLING_PTR_ERROR            10  // VMPTRLD
#define VMX_ARCH_VMPTRLD_WITH_BAD_REVISION_ID_ERROR                    11  // VMPTRLD
#define VMX_ARCH_VMREAD_OR_VMWRITE_OF_UNSUPPORTED_COMPONENT_ERROR      12  // VMREAD
#define VMX_ARCH_VMWRITE_OF_READ_ONLY_COMPONENT_ERROR                  13  // VMWRITE
#define VMX_ARCH_VMWRITE_INVALID_FIELD_VALUE_ERROR                     14  // VMWRITE
#define VMX_ARCH_VMXON_IN_VMX_ROOT_OPERATION_ERROR                     15  // VMXON
#define VMX_ARCH_VMENTRY_WITH_BAD_OSV_CONTROLLING_VMCS_ERROR           16  // VMENTER
#define VMX_ARCH_VMENTRY_WITH_NON_LAUNCHED_OSV_CONTROLLING_VMCS_ERROR  17  // VMENTER
#define VMX_ARCH_VMENTRY_WITH_NON_ROOT_OSV_CONTROLLING_VMCS_ERROR      18  // VMENTER
#define VMX_ARCH_VMCALL_WITH_NON_CLEAR_VMCS_ERROR                      19  // VMCALL
#define VMX_ARCH_VMCALL_WITH_BAD_VMEXIT_FIELDS_ERROR                   20  // VMCALL
#define VMX_ARCH_VMCALL_WITH_INVALID_MSEG_MSR_ERROR                    21  // VMCALL
#define VMX_ARCH_VMCALL_WITH_INVALID_MSEG_REVISION_ERROR               22  // VMCALL
#define VMX_ARCH_VMXOFF_WITH_CONFIGURED_SMM_MONITOR_ERROR              23  // VMXOFF
#define VMX_ARCH_VMCALL_WITH_BAD_SMM_MONITOR_FEATURES_ERROR            24  // VMCALL
#define VMX_ARCH_RETURN_FROM_SMM_WITH_BAD_VM_EXECUTION_CONTROLS_ERROR  25  // Return from SMM
#define VMX_ARCH_VMENTRY_WITH_EVENTS_BLOCKED_BY_MOV_SS_ERROR           26  // VMENTER
#define VMX_ARCH_BAD_ERROR_CODE                                        27  // Bad error code
#define VMX_ARCH_INVALIDATION_WITH_INVALID_OPERAND                     28  // INVEPT, INVVPID

//
// Exception bitmap
//
typedef union _IA32_VMCS_EXCEPTION_BITMAP {
  struct {
    UINT32  DE:1;           // Divide Error
    UINT32  DB:1;           // Debug
    UINT32  NMI:1;          // Non-Maskable Interrupt
    UINT32  BP:1;           // Breakpoint
    UINT32  OF:1;           // Overflow
    UINT32  BR:1;           // BOUND Range Exceeded
    UINT32  UD:1;           // Undefined Opcode
    UINT32  NM:1;           // No Math Coprocessor
    UINT32  DF:1;           // Double Fault
    UINT32  Reserved_0:1;   // Reserved
    UINT32  TS:1;           // Invalid TSS (Task Segment Selector)
    UINT32  NP:1;           // Segment Not Present
    UINT32  SS:1;           // Stack Segment Fault
    UINT32  GP:1;           // General Protection Fault
    UINT32  PF:1;           // Page Fault
    UINT32  Reserved_1:1;   // Reserved
    UINT32  MF:1;           // Math Fault
    UINT32  AC:1;           // Alignment Check
    UINT32  MC:1;           // Machine Check
    UINT32  XF:1;           // SIMD Floating Point Numeric Error
    UINT32  VE:1;           // Virtualization Exception
    UINT32  Reserved_2:11;  // Reserved
  } Bits;
  UINT32  Uint32;
} IA32_VMCS_EXCEPTION_BITMAP;


//
// MSR bitmap offsets
//

// one bit per MSRs 0x00000000 - 0x00001FFF
// bit == 1 - VmExit
#define IA32_VMCS_MSR_BITMAP_READ_LOW_MSRS_OFFSET         0
#define IA32_VMCS_MSR_BITMAP_WRITE_LOW_MSRS_OFFSET        1024

// one bit per MSRs 0xC0000000 - 0xC0001FFF
// bit == 1 - VmExit
#define IA32_VMCS_MSR_BITMAP_READ_HIGH_MSRS_OFFSET         2048
#define IA32_VMCS_MSR_BITMAP_WRITE_HIGH_MSRS_OFFSET        3072

//
// Maximum number of MSRs loaded or stored on VmEntry/VmExit
//
#define IA32_VMCS_MAX_MSRS  32

//
// VMCS Data Structure
//
typedef struct {
  UINT32  RevisionIdentifier;
  UINT32  AbortIndicator;
} IA32_VMX_VMCS;

//
// VMCS MSR Entry Structure
//
typedef struct {
  UINT32  MsrIndex;
  UINT32  Reserved;
  UINT64  MsrData;
} IA32_VMX_MSR_ENTRY;

//
// VMCS Exit Reason Structure
//
typedef union {
  struct {
    UINT32  BasicReason:16;
    UINT32  Reserved:14;
    UINT32  FailedVmExit:1;
    UINT32  FailedVmEntry:1;
  } Bits;
  UINT32  Uint32;
} IA32_VMX_EXIT_REASON;

//
// VMCS Exit Reason - Basic Reason
// If change this enum, please also change gunnison\ia32emulator\emulator_private_types.h
//
typedef enum {
    Ia32VmxExitBasicReasonSoftwareInterruptExceptionNmi = 0,
    Ia32VmxExitBasicReasonHardwareInterrupt             = 1,
    Ia32VmxExitBasicReasonTripleFault                   = 2,
    Ia32VmxExitBasicReasonInitEvent                     = 3,
    Ia32VmxExitBasicReasonSipiEvent                     = 4,
    Ia32VmxExitBasicReasonSmiIoEvent                    = 5,
    Ia32VmxExitBasicReasonSmiOtherEvent                 = 6,
    Ia32VmxExitBasicReasonPendingInterrupt              = 7,
    Ia32VmxExitNmiWindow                                = 8,
    Ia32VmxExitBasicReasonTaskSwitch                    = 9,
    Ia32VmxExitBasicReasonCpuidInstruction              = 10,
    Ia32VmxExitBasicReasonGetsecInstruction             = 11,
    Ia32VmxExitBasicReasonHltInstruction                = 12,
    Ia32VmxExitBasicReasonInvdInstruction               = 13,
    Ia32VmxExitBasicReasonInvlpgInstruction             = 14,
    Ia32VmxExitBasicReasonRdpmcInstruction              = 15,
    Ia32VmxExitBasicReasonRdtscInstruction              = 16,
    Ia32VmxExitBasicReasonRsmInstruction                = 17,
    Ia32VmxExitBasicReasonVmcallInstruction             = 18,
    Ia32VmxExitBasicReasonVmclearInstruction            = 19,
    Ia32VmxExitBasicReasonVmlaunchInstruction           = 20,
    Ia32VmxExitBasicReasonVmptrldInstruction            = 21,
    Ia32VmxExitBasicReasonVmptrstInstruction            = 22,
    Ia32VmxExitBasicReasonVmreadInstruction             = 23,
    Ia32VmxExitBasicReasonVmresumeInstruction           = 24,
    Ia32VmxExitBasicReasonVmwriteInstruction            = 25,
    Ia32VmxExitBasicReasonVmxoffInstruction             = 26,
    Ia32VmxExitBasicReasonVmxonInstruction              = 27,
    Ia32VmxExitBasicReasonCrAccess                      = 28,
    Ia32VmxExitBasicReasonDrAccess                      = 29,
    Ia32VmxExitBasicReasonIoInstruction                 = 30,
    Ia32VmxExitBasicReasonMsrRead                       = 31,
    Ia32VmxExitBasicReasonMsrWrite                      = 32,
    Ia32VmxExitBasicReasonFailedVmEnterGuestState       = 33,
    Ia32VmxExitBasicReasonFailedVmEnterMsrLoading       = 34,
    Ia32VmxExitBasicReasonFailedVmExit                  = 35,
    Ia32VmxExitBasicReasonMwaitInstruction              = 36,
    Ia32VmxExitBasicReasonMonitorTrapFlag               = 37,
    Ia32VmxExitBasicReasonInvalidVmexitReason38         = 38,
    Ia32VmxExitBasicReasonMonitor                       = 39,
    Ia32VmxExitBasicReasonPause                         = 40,
    Ia32VmxExitBasicReasonFailureDueMachineCheck        = 41,
    Ia32VmxExitBasicReasonInvalidVmexitReason42         = 42,
    Ia32VmxExitBasicReasonTprBelowThreshold             = 43,
    Ia32VmxExitBasicReasonApicAccess                    = 44,
    Ia32VmxExitBasicReasonInvalidVmexitReason45         = 45,
    Ia32VmxExitBasicReasonGdtrIdtrAccess                = 46,
    Ia32VmxExitBasicReasonLdtrTrAccess                  = 47,
    Ia32VmxExitBasicReasonEptViolation                  = 48,
    Ia32VmxExitBasicReasonEptMisconfiguration           = 49,
    Ia32VmxExitBasicReasonInveptInstruction             = 50,
    Ia32VmxExitBasicReasonRdtscpInstruction             = 51,
    Ia32VmxExitBasicReasonPreemptionTimerExpired        = 52,
    Ia32VmxExitBasicReasonInvvpidInstruction            = 53,
    Ia32VmxExitBasicReasonInvalidVmexitReason54         = 54,
    Ia32VmxExitBasicReasonXsetbvInstruction             = 55,

#ifdef FAST_VIEW_SWITCH
    Ia32VmxExitBasicReasonPlaceHolder1                  = 56,
    Ia32VmxExitBasicReasonPlaceHolder2                  = 57,
    Ia32VmxExitBasicReasonPlaceHolder3                  = 58,
    Ia32VmxExitBasicReasonInvalidVmfunc                 = 59,
    Ia32VmxExitBasicReasonCount                         = 60,
#else
    Ia32VmxExitBasicReasonCount                         = 56,
#endif
} IA32_VMX_EXIT_BASIC_REASON;

#pragma warning( push )
#pragma warning (disable : 4214) // enable non-standard bitfield
//
// VMCS Exit Qualification
//
typedef union {

  struct {
    UINT32
            Size:3,            // 0=1 byte, 1=2 byte, 3=4 byte
            Direction:1,       // 0=Out, 1=In
            String:1,          // 0=Not String, 1=String
            Rep:1,             // 0=Not REP, 1=REP
            OpEncoding:1,      // 0=DX, 1=Immediate
            Reserved_9:9,
            PortNumber:16;
    UINT32  Reserved_32_64:32;
  } IoInstruction;


  struct {
    UINT32
            Number:4,      // CR#.  0 for CLTS and LMSW
            AccessType:2,  // 0=Move to CR, 1=Move from CR, 2=CLTS, 3=LMSW
            OperandType:1, // LMSW operand type: 0=Register 1=memory. For CLTS and MOV CR cleared to 0
            Reserved_2:1,
            MoveGpr:4,     // 0 for CLTR and LMSW.  0=EAX, 1=ECX, 2=EDX, 3=EBX, 4=ESP, 5=EBP, 6=ESI, 7=EDI
            Reserved_3:4,
            LmswData:16;   // 0 for CLTS and Move to/from CR#
    UINT32  Reserved_32_64;
  } CrAccess;

  struct {
    UINT32
            Number:3,      // DR#
            Reserved_4:1,
            Direction:1,   // 0=Move to DR, 1= Move from DR
            Reserved_5:3,
            MoveGpr:4,     // 0=EAX, 1=ECX, 2=EDX, 3=EBX, 4=ESP, 5=EBP, 6=ESI, 7=EDI
            Reserved_12_31:20;
    UINT32  Reserved_32_63;
  } DrAccess;

  struct {
    UINT32
            TssSelector:16,
            Reserved_7:14,
            Source:2;       // 0=CALL, 1=IRET, 2=JMP, 3=Task gate in IDT
    UINT32  Reserved_32_63;
  } TaskSwitch;

  struct {
    UINT32
            Vector:8,
            Reserved_8_31:24;
    UINT32  Reserved_32_63;
  } Sipi;


  struct {
    UINT64  Address;
  } InvlpgInstruction;

  struct {
    UINT64  Address;
  } PageFault;

  struct {
    UINT64  Info;    // 1=Unsupported Sleep State, 2=PDPTR loading problem, 3=NMI injection problem, 4=Bad guest working VMCS pointer
  } FailedVmEnterGuestState;

  struct {
    UINT64  Entry;
  } FailedVmEnterMsrLoading;

  struct {
    UINT64  Info;    // 1=Storing Guest MSR, 2=Loading PDPTR, 3=Attempt to load null CS, SS, TR selector, 4=Loading host MSR
  } FailedVmExit;

  struct {
    UINT32
            R:1,
            W:1,
            X:1,
            EptR:1,
            EptW:1,
            EptX:1,
            reserved_6:1,
            GawViolation:1,
            GlaValidity:1,
            Reserved_9_11:3,
            NMIunblocking:1,
            Reserved_13_31:19;
    UINT32  Reserved_32_64;
  } EptViolation;

  struct {
    UINT32
            BreakPoints:4,
            Reserved:9,
            DbgRegAccess:1,
            SingleStep:1,   // Breakpoint on Single Instruction or Branch taken
            Reserved2:17;
    UINT32  Reserved3;
  } DbgException;

  struct  {
    UINT32
            Scale:2,        // Memory access index scale 0=1, 1=2, 2=4, 3=8
            Reserved_0:1,   // cleared to 0
            Reg1:4,         // Memory access reg1 0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI, 8-15=R8=R15
            AddressSize:3,  // Memory access address size 0=16bit, 1=32bit, 2=64bit
            MemReg:1,       // 0=memory access 1=register access
            Reserved_1:4,   // cleared to 0
            SegReg:3,       // Memory access segment register 0=ES, 1=CS, 2=SS, 3=DS, 4=FS, 5=GS
            IndexReg:4,     // Memory access index register. Encoded like Reg1
            IndexRegInvalid:1,//Memory access - IndexReg is invalid (0=valid, 1=invalid)
            BaseReg:4,      // Memory access base register. Encoded like Reg1
            BaseRegInvalid:1,//Memory access - BaseReg is invalid (0=valid, 1=invalid)
            Reg2:4;         // Encoded like Reg1. Undef on VMCLEAR, VMPTRLD, VMPTRST, and VMXON.
    UINT32  Reserved_32_64:32;
  } VmxInstruction;

  struct {
    UINT32
            offset      :12,    // Offset of access within the APIC page
            access_type :4,     // 0 = data read during instruction execution
                                // 1 = data write during instruction execution
                                // 2 = instruction fetch
                                // 3 = access (read or write) during event delivery
            reserved1    :16;
    UINT32  reserved2;
  } ApicAccess;

  UINT64  Uint64;

} IA32_VMX_EXIT_QUALIFICATION;

#define TASK_SWITCH_TYPE_CALL        0
#define TASK_SWITCH_TYPE_IRET        1
#define TASK_SWITCH_TYPE_JMP         2
#define TASK_SWITCH_TYPE_IDT         3

#pragma warning( pop )

//
// VMCS VM Enter Interrupt Information
//
typedef union {
  struct {
    UINT32  Vector:8;
    UINT32  InterruptType:3;  // 0=Ext Int, 1=Rsvd, 2=NMI, 3=Exception, 4=Soft INT, 5=Priv Soft Trap, 6=Unpriv Soft Trap, 7=Other
    UINT32  DeliverCode:1;    // 0=Do not deliver, 1=Deliver
    UINT32  Reserved:19;
    UINT32  Valid:1;          // 0=Not valid, 1=Valid.  Must be checked first
  } Bits;
  UINT32  Uint32;
} IA32_VMX_VMCS_VM_ENTER_INTERRUPT_INFO;

//
// VMCS VM Exit Interrupt Information
//
typedef enum {
    //1,4,5,7 are not used
  VmExitInterruptTypeExternalInterrupt           = 0,
  VmExitInterruptTypeNmi                         = 2,
  VmExitInterruptTypeException                   = 3,
  VmExitInterruptTypeSoftwareException           = 6,
} IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO_INTERRUPT_TYPE;

typedef union {
  struct {
    UINT32  Vector:8;
    UINT32  InterruptType:3;  // 0=Ext Int, 1=Rsvd, 2=NMI, 3=Exception, 4=Soft INT, 5=Priv Soft Trap, 6=Unpriv Soft Trap, 7=Other
    UINT32  ErrorCodeValid:1; // 0=Not valid, 1=VM_EXIT_INFO_EXCEPTION_ERROR_CODE valid
    UINT32  NmiUnblockingDueToIret:1;  // 1=VmExit occured while executing IRET, with no IDT Vectoring
    UINT32  MustBeZero:18;
    UINT32  Valid:1;
  } Bits;
  UINT32  Uint32;
} IA32_VMX_VMCS_VM_EXIT_INFO_INTERRUPT_INFO;

//
// VMCS VM Enter Interrupt Information
//
typedef enum {
  VmEnterInterruptTypeExternalInterrupt           = 0,
  VmEnterInterruptTypeReserved                    = 1,
  VmEnterInterruptTypeNmi                         = 2,
  VmEnterInterruptTypeHardwareException           = 3,
  VmEnterInterruptTypeSoftwareInterrupt           = 4,
  VmEnterInterruptTypePrivilegedSoftwareInterrupt = 5,
  VmEnterInterruptTypeSoftwareException           = 6,
  VmEnterInterruptTypeOtherEvent                  = 7
} IA32_VMX_VMCS_VM_ENTER_INFO_INTERRUPT_INFO_INTERRUPT_TYPE;

//
// VMCS VM Exit IDT Vectoring
//
typedef union {
  struct {
    UINT32  Vector:8;
    UINT32  InterruptType:3;  // 0=Ext Int, 1=Rsvd, 2=NMI, 3=Exception, 4=Soft INT, 5=Priv Soft Trap, 6=Unpriv Soft Trap, 7=Other
    UINT32  ErrorCodeValid:1; // 0=Not valid, 1=VM_EXIT_INFO_IDT_VECTORING_ERROR_CODE valid
    UINT32  MustBeZero:19;
    UINT32  Valid:1;          // 0=Not valid, 1=Valid.  Must be checked first.
  } Bits;
  UINT32  Uint32;
} IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING;

typedef enum {
  // 1, 5, 7 Not used
  IdtVectoringInterruptTypeExternalInterrupt           = 0,
  IdtVectoringInterruptTypeNmi                         = 2,
  IdtVectoringInterruptTypeException                   = 3,
  IdtVectoringInterruptTypeSoftwareInterrupt           = 4,
  IdtVectoringInterruptTypePrivilegedSoftwareInterrupt = 5,
  IdtVectoringInterruptTypeSoftwareException           = 6,
} IA32_VMX_VMCS_IDT_VECTORING_INFO_INTERRUPT_INFO_INTERRUPT_TYPE;

#define IsSoftwareVector(vec) \
( \
    (vec.Bits.Valid != 0) && \
        ( \
            (vec.Bits.InterruptType == IdtVectoringInterruptTypeSoftwareInterrupt) || \
            (vec.Bits.InterruptType == IdtVectoringInterruptTypePrivilegedSoftwareInterrupt) || \
            (vec.Bits.InterruptType == IdtVectoringInterruptTypeSoftwareException) \
        ) \
)

//
// Error Code for page fault
//
typedef union {
  struct {
    UINT32  Present:1;
    UINT32  IsWrite:1;
    UINT32  IsUser:1;
    UINT32  IsRsvd:1;
    UINT32  InstructionFetch:1;
    UINT32  Reserved:27;
  } Bits;
  UINT32  Uint32;
} IA32_VMX_VMCS_VM_EXIT_ERROR_CODE;

//
// VMCS VM Exit Instruction Information
//
typedef union {
  struct {
    UINT32  Scaling:2;              // 0=None, 1=By 2, 2=By 4, 3=By 8
    UINT32  Reserved_0:1;           // Must be 0
    UINT32  Register1:4;            // 0=EAX, 1=ECX, 2=EDX, 3=EBX, 4=ESP, 5=EBP, 6=ESI, 7=EDI, 8-15=R8-R15
    UINT32  AddressSize:3;          // 0=16-bit, 1=32-bit
    UINT32  RegisterMemory:1;       // 0=Memory, 1=Register
    UINT32  OperandSize:2;          // 0=16-bit, 1=32-bit, 2=64-bit
    UINT32  Reserved_2:2;           // Must be 0
    UINT32  Segment:3;              // 0=ES, 1=CS, 2=SS, 3=DS, 4=FS, 5=GS
    UINT32  IndexRegister:4;        // 0=EAX, 1=ECX, 2=EDX, 3=EBX, 4=ESP, 5=EBP, 6=ESI, 7=EDI, 8-15=R8-R15
    UINT32  IndexRegisterInvalid:1; // 0=Valid, 1=Invalid
    UINT32  BaseRegister:4;         // 0=EAX, 1=ECX, 2=EDX, 3=EBX, 4=ESP, 5=EBP, 6=ESI, 7=EDI, 8-15=R8-R15
    UINT32  BaseRegisterInvalid:1;  // 0=Valid, 1=Invalid
    UINT32  Register2:4;            // 0=EAX, 1=ECX, 2=EDX, 3=EBX, 4=ESP, 5=EBP, 6=ESI, 7=EDI, 8-15=R8-R15
  } Bits;

  struct {
    UINT32
            Reserved_0:7,      // Undefined
            AddrSize  :3,      // 0=16bit, 1=32bit, 2=64bit, other invalid
            Reserved_1:5,      // Undefined
            SegReg    :3,      // 0=ES, 1=CS, 2=SS, 3=DS, 4=FS, 5=GS, other invalid. Undef for INS
            Reserved_2:14;     // Undefined
   } InsOutsInstruction;
    
  UINT32  Uint32;
} IA32_VMX_VMCS_VM_EXIT_INFO_INSTRUCTION_INFO;

//
// VMCS Guest AR
//
typedef union {
  struct {
    UINT32  SegmentType:4;              //
    UINT32  DescriptorType:1;           // 0=System, 1=Code/Data
    UINT32  DescriptorPrivilegeLevel:2;  //
    UINT32  SegmentPresent:1;           //
    UINT32  Reserved_0:4;
    UINT32  Available:1;
    UINT32  Reserved_1:1;
    UINT32  DefaultOperationSize:1;     // 0=16-bit segment, 1=32-bit segment
    UINT32  Granularity:1;
    UINT32  Null:1;
    UINT32  Reserved_2:15;
  } Bits;
  UINT32  Uint32;
} IA32_VMX_VMCS_GUEST_AR;

//
// VMCS Guest Pending DBE
//
typedef union {
  struct {
    UINT32  B:4;                   // See DR7
    UINT32  Reserved_0:1;
    UINT32  EnabledBareakpoint:1;
    UINT32  BreakDetect:1;
    UINT32  BreakSingleSetp:1;
    UINT32  BreakTaskSwitch:1;
    UINT32  Reserved_1:16;
  } Bits;
  UINT32  Uint32;
} IA32_VMX_VMCS_GUEST_PEND_DBE;

//
// VMCS Guest Interruptibility
//
typedef union {
  struct {
    UINT32  BlockNextInstruction:1;
    UINT32  BlockStackSegment:1;
    UINT32  BlockSmi:1;
    UINT32  BlockNmi:1;
    UINT32  Reserved_0:28;
  } Bits;
  UINT32  Uint32;
} IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY;

//
// VMCS Guest Sleep State
//
typedef enum {
  Ia32VmxVmcsGuestSleepStateActive              = 0,
  Ia32VmxVmcsGuestSleepStateHlt                 = 1,
  Ia32VmxVmcsGuestSleepStateTripleFaultShutdown = 2,
  Ia32VmxVmcsGuestSleepStateWaitForSipi         = 3
} IA32_VMX_VMCS_GUEST_SLEEP_STATE;

//
// IA32 MSEG Header
//
typedef struct {
  UINT32  Revision;
  UINT32  SmmMonitorFeatures;
  UINT32  GdtrLimit;
  UINT32  GdtrBaseOffset;
  UINT32  CS;
  UINT32  EIP;
  UINT32  ESP;
  UINT32  CR3Offset;
} IA32_MSEG_HEADER;

#pragma PACK_OFF

#endif  // _VMX_VMCS_H_
