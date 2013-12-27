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

#ifndef _EM64T_DEFS_H_
#define _EM64T_DEFS_H_

#include "msr_defs.h"

#pragma PACK_ON

//
// IA-32 EFLAGS Register
//
typedef union {
  struct {
    UINT32  CF:1;           // Carry Flag
    UINT32  Reserved_0:1;   // Reserved
    UINT32  PF:1;           // Parity Flag
    UINT32  Reserved_1:1;   // Reserved
    UINT32  AF:1;           // Auxiliary Carry Flag
    UINT32  Reserved_2:1;   // Reserved
    UINT32  ZF:1;           // Zero Flag
    UINT32  SF:1;           // Sign Flag
    UINT32  TP:1;           // Trap Flag
    UINT32  IFL:1;          // Interrupt Enable Flag
    UINT32  DF:1;           // Direction Flag
    UINT32  OF:1;           // Overflow Flag
    UINT32  IOPL:2;         // I/O Privilege Level
    UINT32  NT:1;           // Nexted Task
    UINT32  Reserved_3:1;   // Reserved
    UINT32  RF:1;           // Resume Flag
    UINT32  VM:1;           // Virtual 8086 Mode
    UINT32  AC:1;           // Alignment Check
    UINT32  VIF:1;          // Virtual Interrupt Flag
    UINT32  VIP:1;          // Virtual Interrupt Pending
    UINT32  ID:1;           // ID Flag
    UINT32  Reserved_4:10;  // Reserved
    UINT32  Reserved_5:32;  // Reserved
  } Bits;
  UINT64  Uint64;
} EM64T_RFLAGS;

//
// IA-32 Control Register #0 (CR0)
//
#define CR0_PE                    0x00000001
#define CR0_MP                    0x00000002
#define CR0_EM                    0x00000004
#define CR0_TS                    0x00000008
#define CR0_ET                    0x00000010
#define CR0_NE                    0x00000020
#define CR0_WP                    0x00010000
#define CR0_AM                    0x00040000
#define CR0_NW                    0x20000000
#define CR0_CD                    0x40000000
#define CR0_PG                    0x80000000

typedef union _EM64T_CR0 {
  struct {
    UINT32  PE:1;           // Protection Enable
    UINT32  MP:1;           // Monitor Coprocessor
    UINT32  EM:1;           // Emulation
    UINT32  TS:1;           // Task Switched
    UINT32  ET:1;           // Extension Type
    UINT32  NE:1;           // Numeric Error
    UINT32  Reserved_0:10;  // Reserved
    UINT32  WP:1;           // Write Protect
    UINT32  Reserved_1:1;   // Reserved
    UINT32  AM:1;           // Alignment Mask
    UINT32  Reserved_2:10;  // Reserved
    UINT32  NW:1;           // Not Write-through
    UINT32  CD:1;           // Cache Disable
    UINT32  PG:1;           // Paging
    UINT32  Reserved_3:32;  // Must be zero
  } Bits;
  UINT64  Uint64;
} EM64T_CR0;

#define EM64T_CR1_ReservedBits( Cr1 )                                           \
   ((Cr1).Bits.Reserved_0 && (Cr1).Bits.Reserved_1 && (Cr1).Bits.Reserved_2 && (Cr1).Bits.Reserved_3)

//
// IA-32 Control Register #3 (CR3)
//
typedef struct _EM64T_CR3 {
    struct {
        UINT32 reserved_0_2         :3;
        UINT32 pwt                  :1;     // Page Write Through
        UINT32 pcd                  :1;     // Page Cache Disable
        UINT32 reserved_5_11        :7;
        UINT32 base_address_lo      :20;    // bits 31..12 of base address (low bits are zeroes)
    } lo;
    struct {
        UINT32 base_address_hi      :20;    // bits 51..32 of base address
        UINT32 zeroes               :11;
        UINT32 no_execute           :1;
    } hi;
} EM64T_CR3;

//
// IA-32 Control Register #4 (CR4)
//
#define CR4_VME         0x00000001
#define CR4_PVI         0x00000002
#define CR4_TSD         0x00000004
#define CR4_DE          0x00000008
#define CR4_PSE         0x00000010
#define CR4_PAE         0x00000020
#define CR4_MCE         0x00000040
#define CR4_PGE         0x00000080
#define CR4_PCE         0x00000100
#define CR4_OSFXSR      0x00000200
#define CR4_OSXMMEXCPT  0x00000400
#define CR4_VMXE        0x00002000
#define CR4_SMXE        0x00004000
#define CR4_OSXSAVE     0x00040000

typedef union _EM64T_CR4 {
  struct {
    UINT32  VME:1;          // Virtual-8086 Mode Extensions
    UINT32  PVI:1;          // Protected-Mode Virtual Interrupts
    UINT32  TSD:1;          // Time Stamp Disable
    UINT32  DE:1;           // Debugging Extensions
    UINT32  PSE:1;          // Page Size Extensions
    UINT32  PAE:1;          // Physical Address Extension
    UINT32  MCE:1;          // Machine Check Enable
    UINT32  PGE:1;          // Page Global Enable
    UINT32  PCE:1;          // Performance Monitoring Counter Enable
    UINT32  OSFXSR:1;       // Operating System Support for FXSAVE and FXRSTOR instructions
    UINT32  OSXMMEXCPT:1;   // Operating System Support for Unmasked SIMD Floating Point Exceptions
    UINT32  Reserved_0:2;   // Reserved
    UINT32  VMXE:1;         // VMX Enable
    UINT32  SMXE:1;         // SMX Enable
    UINT32  Reserved_1:1;   // Reseved
    UINT32  FSGSBASE:1;     // Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE,
                            // and WRGSBASE.
    UINT32  PCIDE:1;        // 
    UINT32  OSXSAVE:1;      // XSAVE and Processor Extended States-Enable Bit
    UINT32  Reserved_2:1;   // Reseved
    UINT32  SMEP:1;         // Supervisor Mode Execution Prevention 
    UINT32  Reserved_3:11;  // Reserved
    UINT32  Reserved_4:32;  // Reserved, must be zero
  } Bits;
  UINT64  Uint64;
} EM64T_CR4;

#define EM64T_CR4_ReservedBits( Cr4 )                                           \
   ((Cr4).Bits.Reserved_0 && (Cr4).Bits.Reserved_1 && (Cr4).Bits.Reserved_2)

//
// IA-32 Control Register #8 (CR8)
//
typedef union _EM64T_CR8 {
  struct {
    UINT32  TPR:4;          // Reflect APIC.TPR[7:4] bits
    UINT32  Reserved_1:28;  // Reserved, must be zero
    UINT32  Reserved_2:32;  // Reserved, must be zero
  } Bits;
  UINT64  Uint64;
} EM64T_CR8;

#define EM64T_CR8_VALID_BITS_MASK ((UINT64)0x0F)

//
// Descriptor for the Global Descriptor Table(GDT) and Interrupt Descriptor Table(IDT)
//

typedef struct _EM64T_GDTR {
    UINT16  limit;
    UINT64  base;
} PACKED EM64T_GDTR;

#define EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE 0x10000

//
// Code Segment Entry in Global Descriptor Table(GDT)
//
typedef struct _EM64T_CODE_SEGMENT_DESCRIPTOR {
    UINT32    reserved;
    struct {
        UINT32    reserved_00_07    :8;
        UINT32    accessed          :1;
        UINT32    readable          :1;
        UINT32    conforming        :1;
        UINT32    mbo_11            :1;     // Must Be One
        UINT32    mbo_12            :1;     // Must Be One
        UINT32    dpl               :2;     // Descriptor Privilege Level
        UINT32    present           :1;
        UINT32    reserved_19_16    :4;
        UINT32    avl               :1;     // Available to software
        UINT32    long_mode         :1;
        UINT32    default_size      :1;
        UINT32    granularity       :1;
        UINT32    reserved_31_24    :8;
    } hi;
} EM64T_CODE_SEGMENT_DESCRIPTOR;

#define CS_SELECTOR_CPL_BIT 0x3


//
// TSS Entry in Global Descriptor Table(GDT)
//
typedef struct _EM64T_TSS_SEGMENT_DESCRIPTOR {
    struct {
        UINT32  segment_limit_00_15 :16;
        UINT32  base_address_00_15  :16;
    } q0;
    struct {
        UINT32  base_address_23_16  :8;
        UINT32  type                :4;
        UINT32  mbz_12              :1;
        UINT32  dpl                 :2;
        UINT32  present             :1;
        UINT32  segment_limit_16_19 :4;
        UINT32  avl                 :1;
        UINT32  mbz_21_22           :2;
        UINT32  granularity         :1;
        UINT32  base_address_31_24  :8;
    } q1;
    struct {
        UINT32  base_address_32_63;
    } q2;
    UINT32    q3;     // reserved, must be zero
} EM64T_TSS_SEGMENT_DESCRIPTOR;

typedef struct _EM64T_TASK_STATE_SEGMENT {
    UINT32  reserved_1;
    UINT64  rsp[3];
    UINT64  reserved_2;
    UINT64  ist[7];
    UINT64  reserved_3;
    UINT16  reserved4;
    UINT16  io_bitmap_address;  // offset inside TSS
    UINT8   io_bitmap_last_byte;
    UINT8   pad[7];
} PACKED EM64T_TASK_STATE_SEGMENT;

//
// Page-Map Level-4 and Ptr Directory Page Table
//
typedef struct _EM64T_PML4 {
    struct {
        UINT32 present              :1;
        UINT32 rw                   :1;
        UINT32 us                   :1;     // user / supervisor
        UINT32 pwt                  :1;     // Page Write Through
        UINT32 pcd                  :1;     // Page Cache Disable
        UINT32 accessed             :1;
        UINT32 ignored              :1;
        UINT32 zeroes               :2;
        UINT32 avl                  :3;     // available to software
        UINT32 base_address_lo      :20;    // bits 31..12 of base address (low bits are zeroes)
    } lo;
    struct {
        UINT32 base_address_hi      :20;    // bits 51..32 of base address
        UINT32 available            :11;
        UINT32 no_execute           :1;
    } hi;
} EM64T_PML4, EM64T_PDPE;


//
// Page Table Entry for 2MB pages
//
typedef struct _EM64T_PDE_2MB {
    struct {
        UINT32 present              :1;
        UINT32 rw                   :1;
        UINT32 us                   :1;     // user / supervisor
        UINT32 pwt                  :1;     // Page Write Through
        UINT32 pcd                  :1;     // Page Cache Disable
        UINT32 accessed             :1;
        UINT32 dirty                :1;
        UINT32 pse                  :1;     // must be set
        UINT32 global               :1;
        UINT32 avl                  :3;     // available to software
        UINT32 pat                  :1;
        UINT32 zeroes               :8;
        UINT32 base_address_lo      :11;    // bits 31..21 of base address (low bits are zeroes)
    } lo;
    struct {
        UINT32 base_address_hi      :20; // bits 51..32 of base address
        UINT32 available            :11;
        UINT32 no_execute           :1;
    } hi;
} EM64T_PDE_2MB;

//
// EM64T Interrupt Descriptor Table - Gate Descriptor
//
typedef struct _EM64T_IDT_GATE_DESCRIPTOR {
    // offset 0
    UINT32  offset_0_15     :16;    // Offset bits 15..0
    UINT32  css             :16;    // Command Segment Selector

    // offset 4
    UINT32  ist             :3;     // interrupt Stack Table
    UINT32  reserved_0      :5;     // Reserved. must be zeroes
    UINT32  gate_type       :4;     // Gate Type.  See #defines above
    UINT32  reserved2_0     :1;     // must be zero
    UINT32  dpl             :2;     // Descriptor Privilege Level must be zero
    UINT32  present         :1;     // Segment Present Flag
    UINT32  offset_15_31    :16;    // Offset bits 31..16

    // offset 8
    UINT32  offset_32_63;           // Offset bits 32..63

    // offset 12
    UINT32     reserved3;
} EM64T_IDT_GATE_DESCRIPTOR;

typedef EM64T_IDT_GATE_DESCRIPTOR EM64T_IDT_TABLE[256];

typedef struct _EM64T_IDT_DESCRIPTOR {
    UINT16    limit;
    UINT64    base;
} PACKED EM64T_IDT_DESCRIPTOR;

//
// IA32_MISC_ENABLE_MSR
//
typedef union _IA32_MISC_ENABLE_MSR {
  struct {
    UINT32  FastStringEnable:1;
    UINT32  Reserved0:1;
    UINT32  X87FpuFopcodeCompabilityModeEnable:1;
    UINT32  ThermalMoitor1Enable:1;
    UINT32  SplitLockDisable:1;
    UINT32  Reserved1:1;
    UINT32  ThirdLevelCacheDisable:1;
    UINT32  PerformanceMonitoringAvailable:1;
    UINT32  SupressLockEnable:1;
    UINT32  PrefetchQueueDisable:1;
    UINT32  FerrInterruptReportingEnable:1;
    UINT32  BranchTraceStorageUnavailable:1;
    UINT32  PreciseEventBasedSamplingUnavailable:1;
    UINT32  Reserved2:6;
    UINT32  AdjacentCacheLinePrefetchDisable:1;
    UINT32  Reserved3:4;
    UINT32  L1DataCacheContextMode:1;
    UINT32  Reserved4:7;
    UINT32  Reserved5:32;
  } Bits;
  UINT32  Uint32[2];
  UINT64  Uint64;
} IA32_MISC_ENABLE_MSR;

//
// IA-32 MSR Register EFER (0xC0000080)
//
#define EFER_SCE 0x00000001
#define EFER_LME 0x00000100
#define EFER_LMA 0x00000400
#define EFER_NXE 0x00000800

typedef union _IA32_EFER_S {
  struct {
    UINT32  SCE:1;          // (00) SysCall Enable/Disable (R/W)
    UINT32  Reserved_0:7;   //
    UINT32  LME:1;          // (08) Long Mode Enable (IA-32e) (R/W)
    UINT32  Reserved_1:1;   //
    UINT32  LMA:1;          // (10) Long Mode Active (IA-32e) (R)
    UINT32  NXE:1;          // (11) Execute Disabled Enable (R/W)
    UINT32  Reserved_2:20; //
    UINT32  Reserved_3:32; //
  } Bits;
  struct {
    UINT32  Lower;
    UINT32  Upper;
  } Uint32;
  UINT64  Uint64;
} IA32_EFER_S;

// offset in the VMCS MsrBitmap structure for subset of MSR to force VmExit
#define IA32_EFER_WRITE_MSR_VMCS_BITMAP_BYTES_OFFSET        0x80
#define IA32_EFER_WRITE_MSR_VMCS_BITMAP_BIT                 0x1


#define IA32_SIZE_OF_RDMSR_INST              2
#define IA32_SIZE_OF_WRMSR_INST              2


//
// Yonah/Merom specific MSRs
//
//#define IA32_PMG_IO_CAPTURE_INDEX  0xE4

typedef union _IA32_PMG_IO_CAPTURE_MSR {
  struct {
    UINT32  Lvl2BaseAddress:16;
    UINT32  CstRange:7;
    UINT32  Reserved_0:9;
    UINT32  Reserved_1:32;
  } Bits;
  UINT64  Uint64;
} IA32_PMG_IO_CAPTURE_MSR;


#pragma PACK_OFF

#endif // _EM64T_DEFS_H_


