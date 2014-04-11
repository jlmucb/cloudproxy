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

#ifndef _UVMM_ARCH_DEFS_H_
#define _UVMM_ARCH_DEFS_H_

#include "vmm_defs.h"

// This file contains unified architecture-related structures, defined by uVMM

#pragma PACK_ON


// Standard E820 BIOS map
typedef enum _INT15_E820_RANGE_TYPE {
    INT15_E820_ADDRESS_RANGE_TYPE_MEMORY    = 1,
    INT15_E820_ADDRESS_RANGE_TYPE_RESERVED  = 2,
    INT15_E820_ADDRESS_RANGE_TYPE_ACPI      = 3,
    INT15_E820_ADDRESS_RANGE_TYPE_NVS       = 4,
    INT15_E820_ADDRESS_RANGE_TYPE_UNUSABLE  = 5
} INT15_E820_RANGE_TYPE;

typedef union _INT15_E820_MEMORY_MAP_EXT_ATTRIBUTES {
    struct {
        UINT32 enabled      : 1;
        UINT32 non_volatile : 1;
        UINT32 reserved     : 30;
    } Bits;
    UINT32 uint32;
} INT15_E820_MEMORY_MAP_EXT_ATTRIBUTES;

typedef struct _INT15_E820_MEMORY_MAP_ENTRY {
    UINT64                                  base_address;
    UINT64                                  length;
    INT15_E820_RANGE_TYPE                   address_range_type;
} PACKED INT15_E820_MEMORY_MAP_ENTRY, *PINT15_E820_MEMORY_MAP_ENTRY;

typedef struct _INT15_E820_MEMORY_MAP_ENTRY_EXT {
    INT15_E820_MEMORY_MAP_ENTRY             basic_entry;
    INT15_E820_MEMORY_MAP_EXT_ATTRIBUTES    extended_attributes;
} PACKED INT15_E820_MEMORY_MAP_ENTRY_EXT, *PINT15_E820_MEMORY_MAP_ENTRY_EXT;

// The memory_map_entry may be either INT15_E820_MEMORY_MAP_ENTRY_EXT (24 bytes)
// or INT15_E820_MEMORY_MAP_ENTRY (20 bytes). The returned value size depends on
// the caller-passed buffer - if caller passed 24 bytes or more, the extended entry
// is returned. The minimum buffer size must be 20 bytes.
typedef struct _INT15_E820_MEMORY_MAP {
    UINT32                           memory_map_size;    // size in bytes of all entries,
                                                         // not including the size field itself
    INT15_E820_MEMORY_MAP_ENTRY_EXT  memory_map_entry[1];
} PACKED INT15_E820_MEMORY_MAP;

// NOTE: This enumerator is referened in assembler
typedef enum _VMM_IA32_GP_REGISTERS {
    // GP
    IA32_REG_RAX = 0,
    IA32_REG_RBX,
    IA32_REG_RCX,
    IA32_REG_RDX,
    IA32_REG_RDI,
    IA32_REG_RSI,
    IA32_REG_RBP,
    IA32_REG_RSP,
    IA32_REG_R8,
    IA32_REG_R9,
    IA32_REG_R10,
    IA32_REG_R11,
    IA32_REG_R12,
    IA32_REG_R13,
    IA32_REG_R14,
    IA32_REG_R15,

    // RIP
    IA32_REG_RIP,

    // flags
    IA32_REG_RFLAGS,

    // the count of GP registers
    IA32_REG_GP_COUNT
} VMM_IA32_GP_REGISTERS;

// NOTE: This enumerator is referened in assembler
typedef enum _VMM_IA32_XMM_REGISTERS {
    // XMM
    IA32_REG_XMM0 = 0,
    IA32_REG_XMM1,
    IA32_REG_XMM2,
    IA32_REG_XMM3,
    IA32_REG_XMM4,
    IA32_REG_XMM5,
    IA32_REG_XMM6,
    IA32_REG_XMM7,
    IA32_REG_XMM8,
    IA32_REG_XMM9,
    IA32_REG_XMM10,
    IA32_REG_XMM11,
    IA32_REG_XMM12,
    IA32_REG_XMM13,
    IA32_REG_XMM14,
    IA32_REG_XMM15,

    // the count of XMM registers
    IA32_REG_XMM_COUNT
} VMM_IA32_XMM_REGISTERS;

typedef enum _VMM_IA32_SEGMENT_REGISTERS {
    // general segments
    IA32_SEG_CS = 0,
    IA32_SEG_DS,
    IA32_SEG_SS,
    IA32_SEG_ES,
    IA32_SEG_FS,
    IA32_SEG_GS,
    IA32_SEG_LDTR,
    IA32_SEG_TR,
    // the count of general segments
    IA32_SEG_COUNT
} VMM_IA32_SEGMENT_REGISTERS;

typedef enum _VMM_IA32_DEBUG_REGISTERS {
    IA32_REG_DR0 = 0,
    IA32_REG_DR1,
    IA32_REG_DR2,
    IA32_REG_DR3,
    // dr4 and dr5 are reserved
    IA32_REG_DR6,
    IA32_REG_DR7,

    // the count of debug registers
    IA32_REG_DEBUG_COUNT
} VMM_IA32_DEBUG_REGISTERS;

typedef enum _VMM_IA32_CONTROL_REGISTERS {
    IA32_CTRL_CR0 = 0,
    IA32_CTRL_CR2,
    IA32_CTRL_CR3,
    IA32_CTRL_CR4,
    IA32_CTRL_CR8,

    // the count of control registers
    IA32_CTRL_COUNT
} VMM_IA32_CONTROL_REGISTERS;

#define UNSUPPORTED_CR   IA32_CTRL_COUNT


typedef enum _VMM_IA32_MODEL_SPECIFIC_REGISTERS {
    IA32_VMM_MSR_DEBUGCTL = 0,
    IA32_VMM_MSR_EFER,
    IA32_VMM_MSR_PAT,
    IA32_VMM_MSR_SYSENTER_ESP,
    IA32_VMM_MSR_SYSENTER_EIP,
    IA32_VMM_MSR_SYSENTER_CS,
    IA32_VMM_MSR_SMBASE,
    IA32_VMM_MSR_PERF_GLOBAL_CTRL,
    IA32_VMM_MSR_FEATURE_CONTROL,
    IA32_VMM_MSR_STAR,
    IA32_VMM_MSR_LSTAR,
    IA32_VMM_MSR_FMASK,
    IA32_VMM_MSR_FS_BASE,
    IA32_VMM_MSR_GS_BASE,
    IA32_VMM_MSR_KERNEL_GS_BASE,

    // the count of supported model specific registers
    IA32_VMM_MSR_COUNT
} VMM_IA32_MODEL_SPECIFIC_REGISTERS;

// NOTE: This structure is referened in assembler
typedef struct _VMM_GP_REGISTERS {
    UINT64 reg[IA32_REG_GP_COUNT];
} VMM_GP_REGISTERS;

// NOTE: This structure is referened in assembler
typedef struct _VMM_XMM_REGISTERS {
    UINT128 reg[IA32_REG_XMM_COUNT];
} VMM_XMM_REGISTERS;

typedef union
{
    UINT32 attr32;
    struct {
        UINT32 type          :4;   /* bits 3:0   */
        UINT32 s_bit         :1;   /* bit  4     */
        UINT32 dpl           :2;   /* bit2 6:5   */
        UINT32 p_bit         :1;   /* bit  7     */
        UINT32 reserved_11_8 :4;   /* bits 11:8  */
        UINT32 avl_bit       :1;   /* bit  12    */
        UINT32 l_bit         :1;   /* bit  13    */
        UINT32 db_bit        :1;   /* bit  14    */
        UINT32 g_bit         :1;   /* bit  15    */
        UINT32 null_bit      :1;   /* bit  16    */
        UINT32 reserved_31_17:15;  /* bits 31:17 */
    } bits;
} PACKED VMM_SEGMENT_ATTRIBUTES;

typedef struct _VMM_SEGMENT_STRUCT {
    UINT64 base;            // for real mode it should be selector << 4
    UINT32 limit;
    UINT32 attributes;      // TODO: modify this to use VMM_SEGMENT_ATTRIBUTES
    UINT16 selector;        // for real mode this is the segment value
    UINT16 reserved[3];
} PACKED VMM_SEGMENT_STRUCT;

typedef struct _VMM_SEGMENTS {
    VMM_SEGMENT_STRUCT segment[IA32_SEG_COUNT];
} VMM_SEGMENTS;

typedef struct _VMM_IA32_GDT_REGISTER {
        UINT64          base;
    UINT32          limit;
} PACKED VMM_IA32_GDT_REGISTER;

typedef VMM_IA32_GDT_REGISTER VMM_IA32_IDT_REGISTER;

typedef struct _VMM_DEBUG_REGISTERS {
    UINT64 reg[IA32_REG_DEBUG_COUNT];
} VMM_DEBUG_REGISTERS;

typedef struct _VMM_CONTROL_REGISTERS {
    // Control registers
    UINT64                cr[IA32_CTRL_COUNT];
    // GDT
        VMM_IA32_GDT_REGISTER gdtr;
    UINT32                reserved_1;
    // IDT
    VMM_IA32_IDT_REGISTER idtr;
    UINT32                reserved_2;
} VMM_CONTROL_REGISTERS;

typedef struct _VMM_MODEL_SPECIFIC_REGISTERS {
    UINT64 msr_debugctl;
    UINT64 msr_efer;
    UINT64 msr_pat;

    UINT64 msr_sysenter_esp;
    UINT64 msr_sysenter_eip;

    UINT64 pending_exceptions;

    UINT32 msr_sysenter_cs;

    UINT32 interruptibility_state;
    UINT32 activity_state;
    UINT32 smbase;
} VMM_MODEL_SPECIFIC_REGISTERS;

#pragma PACK_OFF

#endif // _UVMM_ARCH_DEFS_H_

