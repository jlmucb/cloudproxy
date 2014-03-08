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

#ifndef _IA32_DEFS_H_
#define _IA32_DEFS_H_

#pragma PACK_ON

// Segment Selector Definitions

#define IA32_SELECTOR_INDEX_MASK 0xFFF8


// Note About IA32_SELECTOR
// ------------------------
// Although actual selectors are 16-bit fields, the following IA32_SELECTOR
// definition is of a 32-bit union.  This is done because standard C requires
// bit fields to reside within an int-sized variable.

typedef union
{
    struct
    {
        UINT32  rpl   : 2;    // Bits 1-0
        UINT32  ti    : 1;    // Bit  2
        UINT32  index : 13;   // Bits 3-15
        UINT32  dummy : 16;   // Fill up to 32 bits.  Actual selector is 16 bits.
    }       bits;
    UINT16  sel16;
    UINT32  dummy;
} PACKED IA32_SELECTOR;


// Descriptor Definitions
typedef struct {
        UINT16  limit;
        UINT32  base;
} PACKED IA32_GDTR, IA32_IDTR;

typedef struct {
        struct {
                UINT32  limit_15_00             : 16;
                UINT32  base_address_15_00      : 16;
        } lo;
        struct {
                UINT32  base_address_23_16      : 8;
                UINT32  accessed                : 1;
                UINT32  writable                : 1;
                UINT32  expansion_direction     : 1;
                UINT32  mbz_11                  : 1;    // Must Be Zero
                UINT32  mbo_12                  : 1;    // Must Be One
                UINT32  dpl                     : 2;    // Descriptor Privilege Level
                UINT32  present                 : 1;
                UINT32  limit_19_16             : 4;
                UINT32  avl                     : 1;    // Available to software
                UINT32  mbz_21                  : 1;    // Must Be Zero
                UINT32  big                     : 1;
                UINT32  granularity             : 1;
                UINT32  base_address_31_24      : 8;
        } hi;
} PACKED IA32_DATA_SEGMENT_DESCRIPTOR;

typedef struct {
        struct {
                UINT32  limit_15_00             : 16;
                UINT32  base_address_15_00      : 16;
        } lo;
        struct {
                UINT32  base_address_23_16      : 8;
                UINT32  accessed                : 1;
                UINT32  readable                : 1;
                UINT32  conforming              : 1;
                UINT32  mbo_11                  : 1;    // Must Be One
                UINT32  mbo_12                  : 1;    // Must Be One
                UINT32  dpl                     : 2;    // Descriptor Privilege Level
                UINT32  present                 : 1;
                UINT32  limit_19_16             : 4;
                UINT32  avl                     : 1;    // Available to software
                UINT32  mbz_21                  : 1;    // Must Be Zero
                UINT32  default_size            : 1;    // 0 = 16-bit segment; 1 = 32-bit segment
                UINT32  granularity             : 1;
                UINT32  base_address_31_24      : 8;
        } hi;
} PACKED IA32_CODE_SEGMENT_DESCRIPTOR;

typedef struct {
        struct {
                UINT32  limit_15_00             : 16;
                UINT32  base_address_15_00      : 16;
        } lo;
        struct {
                UINT32  base_address_23_16      : 8;
                UINT32  type                    : 4;
                UINT32  s                       : 1;    // 0 = system; 1 = code or data 
                UINT32  dpl                     : 2;    // Descriptor Privilege Level
                UINT32  present                 : 1;
                UINT32  limit_19_16             : 4;
                UINT32  avl                     : 1;    // Available to software
                UINT32  mbz_21                  : 1;    // Must Be Zero
                UINT32  default_size            : 1;    // 0 = 16-bit segment; 1 = 32-bit segment
                UINT32  granularity             : 1;
                UINT32  base_address_31_24      : 8;
        } hi;
} PACKED IA32_GENERIC_SEGMENT_DESCRIPTOR;

typedef struct {
        struct {
                UINT32  limit_15_00             : 16;
                UINT32  base_address_15_00      : 16;
        } lo;
        struct {
                UINT32  base_address_23_16      : 8;
                UINT32  mbo_8                   : 1; // Must Be One
                UINT32  busy                    : 1;
                UINT32  mbz_10                  : 1; // Must Be Zero
                UINT32  mbo_11                  : 1;    // Must Be One
                UINT32  mbz_12                  : 1;    // Must Be Zero
                UINT32  dpl                     : 2;    // Descriptor Privilege Level
                UINT32  present                 : 1;
                UINT32  limit_19_16             : 4;
                UINT32  avl                     : 1;    // Available to software
                UINT32  mbz_21                  : 1;    // Must Be Zero
                UINT32  mbz_22                  : 1;  // Must Be Zero
                UINT32  granularity             : 1;
                UINT32  base_address_31_24      : 8;
        } hi;
} PACKED IA32_STACK_SEGMENT_DESCRIPTOR;

typedef struct {
        UINT16  limit_15_00;
        UINT16  base_address_15_00;
    UINT8       base_address_23_16;
    UINT16  attributes;
    UINT8   base_address_31_24;
} PACKED IA32_GENERIC_SEGMENT_DESCRIPTOR_ATTR;

typedef union
{
    IA32_GENERIC_SEGMENT_DESCRIPTOR       gen;
    IA32_GENERIC_SEGMENT_DESCRIPTOR_ATTR  gen_attr;
    IA32_DATA_SEGMENT_DESCRIPTOR          ds;
    IA32_CODE_SEGMENT_DESCRIPTOR          cs;
    IA32_STACK_SEGMENT_DESCRIPTOR         tss;
    // TODO: add system segment descriptor
    struct {
        UINT32 lo;
        UINT32 hi;
    }                                     desc32;
    UINT64                                desc64;
} PACKED IA32_SEGMENT_DESCRIPTOR;  

// Note About IA32_SEGMENT_DESCRIPTOR_ATTR
// ---------------------------------------
// Although actual attributes are 16-bit fields, the following
// definition is of a 32-bit union.  This is done because standard C requires
// bit fields to reside within an int-sized variable.

typedef union
{
    struct {
        UINT32      type            : 4;
        UINT32      s               : 1;    // 0 = system; 1 = code or data 
        UINT32      dpl             : 2;    // Descriptor Privilege Level
        UINT32      present         : 1;
        UINT32      limit_19_16     : 4;
        UINT32      avl             : 1;    // Available to software
        UINT32      mbz_21          : 1;    // Must Be Zero
        UINT32      default_size    : 1;    // 0 = 16-bit segment; 1 = 32-bit segment
        UINT32      granularity     : 1;
        UINT32      dummy           : 16;   // Fill up to 32 bits.  Actual attributes
                                        // are 16 bits.
    }      bits;
    UINT16 attr16;
    UINT32 dummy;   // Fill up to 32 bits.  Actual attributes are 16 bits.
} PACKED IA32_SEGMENT_DESCRIPTOR_ATTR;

// ICR Definitions
typedef union {
    struct {
        UINT32      reserved_1              : 24;
        UINT32      destination             : 8;
    } bits;
    UINT32          uint32;
} IA32_ICR_HIGH;

typedef union {
    struct {
        UINT32      vector                  : 8;
        UINT32      delivery_mode           : 3;
        UINT32      destination_mode        : 1;
        UINT32      delivery_status         : 1;
        UINT32      reserved_1              : 1;
        UINT32      level                   : 1;
        UINT32      trigger_mode            : 1;
        UINT32      reserved_2              : 2;
        UINT32      destination_shorthand   : 2;
        UINT32      reserved_3              : 12;
    }                             bits;
    UINT32                        uint32;
} IA32_ICR_LOW;

typedef struct {
    IA32_ICR_LOW  lo_dword;
    IA32_ICR_HIGH hi_dword;
} IA32_ICR;


// Local APIC Memory Mapped I/O register offsets
#define LOCAL_APIC_IDENTIFICATION_OFFSET                    0x020
#define LOCAL_APIC_IDENTIFICATION_OFFSET_HIGH               LOCAL_APIC_IDENTIFICATION_OFFSET + 0x3
#define LOCAL_APIC_VERSION_OFFSET                           0x030
#define LOCAL_APIC_TASK_PRIORITY_OFFSET                     0x080
#define LOCAL_APIC_ARBITRATION_PRIORITY_OFFSET              0x090
#define LOCAL_APIC_PROCESSOR_PRIORITY_OFFSET                0x0A0
#define LOCAL_APIC_EOI_OFFSET                               0x0B0
#define LOCAL_APIC_LOGICAL_DESTINATION_OFFSET               0x0D0
#define LOCAL_APIC_DESTINATION_FORMAT_OFFSET                0x0E0
#define LOCAL_APIC_SPURRIOUS_INTERRUPT_VECTOR_OFFSET        0x0F0
#define LOCAL_APIC_ISR_OFFSET                               0x100
#define LOCAL_APIC_TMR_OFFSET                               0x180
#define LOCAL_APIC_IRR_OFFSET                               0x200
#define LOCAL_APIC_ERROR_STATUS_OFFSET                      0x280
#define LOCAL_APIC_ICR_OFFSET                               0x300
#define LOCAL_APIC_ICR_OFFSET_HIGH                          LOCAL_APIC_ICR_OFFSET + 0x10
#define LOCAL_APIC_LVT_TIMER_OFFSET                         0x320
#define LOCAL_APIC_LVT_THERMAL_SENSOR_OFFSET                0x330
#define LOCAL_APIC_LVT_PERFORMANCE_MONITOR_COUNTERS_OFFSET  0x340
#define LOCAL_APIC_LVT_LINT0_OFFSET                         0x350
#define LOCAL_APIC_LVT_LINT1_OFFSET                         0x360
#define LOCAL_APIC_LVT_ERROR_OFFSET                         0x370
#define LOCAL_APIC_INITIAL_COUNT_OFFSET                     0x380
#define LOCAL_APIC_CURRENT_COUNT_OFFSET                     0x390
#define LOCAL_APIC_DIVIDE_CONFIGURATION_OFFSET              0x3E0
#define LOCAL_APIC_MAXIMUM_OFFSET                           0x3E4

#define LOCAL_APIC_ID_LOW_RESERVED_BITS_COUNT               24

#define LOCAL_APIC_DESTINATION_BROADCAST                    0xFF

#define LOCAL_APIC_DESTINATION_MODE_PHYSICAL                0x0
#define LOCAL_APIC_DESTINATION_MODE_LOGICAL                 0x1

#define LOCAL_APIC_DELIVERY_STATUS_IDLE                     0x0
#define LOCAL_APIC_DELIVERY_STATUS_SEND_PENDING             0x1

#define LOCAL_APIC_DELIVERY_MODE_FIXED                      0x0
#define LOCAL_APIC_DELIVERY_MODE_LOWEST_PRIORITY            0x1
#define LOCAL_APIC_DELIVERY_MODE_SMI                        0x2
#define LOCAL_APIC_DELIVERY_MODE_REMOTE_READ                0x3
#define LOCAL_APIC_DELIVERY_MODE_NMI                        0x4
#define LOCAL_APIC_DELIVERY_MODE_INIT                       0x5
#define LOCAL_APIC_DELIVERY_MODE_SIPI                       0x6
#define LOCAL_APIC_DELIVERY_MODE_MAX                        0x7

#define LOCAL_APIC_TRIGGER_MODE_EDGE                        0x0
#define LOCAL_APIC_TRIGGER_MODE_LEVEL                       0x1

#define LOCAL_APIC_DELIVERY_LEVEL_DEASSERT                  0x0
#define LOCAL_APIC_DELIVERY_LEVEL_ASSERT                    0x1

#define LOCAL_APIC_BROADCAST_MODE_SPECIFY_CPU               0x0
#define LOCAL_APIC_BROADCAST_MODE_SELF                      0x1
#define LOCAL_APIC_BROADCAST_MODE_ALL_INCLUDING_SELF        0x2
#define LOCAL_APIC_BROADCAST_MODE_ALL_EXCLUDING_SELF        0x3

// get LOCAL_APIC_BASE from IA32_MSR_APIC_BASE_INDEX
#define LOCAL_APIC_BASE_MSR_MASK                            (~0xFFF)


#pragma PACK_OFF

#endif // _IA32_DEFS_H_

