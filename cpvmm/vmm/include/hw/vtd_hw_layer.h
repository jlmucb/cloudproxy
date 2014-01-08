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

#ifndef _VTD_HW_LAYER
#define _VTD_HW_LAYER

#include "vtd.h"
#include "hw_utils.h"

#pragma warning(push)
#pragma warning(disable:4214)

typedef union _DMA_REMAPPING_ROOT_ENTRY_LOW
{
    struct
    {
        UINT32
            present:1,
            reserved:11,
            context_entry_table_ptr_low:20;
        UINT32 context_entry_table_ptr_high;
    } bits;
    UINT64 uint64;
} DMA_REMAPPING_ROOT_ENTRY_LOW;

typedef union _DMA_REMAPPING_ROOT_ENTRY_HIGH
{
    struct
    {
        UINT64 reserved;
    } bits;
    UINT64 uint64;
} DMA_REMAPPING_ROOT_ENTRY_HIGH;

typedef struct _DMA_REMAPPING_ROOT_ENTRY
{
    DMA_REMAPPING_ROOT_ENTRY_LOW low;
    DMA_REMAPPING_ROOT_ENTRY_HIGH high;
} DMA_REMAPPING_ROOT_ENTRY;

typedef enum
{
    TRANSLATION_TYPE_UNTRANSLATED_ADDRESS_ONLY = 0,
    TRANSLATION_TYPE_ALL,
    TRANSLATION_TYPE_PASSTHROUGH_UNTRANSLATED_ADDRESS
} DMA_REMAPPING_TRANSLATION_TYPE;

typedef enum
{
    DMA_REMAPPING_GAW_30 = 0,
    DMA_REMAPPING_GAW_39,
    DMA_REMAPPING_GAW_48,
    DMA_REMAPPING_GAW_57,
    DMA_REMAPPING_GAW_64
} DMA_REMAPPING_GUEST_ADDRESS_WIDTH;

typedef union _DMA_REMAPPING_CONTEXT_ENTRY_LOW
{
    struct
    {
        UINT32
            present:1,
            fault_processing_disable:1,
            translation_type:2,
            eviction_hint:1,             // 0 = default, 1 = eager eviction
            adress_locality_hint:1,      // 0 = default, 1 = requests have spatial locality
            reserved:6,
            address_space_root_low:20;
        UINT32 address_space_root_high;
    } bits;
    UINT64 uint64;
} DMA_REMAPPING_CONTEXT_ENTRY_LOW;

typedef union _DMA_REMAPPING_CONTEXT_ENTRY_HIGH
{
    struct
    {
        UINT32
            address_width:3,
            available:4,
            reserved0:1,
            domain_id:16,
            reserved1:8;
        UINT32 reserved;
    } bits;
    UINT64 uint64;
} DMA_REMAPPING_CONTEXT_ENTRY_HIGH;

typedef struct _DMA_REMAPPING_CONTEXT_ENTRY
{
    DMA_REMAPPING_CONTEXT_ENTRY_LOW low;
    DMA_REMAPPING_CONTEXT_ENTRY_HIGH high;
} DMA_REMAPPING_CONTEXT_ENTRY;

typedef union _DMA_REMAPPING_PAGE_TABLE_ENTRY
{
    struct
    {
        UINT32
            read:1,
            write:1,
            available0:5,
            super_page:1,
            available:3,
            snoop_behavior:1, // 0 = default, 1 = treat as snooped
            address_low:20;
        UINT32
            address_high:30,
            transient_mapping:1,
            available1:1;
    } bits;
    UINT64 uint64;
} DMA_REMAPPING_PAGE_TABLE_ENTRY;

typedef union _DMA_REMAPPING_FAULT_RECORD_LOW
{
    struct
    {
        UINT32
            reserved:12,
            fault_information_low:20;
        UINT32 fault_information_high;
    } bits;
    UINT64 uint64;
} DMA_REMAPPING_FAULT_RECORD_LOW;

typedef union _DMA_REMAPPING_FAULT_RECORD_HIGH
{
    struct
    {
        UINT32
            source_id:16,
            reserved0:16;
        UINT32
            fault_reason:8,
            reserved1:20,
            address_type:2,
            access_type:1, // 0 = write, 1 = read
            reserved2:1;
    } bits;
    UINT64 uint64;
} DMA_REMAPPING_FAULT_RECORD_HIGH;

typedef struct _DMA_REMAPPING_FAULT_RECORD
{
    DMA_REMAPPING_FAULT_RECORD_LOW low;
    DMA_REMAPPING_FAULT_RECORD_HIGH high;
} DMA_REMAPPING_FAULT_RECORD;

typedef enum
{
    SOURCE_ID_QUALIFIER_ALL = 0,
    SOURCE_ID_QUALIFIER_IGNORE_FUNCTION_MSB,
    SOURCE_ID_QUALIFIER_IGNORE_2_FUNCTION_MSB,
    SOURCE_ID_QUALIFIER_IGNORE_FUNCTION
} INTERRUPT_REMAPPING_SOURCE_ID_QUALIFIER;

typedef enum
{
    SOURCE_ID_VALIDATION_NONE,
    SOURCE_ID_VALIDATION_AS_BDF,
    SOURCE_ID_VALIDATION_BUS_IN_RANGE
} INTERRUPT_REMAPPING_SOURCE_ID_VALIDATION_TYPE;

typedef union _INTERRUPT_REMAPPING_TABLE_ENTRY_LOW
{
    struct
    {
        UINT32
            present:1,
            fault_processing_disable:1,
            destination_mode:1, // 0 = physical APIC ID, 1 = logical APIC ID
            redirection_hint:1, // 0 = direct to CPU in destination id field, 1 = direct to one CPU from the group
            trigger_mode:1, // 0 = edge, 1 = level
            delivery_mode:1,
            available:4,
            reserved:4;
        UINT32 destination_id;
     } bits;
    UINT64 uint64;
} INTERRUPT_REMAPPING_TABLE_ENTRY_LOW;

typedef union _INTERRUPT_REMAPPING_TABLE_ENTRY_HIGH
{
    struct
    {
        UINT32
            source_id:16,
            source_id_qualifier:2,
            source_validation_type:2,
            reserved0:12;
        UINT32 reserved1;
     } bits;
    UINT64 uint64;
} INTERRUPT_REMAPPING_TABLE_ENTRY_HIGH;

typedef struct _INTERRUPT_REMAPPING_TABLE_ENTRY
{
    INTERRUPT_REMAPPING_TABLE_ENTRY_LOW low;
    INTERRUPT_REMAPPING_TABLE_ENTRY_HIGH high;
} INTERRUPT_REMAPPING_TABLE_ENTRY;

// vtd registers
#define VTD_VERSION_REGISTER_OFFSET                                         0x0000
#define VTD_CAPABILITY_REGISTER_OFFSET                                      0x0008
#define VTD_EXTENDED_CAPABILITY_REGISTER_OFFSET                             0x0010
#define VTD_GLOBAL_COMMAND_REGISTER_OFFSET                                  0x0018
#define VTD_GLOBAL_STATUS_REGISTER_OFFSET                                   0x001C
#define VTD_ROOT_ENTRY_TABLE_ADDRESS_REGISTER_OFFSET                        0x0020
#define VTD_CONTEXT_COMMAND_REGISTER_OFFSET                                 0x0028
#define VTD_FAULT_STATUS_REGISTER_OFFSET                                    0x0034
#define VTD_FAULT_EVENT_CONTROL_REGISTER_OFFSET                             0x0038
#define VTD_FAULT_EVENT_DATA_REGISTER_OFFSET                                0x003C
#define VTD_FAULT_EVENT_ADDRESS_REGISTER_OFFSET                             0x0040
#define VTD_FAULT_EVENT_ADDRESS_HIGH_REGISTER_OFFSET                        0x0044
#define VTD_ADVANCED_FAULT_LOG_REGISTER_OFFSET                              0x0058
#define VTD_PROTECTED_MEMORY_ENABLE_REGISTER_OFFSET                         0x0064
#define VTD_PROTECTED_LOW_MEMORY_BASE_REGISTER_OFFSET                       0x0068
#define VTD_PROTECTED_LOW_MEMORY_LIMIT_REGISTER_OFFSET                      0x006C
#define VTD_PROTECTED_HIGH_MEMORY_BASE_REGISTER_OFFSET                      0x0070
#define VTD_PROTECTED_HIGH_MEMORY_LIMIT_REGISTER_OFFSET                     0x0078
#define VTD_INVALIDATION_QUEUE_HEAD_REGISTER_OFFSET                         0x0080
#define VTD_INVALIDATION_QUEUE_TAIL_REGISTER_OFFSET                         0x0088
#define VTD_INVALIDATION_QUEUE_ADDRESS_REGISTER_OFFSET                      0x0090
#define VTD_INVALIDATION_COMPLETION_STATUS_REGISTER_OFFSET                  0x009C
#define VTD_INVALIDATION_COMPLETION_EVENT_CONTROL_REGISTER_OFFSET           0x00A0
#define VTD_INVALIDATION_COMPLETION_EVENT_DATA_REGISTER_OFFSET              0x00A4
#define VTD_INVALIDATION_COMPLETION_EVENT_ADDRESS_REGISTER_OFFSET           0x00A8
#define VTD_INVALIDATION_COMPLETION_EVENT_ADDRESS_HIGH_REGISTER_OFFSET      0x00AC
#define VTD_INTERRUPT_REMAPPING_TABLE_ADDRESS_REGISTER_OFFSET               0x00A0

// definition for "Snoop Behavior" and "Transient Mapping" filds in VT-d page tables
#define VTD_SNPB_SNOOPED			1
#define VTD_NON_SNPB_SNOOPED		0
#define VTD_TRANSIENT_MAPPING		1
#define VTD_NON_TRANSIENT_MAPPING	0

typedef union
{
    struct
    {
        UINT32 minor:4;
        UINT32 major:4;
        UINT32 reserved:24;
    } bits;
    UINT32 uint32;
} VTD_VERSION_REGISTER;

typedef enum
{
    VTD_NUMBER_OF_SUPPORTED_DOMAINS_16 = 0,
    VTD_NUMBER_OF_SUPPORTED_DOMAINS_64,
    VTD_NUMBER_OF_SUPPORTED_DOMAINS_256,
    VTD_NUMBER_OF_SUPPORTED_DOMAINS_1024,
    VTD_NUMBER_OF_SUPPORTED_DOMAINS_4K,
    VTD_NUMBER_OF_SUPPORTED_DOMAINS_16K,
    VTD_NUMBER_OF_SUPPORTED_DOMAINS_64K
} VTD_NUMBER_OF_SUPPORTED_DOMAINS;

#define VTD_SUPER_PAGE_SUPPORT_21(sp_support)           ((sp_support) & 0x0001)
#define VTD_SUPER_PAGE_SUPPORT_30(sp_support)           ((sp_support) & 0x0010)
#define VTD_SUPER_PAGE_SUPPORT_39(sp_support)           ((sp_support) & 0x0100)
#define VTD_SUPER_PAGE_SUPPORT_48(sp_support)           ((sp_support) & 0x1000)

typedef union
{
    struct
    {
        UINT32
            number_of_domains:3,
            advanced_fault_log:1,
            required_write_buffer_flush:1,
            protected_low_memory_region:1,   // 0 = not supported, 1 = supported
            protected_high_memory_region:1,  // 0 = not supported, 1 = supported
            caching_mode:1,
            adjusted_guest_address_width:5,
            reserved0:3,
            max_guest_address_width:6,
            zero_length_read:1,
            isochrony:1,
            fault_recording_register_offset_low:8;
        UINT32
            fault_recording_register_offset_high:2,
            super_page_support:4,
            reserved1:1,
            page_selective_invalidation:1, // 0 = not supported (only global and domain), 1 = supported
            number_of_fault_recording_registers:8,
            max_address_mask_value:6,
            dma_write_draining:1, // 0 = not supported, 1 = supported
            dma_read_draining:1, // 0 = not supported, 1 = supported
            reserved2:8;
    } bits;
    UINT64 uint64;
} VTD_CAPABILITY_REGISTER;

typedef union
{
    struct
    {
        UINT32
            coherency:1, // 0 = not-snooped, 1 = snooped
            queued_invalidation:1, // 0 = not-supported, 1 = supported
            device_iotlb:1,
            interrupt_remapping:1,
            extended_interrupt_mode:1, // 0 = 8-bit APIC id, 1 = 16-bit (x2APIC)
            caching_hints:1,
            pass_through:1,
            snoop_control:1,
            iotlb_register_offset:10,
            reserved0:2,
            max_handle_mask_value:4,
            reserved1:8;
        UINT32 reserved2;
    } bits;
    UINT64 uint64;
} VTD_EXTENDED_CAPABILITY_REGISTER;

typedef union
{
    struct
    {
        UINT32 reserved0:23;
        UINT32 compatibility_format_interrupt:1; // 0 = block; 1 = pass-through
        UINT32 set_interrupt_remap_table_ptr:1;
        UINT32 interrupt_remap_enable:1;
        UINT32 queued_invalidation_enable:1;
        UINT32 write_buffer_flush:1;
        UINT32 advanced_fault_log_enable:1;
        UINT32 set_advanced_fault_log_ptr:1;
        UINT32 set_root_table_ptr:1;
        UINT32 translation_enable:1;
    } bits;
    UINT32 uint32;
} VTD_GLOBAL_COMMAND_REGISTER;

typedef union
{
    struct
    {
        UINT32 reserved0:23;
        UINT32 compatibility_format_interrupt_status:1;
        UINT32 interrupt_remap_table_ptr_status:1;
        UINT32 interrupt_remap_enable_status:1;
        UINT32 queued_invalidation_enable_status:1;
        UINT32 write_buffer_flush_status:1;
        UINT32 advanced_fault_log_enable_status:1;
        UINT32 advanced_fault_log_ptr_status:1;
        UINT32 root_table_ptr_status:1;
        UINT32 translation_enable_status:1;
    } bits;
    UINT32 uint32;
} VTD_GLOBAL_STATUS_REGISTER;

typedef union
{
    struct
    {
        UINT32
            reserved:12,
            address_low:20;
        UINT32 address_high;
    } bits;
    UINT64 uint64;
} VTD_ROOT_ENTRY_TABLE_ADDRESS_REGISTER;

typedef enum
{
    VTD_CONTEXT_INV_GRANULARITY_GLOBAL = 0x1,
    VTD_CONTEXT_INV_GRANULARITY_DOMAIN = 0x2,
    VTD_CONTEXT_INV_GRANULARITY_DEVICE = 0x3
} VTD_CONTEXT_INV_GRANULARITY;

typedef union
{
    struct
    {
        UINT32
            domain_id:16,
            source_id:16;
        UINT32
            function_mask:2,
            reserved:25,
            context_actual_invld_granularity:2,
            context_invld_request_granularity:2,
            invalidate_context_cache:1;
    } bits;
    UINT64 uint64;
} VTD_CONTEXT_COMMAND_REGISTER;

typedef enum
{
    VTD_IOTLB_INV_GRANULARITY_GLOBAL = 0x1,
    VTD_IOTLB_INV_GRANULARITY_DOMAIN = 0x2,
    VTD_IOTLB_INV_GRANULARITY_PAGE = 0x3
} VTD_IOTLB_INV_GRANULARITY;

typedef union
{
    struct
    {
        UINT32 reserved0;
        UINT32 domain_id:16,
               drain_writes:1,
               drain_reads:1,
               reserved1:7,
               iotlb_actual_invld_granularity:3,
               iotlb_invld_request_granularity:3,
               invalidate_iotlb:1;
    } bits;
    UINT64 uint64;
} VTD_IOTLB_INVALIDATE_REGISTER;

typedef union
{
    struct
    {
        UINT32
            address_mask:6,
            invalidation_hint:1,
            reserved:5,
            address_low:20;
        UINT32 address_high;
    } bits;
    UINT64 uint64;
} VTD_INVALIDATE_ADDRESS_REGISTER;

typedef union
{
    struct
    {
        UINT32 fault_overflow:1;
        UINT32 primary_pending_fault:1;
        UINT32 advanced_fault_overflow:1;
        UINT32 advanced_pending_fault:1;
        UINT32 invalidation_queue_error:1;
        UINT32 invalidation_completion_error:1;
        UINT32 invalidation_timeout_error:1;
        UINT32 reserved0:1;
        UINT32 fault_record_index:8;
        UINT32 reserved1:16;
    } bits;
    UINT32 uint32;
} VTD_FAULT_STATUS_REGISTER;

typedef union
{
    struct
    {
        UINT32 reserved:30;
        UINT32 interrupt_pending:1;
        UINT32 interrupt_mask:1;
    } bits;
    UINT32 uint32;
} VTD_FAULT_EVENT_CONTROL_REGISTER;

typedef union
{
    struct
    {
        UINT32 vector:8;
        UINT32 delivery_mode:3; // 0 = fixed; 1=lowest priority
        UINT32 reserved:3;
        UINT32 trigger_mode_level:1;
        UINT32 trigger_mode:1;
        UINT32 reserved1:18;
    } bits;
    UINT32 uint32;
} VTD_FAULT_EVENT_DATA_REGISTER;

typedef union
{
    struct
    {
        UINT32 reserved0:2;
        UINT32 destination_mode:1;
        UINT32 redirection_hint:1;
        UINT32 reserved1:8;
        UINT32 destination_id:8;
        UINT32 reserved2:12; // reserved to 0xfee
    } bits;
    UINT32 uint32;
} VTD_FAULT_EVENT_ADDRESS_REGISTER;

typedef struct
{
    UINT32 reserved;
} VTD_FAULT_EVENT_UPPER_ADDRESS_REGISTER;

typedef union
{
    struct
    {
        UINT32
            reserved:12,
            fault_info_low:20;
        UINT32 fault_info_high;
    } bits;
    UINT64 uint64;
} VTD_FAULT_RECORDING_REGISTER_LOW;

typedef union
{
    struct
    {
        UINT32
            source_id:16,
            reserved0:16;
        UINT32
            fault_reason:8,
            reserved1:20,
            address_type:2,
            request_type:1, // 0 = write; 1 = read
            fault:1;
    } bits;
    UINT64 uint64;
} VTD_FAULT_RECORDING_REGISTER_HIGH;

typedef struct
{
    VTD_FAULT_RECORDING_REGISTER_LOW low;
    VTD_FAULT_RECORDING_REGISTER_HIGH high;
} VTD_FAULT_RECORDING_REGISTER;

typedef union
{
    struct
    {
        UINT32
            reserved:9,
            fault_log_size:3,
            fault_log_address_low:20;
        UINT32 fault_log_address_high;
    } bits;
    UINT64 uint64;
} VTD_ADVANCED_FAULT_LOG_REGISTER;

typedef union
{
    struct
    {
        UINT32 protected_region_status:1;
        UINT32 reserved_p:30;
        UINT32 enable_protected_memory:1;
    } bits;
    UINT32 uint32;
} VTD_PROTECTED_MEMORY_ENABLE_REGISTER;

typedef union
{
    struct
    {
        UINT32
            reserved0:4,
            queue_head:15, // 128-bit aligned
            reserved1:13;
        UINT32 reserved2;
    } bits;
    UINT64 uint64;
} VTD_INVALIDATION_QUEUE_HEAD_REGISTER;

typedef union
{
    struct
    {
        UINT32
            reserved0:4,
            queue_tail:15, // 128-bit aligned
            reserved1:13;
        UINT32 reserved2;
    } bits;
    UINT64 uint64;
} VTD_INVALIDATION_QUEUE_TAIL_REGISTER;

typedef union
{
    struct
    {
        UINT32
            queue_size:3,
            reserved:9,
            queue_base_low:20;
        UINT32 queue_base_high;
    } bits;
    UINT64 uint64;
} VTD_INVALIDATION_QUEUE_ADDRESS_REGISTER;

typedef union
{
    struct
    {
        UINT32 wait_descriptor_complete:1;
        UINT32 reserved:31;
    } bits;
    UINT32 uint32;
} VTD_INVALIDATION_COMPLETION_STATUS_REGISTER;

typedef union
{
    struct
    {
        UINT32 reserved:30;
        UINT32 interrupt_pending:1;
        UINT32 interrupt_mask:1;
    } bits;
    UINT32 uint32;
} VTD_INVALIDATION_EVENT_CONTROL_REGISTER;

typedef union
{
    struct
    {
        UINT32 interrupt_message_data:16;
        UINT32 extended_interrupt_message_data:16;
    } bits;
    UINT32 uint32;
} VTD_INVALIDATION_EVENT_DATA_REGISTER;

typedef union
{
    struct
    {
        UINT32 reserved:2;
        UINT32 message_address:30;
    } bits;
    UINT32 uint32;
} VTD_INVALIDATION_EVENT_ADDRESS_REGISTER;

typedef struct
{
    UINT32 message_upper_address;
} VTD_INVALIDATION_EVENT_UPPER_ADDRESS_REGISTER;

typedef union
{
    struct
    {
        UINT32
            size:4,
            reserved:7,
            extended_interrupt_mode_enable:1,
            address_low:20;
        UINT32 address_high;
    } bits;
    UINT64 uint64;
} VTD_INTERRUPT_REMAPPING_TABLE_ADDRESS_REGISTER;

#pragma warning(pop)

typedef enum
{
    VTD_POWER_ACTIVE,
    VTD_POWER_SUSPEND,
    VTD_POWER_RESUME
} VTD_POWER_STATE;

typedef struct _VTD_DMA_REMAPPING_HW_UNIT
{
    UINT32                             id;
    VTD_DOMAIN_ID                      avail_domain_id;
    LIST_ELEMENT                       domain_list;
    UINT64                             register_base;
    UINT32                             num_devices;
    VMM_LOCK                           hw_lock;
    VTD_POWER_STATE                    power_state;
    VTD_CAPABILITY_REGISTER            capability;
    VTD_EXTENDED_CAPABILITY_REGISTER   extended_capability;
    DMAR_DEVICE                       *devices;
    DMA_REMAPPING_ROOT_ENTRY          *root_entry_table;
} VTD_DMA_REMAPPING_HW_UNIT;

BOOLEAN vtd_hw_set_root_entry_table(VTD_DMA_REMAPPING_HW_UNIT *dmar, DMA_REMAPPING_ROOT_ENTRY *root_entry_table);

BOOLEAN vtd_hw_enable_translation(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_hw_disable_translation(VTD_DMA_REMAPPING_HW_UNIT *dmar);

BOOLEAN vtd_hw_enable_interrupt_remapping(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_hw_disable_interrupt_remapping(VTD_DMA_REMAPPING_HW_UNIT *dmar);

void vtd_hw_inv_context_cache_global(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_hw_flush_write_buffers(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_hw_inv_iotlb_global(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_hw_inv_iotlb_page(VTD_DMA_REMAPPING_HW_UNIT *dmar,
                           ADDRESS addr,
                           size_t size,
                           VTD_DOMAIN_ID domain_id);

UINT32 vtd_hw_get_protected_low_memory_base_alignment(VTD_DMA_REMAPPING_HW_UNIT *dmar);
UINT32 vtd_hw_get_protected_low_memory_limit_alignment(VTD_DMA_REMAPPING_HW_UNIT *dmar);
UINT64 vtd_hw_get_protected_high_memory_base_alignment(VTD_DMA_REMAPPING_HW_UNIT *dmar);
UINT64 vtd_hw_get_protected_high_memory_limit_alignment(VTD_DMA_REMAPPING_HW_UNIT *dmar);
BOOLEAN vtd_hw_setup_protected_low_memory(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT32 base, UINT32 limit);
BOOLEAN vtd_hw_setup_protected_high_memory(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT64 base, UINT64 limit);
BOOLEAN vtd_hw_enable_protected_memory(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_hw_disable_protected_memory(VTD_DMA_REMAPPING_HW_UNIT *dmar);
BOOLEAN vtd_hw_is_protected_memory_enabled(VTD_DMA_REMAPPING_HW_UNIT *dmar);

// hw read/write
UINT32 vtd_hw_read_reg32(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT64 reg);
void vtd_hw_write_reg32(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT64 reg, UINT32 value);

UINT64 vtd_hw_read_reg64(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT64 reg);
void vtd_hw_write_reg64(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT64 reg, UINT64 value);

// capabilities
INLINE
UINT32 vtd_hw_get_super_page_support(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.super_page_support;
}

INLINE
UINT32 vtd_hw_get_supported_ajusted_guest_address_width(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.adjusted_guest_address_width;
}

INLINE
UINT32 vtd_hw_get_max_guest_address_width(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.max_guest_address_width;
}

INLINE
UINT32 vtd_hw_get_number_of_domains(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.number_of_domains;
}

INLINE
UINT32 vtd_hw_get_caching_mode(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.caching_mode;
}

INLINE
UINT32 vtd_hw_get_required_write_buffer_flush(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.required_write_buffer_flush;
}

INLINE
UINT32 vtd_hw_get_coherency(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->extended_capability.bits.coherency;
}

INLINE
UINT32 vtd_hw_get_protected_low_memory_support(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.protected_low_memory_region;
}

INLINE
UINT32 vtd_hw_get_protected_high_memory_support(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.protected_high_memory_region;
}

// fault handling
INLINE
UINT32 vtd_hw_get_number_of_fault_recording_regs(VTD_DMA_REMAPPING_HW_UNIT *dmar)
{
    return (UINT32) dmar->capability.bits.number_of_fault_recording_registers;
}

INLINE
UINT64 vtd_hw_get_fault_recording_reg_offset(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT32 fault_record_index)
{
	UINT32 fault_recording_register_offset =
        dmar->capability.bits.fault_recording_register_offset_high << 8 |
        dmar->capability.bits.fault_recording_register_offset_low;
    return  (16 * fault_recording_register_offset)
            + (sizeof(VTD_FAULT_RECORDING_REGISTER) * fault_record_index);
}

void vtd_hw_mask_fault_interrupt(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_hw_unmask_fault_interrupt(VTD_DMA_REMAPPING_HW_UNIT *dmar);

UINT32 vtd_hw_get_fault_overflow(VTD_DMA_REMAPPING_HW_UNIT *dmar);
UINT32 vtd_hw_get_primary_fault_pending(VTD_DMA_REMAPPING_HW_UNIT *dmar);
UINT32 vtd_hw_get_fault_record_index(VTD_DMA_REMAPPING_HW_UNIT *dmar);

void vtd_hw_set_fault_event_data(VTD_DMA_REMAPPING_HW_UNIT *dmar,
                                 UINT8 vector,
                                 UINT8 delivery_mode,
                                 UINT32 trigger_mode_level,
                                 UINT32 trigger_mode);

void vtd_hw_set_fault_event_addr(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT8 dest_mode, UINT8 dest_id);
void vtd_hw_clear_fault_overflow(VTD_DMA_REMAPPING_HW_UNIT *dmar);
UINT64 vtd_hw_read_fault_register(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT32 fault_record_index);
UINT64 vtd_hw_read_fault_register_high(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT32 fault_record_index);
void vtd_hw_clear_fault_register(VTD_DMA_REMAPPING_HW_UNIT *dmar, UINT32 fault_record_index);

void vtd_hw_print_capabilities(VTD_DMA_REMAPPING_HW_UNIT *dmar);
void vtd_print_hw_status(VTD_DMA_REMAPPING_HW_UNIT *dmar);

#endif
