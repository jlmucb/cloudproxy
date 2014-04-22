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

#ifndef _PCI_CONFIGURATION_H
#define _PCI_CONFIGURATION_H

#include "vmm_defs.h"

#define PCI_CONFIG_SPACE_SIZE                   0x100

// PCI config header fileds
#define PCI_CONFIG_VENDOR_ID_OFFSET             0x00
#define PCI_CONFIG_DEVICE_ID_OFFSET             0x02
#define PCI_CONFIG_COMMAND_OFFSET               0x04
#define PCI_CONFIG_REVISION_ID_OFFSET           0x08
#define PCI_CONFIG_CLASS_CODE_OFFSET            0x09
#define PCI_CONFIG_PROGRAMMING_INTERFACE_OFFSET PCI_CONFIG_CLASS_CODE_OFFSET
#define PCI_CONFIG_SUB_CLASS_CODE_OFFSET        0x0A
#define PCI_CONFIG_BASE_CLASS_CODE_OFFSET       0x0B
#define PCI_CONFIG_CACHE_LINE_SIZE_OFFSET       0x0C
#define PCI_CONFIG_LATENCY_TIMER_OFFSET         0x0D
#define PCI_CONFIG_HEADER_TYPE_OFFSET           0x0E
#define PCI_CONFIG_BIST_OFFSET                  0x0F
#define PCI_CONFIG_BAR_OFFSET                   0x10
#define PCI_CONFIG_BAR_LAST_OFFSET          0x24
#define PCI_CONFIG_CARD_BUS_CIS_PTR_OFFSET      0x28
#define PCI_CONFIG_SUBSYSTEM_VENDOR_ID_OFFSET   0x2C
#define PCI_CONFIG_SUBSYSTEM_ID_OFFSET          0x2E
#define PCI_CONFIG_EXPANSION_ROM_BASE_OFFSET    0x30
#define PCI_CONFIG_CAPABILITIES_PTR_OFFSET      0x34
#define PCI_CONFIG_INTERRUPT_LINE_OFFSET        0x3C
#define PCI_CONFIG_INTERRUPT_PIN_OFFSET         0x3D
#define PCI_CONFIG_MIN_GNT_OFFSET               0x3E
#define PCI_CONFIG_MAX_LAT_OFFSET               0x3F

// for PCI config of type '1' (bridge)
#define PCI_CONFIG_SECONDARY_BUS_OFFSET         0x19
#define PCI_CONFIG_BRIDGE_MEMORY_BASE             0x20
#define PCI_CONFIG_BRIDGE_MEMORY_LIMIT             0x22
#define PCI_CONFIG_BRIDGE_IO_BASE_LOW             0x1C
#define PCI_CONFIG_BRIDGE_IO_LIMIT_LOW             0x1D
#define PCI_CONFIG_BRIDGE_IO_BASE_HIGH             0x30
#define PCI_CONFIG_BRIDGE_IO_LIMIT_HIGH             0x32


#define PCI_BASE_CLASS_BRIDGE                   0x06

#define PCI_CONFIG_ADDRESS_REGISTER             0xCF8
#define PCI_CONFIG_DATA_REGISTER                0xCFC

#define PCI_INVALID_VENDOR_ID                   0xFFFF
#define PCI_INVALID_DEVICE_ID                   PCI_INVALID_VENDOR_ID

#define PCI_CONFIG_HEADER_TYPE_DEVICE           0x0
#define PCI_CONFIG_HEADER_TYPE_PCI2PCI_BRIDGE   0x1
#define PCI_CONFIG_HEADER_TYPE_CARDBUS_BRIDGE   0x2

#define PCI_MAX_NUM_BUSES                       (UINT16) 256
#define PCI_MAX_NUM_DEVICES_ON_BUS              (UINT16) 32
#define PCI_MAX_NUM_FUNCTIONS_ON_DEVICE         (UINT16) 8
#define PCI_MAX_NUM_FUNCTIONS                   (PCI_MAX_NUM_BUSES * PCI_MAX_NUM_DEVICES_ON_BUS * PCI_MAX_NUM_FUNCTIONS_ON_DEVICE)

#define PCI_MAX_NUM_SUPPORTED_DEVICES           0x100
#define PCI_MAX_PATH                            16

#define PCI_IS_ADDRESS_VALID(bus, device, function) (bus < PCI_MAX_NUM_BUSES && device < PCI_MAX_NUM_DEVICES_ON_BUS && function < PCI_MAX_NUM_FUNCTIONS_ON_DEVICE)
#define PCI_GET_ADDRESS(bus, device, function)      (bus << 8 | device << 3 | function)

#define PCI_CONFIG_HEADER_BAR_MEMORY_TYPE_MASK            (UINT64) 0x1
#define PCI_CONFIG_HEADER_BAR_ADDRESS_TYPE_MASK           (UINT64) 0x6
#define PCI_CONFIG_HEADER_BAR_IO_ENCODING_MASK            (UINT64) 0x3
#define PCI_CONFIG_HEADER_BAR_MEM_ENCODING_MASK           (UINT64) 0xf
#define PCI_CONFIG_HEADER_COMMAND_IOSPACE_MASK            (UINT64) 0x1
#define PCI_CONFIG_HEADER_COMMAND_MEMORY_MASK             (UINT64) 0x2
#define PCI_CONFIG_HEADER_BAR_SIZING_COMMAND              0xFFFFFFFF
#define PCI_BAR_MMIO_REGION                               (BAR_TYPE)0
#define PCI_BAR_IO_REGION                                 (BAR_TYPE)1
#define PCI_BAR_UNUSED                                    (BAR_TYPE)-1
#define PCI_CONFIG_HEADER_BAR_ADDRESS_MASK_TYPE_MMIO      (UINT64) ~(0xf)
#define PCI_CONFIG_HEADER_BAR_ADDRESS_MASK_TYPE_IO        (UINT64) ~(0x3)
#define PCI_CONFIG_HEADER_BAR_ADDRESS_32                  0
#define PCI_CONFIG_HEADER_BAR_ADDRESS_64                  0x2

#if (PCI_MAX_NUM_SUPPORTED_DEVICES <= 0x100)
typedef UINT8 PCI_DEV_INDEX;
#elif (PCI_MAX_NUM_SUPPORTED_DEVICES <= 0x10000)
typedef UINT16 PCI_DEV_INDEX;
#else
typedef UINT32 PCI_DEV_INDEX;
#endif

#pragma warning (push)
#pragma warning (disable:4214)

#pragma PACK_ON

typedef union _PCI_CONFIG_ADDRESS
{
    struct
    {
        UINT32 
            Register:8,
            Function:3,
            Device:5,
            Bus:8,
            Reserved:7,
            Enable:1;
    } Bits;
    UINT32 Uint32;
} PCI_CONFIG_ADDRESS;

typedef UINT16 PCI_DEVICE_ADDRESS;

#define PCI_BUS_MASK                 0xff00
#define PCI_DEVICE_MASK              0x00f8
#define PCI_FUNCTION_MASK            0x0007

#define GET_PCI_BUS(addr)                       (UINT8)(BITMAP_GET((addr), PCI_BUS_MASK) >> 8)
#define GET_PCI_DEVICE(addr)                    (UINT8)(BITMAP_GET((addr), PCI_DEVICE_MASK) >> 3)
#define GET_PCI_FUNCTION(addr)                  (UINT8)(BITMAP_GET((addr), PCI_FUNCTION_MASK))

#define SET_PCI_BUS(addr, bus)                  BITMAP_ASSIGN((addr), PCI_BUS_MASK, (bus) << 8)
#define SET_PCI_DEVICE(addr, device)            BITMAP_ASSIGN((addr), PCI_DEVICE_MASK, (device) << 3)
#define SET_PCI_FUNCTION(addr, function)        BITMAP_ASSIGN((addr), PCI_FUNCTION_MASK, (function))

#pragma PACK_OFF

#pragma warning (pop)

typedef struct _PCI_PATH_ELEMENT
{
    UINT8 device;
    UINT8 function;
} PCI_PATH_ELEMENT;

typedef struct _PCI_PATH
{
    UINT8 start_bus;
    PCI_PATH_ELEMENT path[PCI_MAX_PATH];
} PCI_PATH;

#define PCI_MAX_BAR_NUMBER      6

typedef enum
{
    BAR_TYPE_IO,
    BAR_TYPE_MMIO
} BAR_TYPE;

#define PCI_MAX_BAR_NUMBER_IN_BRIDGE      2

typedef struct _PCI_BASE_ADDRESS_REGISTER
{
    BAR_TYPE type;
    char padding1[4];
    UINT64 addr;
    UINT64 length;
} PCI_BASE_ADDRESS_REGISTER;

#endif
