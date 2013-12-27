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

#ifndef _VTD_ACPI_DMAR_H
#define _VTD_ACPI_DMAR_H

#include "vmm_defs.h"
#include "pci_configuration.h"
#include "list.h"

typedef PCI_DEVICE_ADDRESS SOURCE_ID;
typedef struct _DMAR_DEVICE DMAR_DEVICE;

typedef struct _DMAR_HW_UNIT
{
    LIST_ELEMENT            list;
    UINT32                  id;
    BOOLEAN                 include_all;
    UINT16                  segment;
    char                    padding0[6];
    UINT64                  register_base;
    UINT16                  num_devices;
    char                    padding1[6];
    DMAR_DEVICE             *devices;
} DMAR_HW_UNIT;

typedef struct _DMAR_RESERVED_MEMORY
{
    LIST_ELEMENT            list;
    UINT16                  segment;
    char                    padding0[6];
    UINT64                  base;
    UINT64                  limit;
    UINT16                  num_devices;
    char                    padding1[6];
    DMAR_DEVICE             *devices;
} DMAR_RESERVED_MEMORY;

typedef struct _DMAR_ADDR_TRANSLATION_SERVICE
{
    LIST_ELEMENT            list;
    UINT16                  segment;
    char                    padding0[2];
    BOOLEAN                 supported_on_all_ports;
    UINT16                  num_devices;
    char                    padding1[6];
    DMAR_DEVICE             *devices;
} DMAR_ADDR_TRANSLATION_SERVICE;

typedef enum
{
    DMAR_DEVICE_PCI_DEVICE,
    DMAR_DEVICE_IOAPIC,
    DMAR_DEVICE_HPET
} DMAR_DEVICE_TYPE;

struct _DMAR_DEVICE
{
    DMAR_DEVICE_TYPE        type;
    SOURCE_ID               source_id; // pci-device or HPET
    UINT8                   ioapic_id; // valid if type == IOAPIC
    char                    padding0[1];
};

int vtd_acpi_dmar_init(HVA address);
void restore_dmar_table(void);

UINT32 dmar_num_dma_remapping_hw_units(void);

LIST_ELEMENT *dmar_get_dmar_unit_definitions(void);
LIST_ELEMENT *dmar_get_reserved_memory_regions(void);

BOOLEAN rmrr_contains_device(DMAR_RESERVED_MEMORY *rmrr, UINT8 bus, UINT8 device, UINT8 function);

#endif

