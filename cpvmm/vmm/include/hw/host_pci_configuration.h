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

#ifndef _HOST_PCI_CONFIG_H
#define _HOST_PCI_CONFIG_H

#include "pci_configuration.h"

typedef struct _HOST_PCI_DEVICE
{
    PCI_DEVICE_ADDRESS address;
    char padding0[6];
    struct _HOST_PCI_DEVICE *parent;
    UINT8 depth;                    // number of bridges up to the device
    PCI_PATH path;                  // path to the device
    UINT16 vendor_id;
    UINT16 device_id;
    UINT8 revision_id;              // device-specific revision id chosen by vendor
    UINT8 base_class;
    UINT8 sub_class;
    UINT8 programming_interface;
    UINT8 header_type;              // =0x0 for devices, 0x1 for p2p bridge, 0x2 for cardbus bridge
    char padding1[1];
    BOOLEAN is_multifunction;
    BOOLEAN is_pci_2_pci_bridge;    // baseclass and subclass specify pci2pci bridge
    UINT8 interrupt_pin;            // interrupt pin (R/O) used by the device (INTA, INTB, INTC or INTD)
    UINT8 interrupt_line;           // interrupt line that connects to interrupt controller (0xFF - not connected)
    char padding2[2];
    PCI_BASE_ADDRESS_REGISTER bars[PCI_MAX_BAR_NUMBER];
} HOST_PCI_DEVICE;

UINT8 pci_read8(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg_id);
void pci_write8(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg_id, UINT8 value);

UINT16 pci_read16(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg_id);
void pci_write16(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg_id, UINT16 value);

UINT32 pci_read32(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg_id);
void pci_write32(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg_id, UINT32 value);

void host_pci_initialize(void);

HOST_PCI_DEVICE *get_host_pci_device(UINT8 bus, UINT8 device, UINT8 function);

BOOLEAN pci_read_secondary_bus_reg(UINT8 bus, UINT8 device, UINT8 func, OUT UINT8 *secondary_bus);

UINT32 host_pci_get_num_devices(void);

#endif
