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

#ifndef _GUEST_PCI_CONFIG_H
#define _GUEST_PCI_CONFIG_H

#include "list.h"
#include "host_pci_configuration.h"
#include "vmm_objects.h"

struct _GUEST_PCI_DEVICE;

typedef void (*GUEST_PCI_READ_HANDLER) (
    GUEST_CPU_HANDLE  gcpu,
    struct _GUEST_PCI_DEVICE *pci_device,
    UINT32 port_id,
    UINT32 port_size,
    void   *value);

typedef void (*GUEST_PCI_WRITE_HANDLER) (
    GUEST_CPU_HANDLE  gcpu,
    struct _GUEST_PCI_DEVICE *pci_device,
    UINT32 port_id,
    UINT32 port_size,
    void   *value);

typedef struct _GPCI_GUEST_PROFILE
{
    GUEST_PCI_READ_HANDLER pci_read;
    GUEST_PCI_WRITE_HANDLER pci_write;
} GPCI_GUEST_PROFILE;


typedef enum
{
    GUEST_DEVICE_VIRTUALIZATION_DIRECT_ASSIGNMENT,    
    GUEST_DEVICE_VIRTUALIZATION_HIDDEN    
} GUEST_DEVICE_VIRTUALIZATION_TYPE;

typedef struct _GUEST_PCI_DEVICE
{
    GUEST_ID                 guest_id;
    char                     padding[2];
    GUEST_DEVICE_VIRTUALIZATION_TYPE type;
    HOST_PCI_DEVICE         *host_device;
    GUEST_PCI_READ_HANDLER   pci_read;
    GUEST_PCI_WRITE_HANDLER  pci_write;
    UINT8                   *config_space;
} GUEST_PCI_DEVICE;

typedef struct _GUEST_PCI_DEVICES
{
    GUEST_ID guest_id;
    char padding[2];
    UINT32 num_devices;
    GUEST_PCI_DEVICE devices[PCI_MAX_NUM_SUPPORTED_DEVICES + 1]; 
    PCI_DEV_INDEX device_lookup_table[PCI_MAX_NUM_FUNCTIONS]; // index 0 is reserved to mark "not-present" device
    LIST_ELEMENT guests[1];
    PCI_CONFIG_ADDRESS *gcpu_pci_access_address;
} GUEST_PCI_DEVICES;

BOOLEAN gpci_initialize(void);

BOOLEAN gpci_guest_initialize(GUEST_ID guest_id);

BOOLEAN gpci_register_device(GUEST_ID                      guest_id,
                             GUEST_DEVICE_VIRTUALIZATION_TYPE type,                     
                             HOST_PCI_DEVICE               *host_pci_device,
                             UINT8*                        config_space,
                             GUEST_PCI_READ_HANDLER        pci_read,
                             GUEST_PCI_WRITE_HANDLER       pci_write);

#ifdef INCLUDE_UNUSED_CODE
void gpci_unregister_device(GUEST_ID guest_id, 
                            UINT16   bus, 
                            UINT16   device, 
                            UINT16   function);
#endif

GUEST_ID gpci_get_device_guest_id(UINT16   bus, 
                                  UINT16   device, 
                                  UINT16   function);

#endif
