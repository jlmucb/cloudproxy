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

#ifndef _VTD_DOMAIN_H
#define _VTD_DOMAIN_H

#include "list.h"
#include "memory_address_mapper_api.h"
#include "vtd_acpi_dmar.h"
#include "vmm_startup.h"

typedef UINT32 VTD_DOMAIN_ID;

#define INVALID_VTD_DOMAIN_ID   ((VTD_DOMAIN_ID) -1)

typedef struct _VTD_PCI_DEVICE
{
    LIST_ELEMENT            list;    // list of devices that belong to the same domain
    SOURCE_ID               source_id;
    char                    padding[6];
} VTD_PCI_DEVICE;

typedef struct _VTD_DOMAIN
{
    VTD_DOMAIN_ID domain_id;
    UINT32 sagaw_bit_index;
    GUEST_ID guest_id;
    char padding0[6];
    MAM_HANDLE address_space;
    UINT64 address_space_root;
    LIST_ELEMENT devices;
    struct _VTD_DMA_REMAPPING_HW_UNIT *dmar;
    LIST_ELEMENT list;          // list of all existing domains
    LIST_ELEMENT dmar_list;     // list of domains in the same dmar
} VTD_DOMAIN;

VTD_DOMAIN* vtd_domain_create(MAM_HANDLE address_space, UINT32 sagaw_bit_index);
VTD_DOMAIN* vtd_domain_create_guest_domain(struct _VTD_DMA_REMAPPING_HW_UNIT *dmar, GUEST_ID gid, UINT32 sagaw_bit_index, const VMM_MEMORY_LAYOUT* vmm_memory_layout, const VMM_APPLICATION_PARAMS_STRUCT* application_params);

VTD_DOMAIN* vtd_get_domain(struct _VTD_DMA_REMAPPING_HW_UNIT *dmar, VTD_DOMAIN_ID domain_id);
LIST_ELEMENT* vtd_get_domain_list(void);

BOOLEAN vtd_domain_add_device(VTD_DOMAIN *domain, UINT8 bus, UINT8 device, UINT8 function);
void vtd_domain_remove_device(VTD_DOMAIN *domain, UINT8 bus, UINT8 device, UINT8 function);

BOOLEAN vtd_domain_add_to_dmar(VTD_DOMAIN *domain, struct _VTD_DMA_REMAPPING_HW_UNIT *dmar);

UINT64 vtd_domain_get_address_space_root(VTD_DOMAIN *domain, MAM_VTDPT_SNOOP_BEHAVIOR common_snpb, MAM_VTDPT_TRANS_MAPPING common_tm);

#endif
