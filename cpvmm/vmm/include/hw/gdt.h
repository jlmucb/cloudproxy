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

#ifndef _GDT_H_
#define _GDT_H_


#define TSS_ENTRY_SIZE (sizeof(ADDRESS) * 2)
#define TSS_ENTRY_OFFSET(__cpuid) (TSS_FIRST_GDT_ENTRY_OFFSET + (__cpuid) * TSS_ENTRY_SIZE)


enum {
    NULL_GDT_ENTRY_OFFSET       = 0,
    DATA32_GDT_ENTRY_OFFSET     = 8,
    CODE32_GDT_ENTRY_OFFSET     = 0x10,
    CODE64_GDT_ENTRY_OFFSET     = 0x18,
    TSS_FIRST_GDT_ENTRY_OFFSET  = 0x20,
    CPU_LOCATOR_GDT_ENTRY_OFFSET = TSS_FIRST_GDT_ENTRY_OFFSET // this value is used in assembler.
};


void hw_gdt_setup(CPU_ID number_of_cpus);
void hw_gdt_load(CPU_ID cpu_id);
void hw_gdt_set_ist_pointer(CPU_ID cpu_id, UINT8 ist_no, ADDRESS address);
VMM_STATUS hw_gdt_parse_entry(
    IN UINT8    *p_gdt,
    IN UINT16   selector,
    OUT ADDRESS *p_base,
    OUT UINT32  *p_limit,
    OUT UINT32  *p_attributes
    );

#endif //_GDT_H_

