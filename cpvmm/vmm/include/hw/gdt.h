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

