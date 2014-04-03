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

/*---------------------------------------------------*
*
* file		: x32_gdt64.c
* purpose	: copy existing 32-bit GDT and
*			: expands it with 64-bit mode entries
*
*----------------------------------------------------*/

#include "vmm_defs.h"
#include "em64t_defs.h"
#include "ia32_low_level.h"
#include "x32_gdt64.h"

extern void *  __cdecl vmm_memset(void *buffer, int filler, unsigned howmany);
extern void * __cdecl vmm_page_alloc(UINT32 pages);
extern void *  __cdecl vmm_memcpy(void *dest, const void* src, UINT32 count);

extern void ClearScreen();
extern void PrintString(UINT8* String);
extern void PrintValue(UINT32 Value);

void print_gdt(UINT32 base, UINT16 limit);


static IA32_GDTR   	gdtr_32;
static IA32_GDTR	gdtr_64;  // still in 32-bit mode
static UINT16 		cs_64;


void x32_gdt64_setup(void)
{
	EM64T_CODE_SEGMENT_DESCRIPTOR *p_gdt_64;
	UINT32 last_index;

	// allocate page for 64-bit GDT
	p_gdt_64 = vmm_page_alloc(1);	// 1 page should be sufficient ???
	vmm_memset(p_gdt_64, 0, PAGE_4KB_SIZE);


	// read 32-bit GDTR
	ia32_read_gdtr(&gdtr_32);

	// clone it to the new 64-bit GDT
	vmm_memcpy(p_gdt_64, (void *) gdtr_32.base, gdtr_32.limit+1);

	// build and append to GDT 64-bit mode code-segment entry
	// check if the last entry is zero, and if so, substitute it

	last_index = gdtr_32.limit / sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR);

	if (*(UINT64 *) &p_gdt_64[last_index] != 0)
	{
		last_index++;
	}

    // code segment for eVmm code

	p_gdt_64[last_index].hi.accessed	= 0;
	p_gdt_64[last_index].hi.readable	= 1;
	p_gdt_64[last_index].hi.conforming	= 1;
	p_gdt_64[last_index].hi.mbo_11		= 1;
	p_gdt_64[last_index].hi.mbo_12		= 1;
	p_gdt_64[last_index].hi.dpl		= 0;
	p_gdt_64[last_index].hi.present	= 1;
	p_gdt_64[last_index].hi.long_mode	= 1;	// important !!!
	p_gdt_64[last_index].hi.default_size= 0;	// important !!!
	p_gdt_64[last_index].hi.granularity= 1;

    // data segment for eVmm stacks

	p_gdt_64[last_index + 1].hi.accessed	= 0;
	p_gdt_64[last_index + 1].hi.readable	= 1;
	p_gdt_64[last_index + 1].hi.conforming	= 0;
	p_gdt_64[last_index + 1].hi.mbo_11		= 0;
	p_gdt_64[last_index + 1].hi.mbo_12		= 1;
	p_gdt_64[last_index + 1].hi.dpl		= 0;
	p_gdt_64[last_index + 1].hi.present	= 1;
	p_gdt_64[last_index + 1].hi.long_mode	= 1;	// important !!!
	p_gdt_64[last_index + 1].hi.default_size= 0;	// important !!!
	p_gdt_64[last_index + 1].hi.granularity= 1;

	// prepare GDTR
	gdtr_64.base  = (UINT32) p_gdt_64;
	gdtr_64.limit = gdtr_32.limit + sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR) * 2; // !!! TBD !!! will be extended by TSS
	cs_64 = last_index * sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR) ;
}

void x32_gdt64_load(void)
{
	// ClearScreen();
	//print_gdt(0,0);
	//PrintString("\n======================\n");

	ia32_write_gdtr(&gdtr_64);

	//print_gdt(0,0);
	//PrintString("CS_64= "); PrintValue((UINT16) cs_64); PrintString("\n");
}

UINT16 x32_gdt64_get_cs(void)
{
	return cs_64;
}

void x32_gdt64_get_gdtr(IA32_GDTR *p_gdtr)
{
    *p_gdtr = gdtr_64;
}


void print_gdt(UINT32 base, UINT16 limit)
{
	UINT32 *pTab;
	UINT16 i;
	if (0 == base)
	{
		IA32_GDTR gdtr;
		ia32_read_gdtr(&gdtr);
		base = gdtr.base;
		limit = gdtr.limit;
	}

//	PrintString("GDT BASE = "); PrintValue((UINT32) base);
//	PrintString("GDT LIMIT = "); PrintValue((UINT32) limit);
//	PrintString("\n");

	pTab = (UINT32 *) base;

	for (i = 0; i < (limit+1) / sizeof(IA32_CODE_SEGMENT_DESCRIPTOR); ++i)
	{
//		PrintValue((UINT32)i); PrintString("...."); PrintValue(pTab[i*2]); PrintString(" "); PrintValue(pTab[i*2+1]);PrintString("\n");
	}

}
