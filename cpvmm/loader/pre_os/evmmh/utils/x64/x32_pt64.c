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
* file		: x32_pt64.c
* purpose	: Configures 4G memory space for 64-bit mode
*			: while runnning in 32-bit mode
*
*----------------------------------------------------*/

#include "vmm_defs.h"
#include "ia32_low_level.h"
#include "em64t_defs.h"
#include "x32_pt64.h"

extern void *  __cdecl vmm_memset(void *buffer, int filler, unsigned howmany);
extern void * __cdecl vmm_page_alloc(UINT32 pages);


static EM64T_CR3 cr3_for_x64 = { 0 };


/*---------------------------------------------------------*
*  FUNCTION		: x32_pt64_setup_paging
*  PURPOSE		: establish paging tables for x64 -bit mode, 2MB pages
*   		  		: while running in 32-bit mode.
*				: It should scope full 32-bit space, i.e. 4G
*  ARGUMENTS	:
*  RETURNS		: void
*---------------------------------------------------------*/
void x32_pt64_setup_paging(UINT64 memory_size)
{
	EM64T_PML4 		*pml4_table;
	EM64T_PDPE		*pdp_table;
	EM64T_PDE_2MB	*pd_table;

	UINT32 pdpt_entry_id;
	UINT32 pdt_entry_id;
	UINT32 address = 0;

	if (memory_size >= 0x100000000)
		memory_size = 0x100000000;

	/*
		To cover 4G-byte addrerss space the minimum set is
		PML4	- 1entry
		PDPT	- 4 entries
		PDT		- 2048 entries
	*/

	pml4_table = (EM64T_PML4 *) vmm_page_alloc(1);
	vmm_memset(pml4_table, 0, PAGE_4KB_SIZE);

	pdp_table = (EM64T_PDPE *) vmm_page_alloc(1);
	vmm_memset(pdp_table, 0, PAGE_4KB_SIZE);


	// only one  entry is enough in PML4 table
	pml4_table[0].lo.base_address_lo = (UINT32) pdp_table >> 12;
	pml4_table[0].lo.present	= 1;
	pml4_table[0].lo.rw			= 1;
	pml4_table[0].lo.us			= 0;
	pml4_table[0].lo.pwt 		= 0;
	pml4_table[0].lo.pcd		= 0;
	pml4_table[0].lo.accessed	= 0;
	pml4_table[0].lo.ignored 	= 0;
	pml4_table[0].lo.zeroes 	= 0;
	pml4_table[0].lo.avl		= 0;

	// 4  entries is enough in PDPT
	for (pdpt_entry_id = 0; pdpt_entry_id < 4; ++pdpt_entry_id)
	{
		pdp_table[pdpt_entry_id].lo.present	= 1;
		pdp_table[pdpt_entry_id].lo.rw 		= 1;
		pdp_table[pdpt_entry_id].lo.us 		= 0;
		pdp_table[pdpt_entry_id].lo.pwt		= 0;
		pdp_table[pdpt_entry_id].lo.pcd		= 0;
		pdp_table[pdpt_entry_id].lo.accessed= 0;
		pdp_table[pdpt_entry_id].lo.ignored	= 0;
		pdp_table[pdpt_entry_id].lo.zeroes	= 0;
		pdp_table[pdpt_entry_id].lo.avl		= 0;

		pd_table = (EM64T_PDE_2MB *) vmm_page_alloc(1);
		vmm_memset(pd_table, 0, PAGE_4KB_SIZE);
		pdp_table[pdpt_entry_id].lo.base_address_lo = (UINT32) pd_table >> 12;


		for (pdt_entry_id = 0; pdt_entry_id < 512; ++pdt_entry_id, address += PAGE_2MB_SIZE)
		{
			pd_table[pdt_entry_id].lo.present	= 1;
			pd_table[pdt_entry_id].lo.rw		= 1;
			pd_table[pdt_entry_id].lo.us		= 0;
			pd_table[pdt_entry_id].lo.pwt		= 0;
			pd_table[pdt_entry_id].lo.pcd		= 0;
			pd_table[pdt_entry_id].lo.accessed  = 0;
			pd_table[pdt_entry_id].lo.dirty		= 0;
			pd_table[pdt_entry_id].lo.pse		= 1;
			pd_table[pdt_entry_id].lo.global	= 0;
			pd_table[pdt_entry_id].lo.avl		= 0;
			pd_table[pdt_entry_id].lo.pat		= 0;	 //????
			pd_table[pdt_entry_id].lo.zeroes	= 0;
			pd_table[pdt_entry_id].lo.base_address_lo = address >> 21;
		}
	}

	cr3_for_x64.lo.pwt = 0;
	cr3_for_x64.lo.pcd = 0;
	cr3_for_x64.lo.base_address_lo = ((UINT32) pml4_table) >> 12;

}

void x32_pt64_load_cr3(void)
{
	ia32_write_cr3(*((UINT32*) &(cr3_for_x64.lo)));

}

UINT32 x32_pt64_get_cr3(void)
{
	return *((UINT32*) &(cr3_for_x64.lo));
}

