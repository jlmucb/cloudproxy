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
* Copyright 2013 Intel Corporation All Rights Reserved.
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

#include "common_types.h"
#include "vmm_defs.h"
#include "vmm_arch_defs.h"
#include "vmm_startup.h"
#include "startap.h"
#include "common_libc.h"
#include "loader.h"
#include "pe_def.h"
#include "PE_loader.h"
#include "image_access_mem.h"
#include "memory.h"
#include "decompress.h"
#include "x32_gdt64.h"
#include "x32_pt64.h"
#include "x32_init64.h"
#include "evmm_desc.h"

typedef struct
{
    INIT32_STRUCT s;
    UINT32 data[32];
} INIT32_STRUCT_SAFE;


#define get_e820_table get_e820_table_from_multiboot
//#define get_e820_table get_e820_table_from_sfi
//#define get_e820_table copy_e820_table_from_efi

/////////////////////////////////////////////////////////////////////////////

static int decompress(void *inb, UINT32 insize, void **outb)
{
    UINT32 r;
    UINT32 outsize;

    r = Decompress_GetInfo(inb, insize, &outsize);

    if (r == UNEXPECTED_ERROR)
        return -1;

    *outb = AllocateMemory(outsize);

    if (*outb == NULL)
        return -1;

    r = Decompress_Decompress(inb, insize, *outb, outsize);

    if (r == UNEXPECTED_ERROR)
        return -1;

    return 0;
}

/////////////////////////////////////////////////////////////////////////////

static VMM_STARTUP_STRUCT
*setup_env(EVMM_DESC *td, PE_IMAGE_INFO *thunk, PE_IMAGE_INFO *evmm)
{
    static __declspec(align(8)) VMM_STARTUP_STRUCT env;
    static __declspec(align(8)) VMM_GUEST_STARTUP g0;
    VMM_MEMORY_LAYOUT *vmem;

    memcpy(
        &g0,
        (void *)((UINT32)td + td->guest1_start * 512),
        sizeof(g0)
        );

    g0.cpu_states_array = STATES0_BASE(td);
    g0.cpu_states_count = 1;
    g0.devices_array    = 0;

    memcpy(
        (void *)&env,
        (void *)((UINT32)td + td->startup_start * 512),
        sizeof(env)
        );

    env.primary_guest_startup_state = (UINT64)(UINT32)&g0;

    vmem = env.vmm_memory_layout;
    vmem[thunk_image].base_address = THUNK_BASE(td);
    vmem[thunk_image].total_size   = THUNK_SIZE;
    vmem[thunk_image].image_size   = UVMM_PAGE_ALIGN_4K(thunk->load_size);
    vmem[uvmm_image].base_address  = EVMM_BASE(td);
    vmem[uvmm_image].total_size    = EVMM_SIZE(td);
    vmem[uvmm_image].image_size    = UVMM_PAGE_ALIGN_4K(evmm->load_size);

    return &env;
}

/////////////////////////////////////////////////////////////////////////////

void evmmh(EVMM_DESC *td)
{
    static INIT64_STRUCT init64;
    static INIT32_STRUCT_SAFE init32;

    GET_PE_IMAGE_INFO_STATUS pe_ok;
    PE_IMAGE_INFO thunk_hdr;
    PE_IMAGE_INFO evmm_hdr;

    VMM_STARTUP_STRUCT *vmm_env;
    STARTAP_IMAGE_ENTRY_POINT call_thunk_entry;
	UINT64 call_thunk;
    UINT64 call_evmm;

    UINT32 heap_base;
    UINT32 heap_size;

    UINT64 e820_addr;
    void *p_evmm;
    void *p_low_mem = (void*)0x8000; // find 20 KB below 640 K

    int info[4] = {0, 0, 0, 0};
    int num_of_aps;
    BOOLEAN ok;
    int r;
    int i;

    // (1) Init loader heap, run-time space, and idt.

    heap_base = HEAP_BASE(td);
    heap_size = HEAP_SIZE;

    InitializeMemoryManager((UINT64 *)&heap_base, (UINT64 *)&heap_size);
    SetupIDT();

    // (2) Build E820 table.

    if (get_e820_table(td, &e820_addr) != 0)
        return;

    // (3) Read evmm and thunk header.

    r = decompress(
            (void *)((UINT32)td + td->evmm_start * 512),
            td->evmm_count * 512,
            &p_evmm
            );

    if (r != 0)
        return;

    pe_ok = get_PE_image_info(p_evmm, &evmm_hdr);

    if ((pe_ok != GET_PE_IMAGE_INFO_OK) ||
        (evmm_hdr.machine_type != PE_IMAGE_MACHINE_EM64T) ||
        (evmm_hdr.load_size == 0))
        return;

    pe_ok = get_PE_image_info(
        (void*)((UINT32)td + td->startap_start * 512),
        &thunk_hdr
        );

    if ((pe_ok != GET_PE_IMAGE_INFO_OK) ||
        (thunk_hdr.machine_type != PE_IMAGE_MACHINE_X86) ||
        (thunk_hdr.load_size == 0))
        return;

    // (4) Load evmm, thunk, and tee.

    ok = load_PE_image(
            p_evmm,
            (void *)EVMM_BASE(td),
            EVMM_SIZE(td),
            &call_evmm
            );

    if (!ok)
        return;

    ok = load_PE_image(
            (void *)((UINT32)td + td->startap_start * 512),
            (void *)THUNK_BASE(td),
            THUNK_SIZE,
            (UINT64 *)&call_thunk
            );

    if (!ok)
        return;


    vmm_env = setup_env(td, &thunk_hdr, &evmm_hdr);
    vmm_env->physical_memory_layout_E820 = e820_addr;

    // (5) Setup init32.

    __cpuid(info, 1);
    num_of_aps = ((info[1] >> 16) & 0xff) - 1;

    if (num_of_aps < 0)
        num_of_aps = 0;

    init32.s.i32_low_memory_page = (UINT32)p_low_mem;
    init32.s.i32_num_of_aps = num_of_aps;

    for (i = 0; i < num_of_aps; i ++)
    {
        UINT8 *buf = vmm_page_alloc(2);

        if (buf == NULL)
            return;

        init32.s.i32_esp[i] = (UINT32)&buf[PAGE_4KB_SIZE * 2];
    }

    // (6) Setup init64.

    x32_gdt64_setup();
    x32_gdt64_get_gdtr(&init64.i64_gdtr);
    x32_pt64_setup_paging(((UINT64)1024 * 4) * 0x100000);
    init64.i64_cr3 = x32_pt64_get_cr3();
    init64.i64_cs = x32_gdt64_get_cs();
    init64.i64_efer = 0;

    // (7) Call thunk.

	call_thunk_entry = (STARTAP_IMAGE_ENTRY_POINT)call_thunk;
    call_thunk_entry(
        (num_of_aps != 0) ? &init32.s : 0,
        &init64,
        vmm_env,
        (UINT32)call_evmm
        );

    while (1)
        ;
}

// End of file
