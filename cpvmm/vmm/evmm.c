/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common_types.h"
#include "vmm_defs.h"
#include "vmm_arch_defs.h"
#include "vmm_startup.h"
#include "common_libc.h"
#include "loader.h"
#include "image_access_mem.h"
typedef long long unsigned uint64_t;
typedef unsigned uint32_t;
typedef short unsigned uint16_t;
typedef unsigned char uint8_t;
typedef int bool;
#include "msr.h"
#include "multiboot.h"
#include "elf_defns.h"
#include <evmm_desc.h>
#include <vmm_startup.h>
#include "tboot.h"


multiboot_info_t *g_mbi;


void InitializeMemoryManager(UINT64 *HeapBaseAddress, UINT64 * HeapBytes)
{
}


int get_e820_table(EVMM_DESC* ed, UINT64* e820_addr)
{
    return 1;
}


void SetupIDT()
{
}

typedef void (*tboot_printk)(const char *fmt, ...);
// TODO(tmroeder): this should be the real base, but I want it to compile.
uint64_t tboot_shared_page = 0;

int evmm_main (multiboot_info_t *evmm_mbi, const void *elf_image, int size) 
{
    tboot_shared_t *shared_page = (tboot_shared_t *)(tboot_shared_page);
    tboot_printk tprintk = (tboot_printk*)(shared_page->tboot_base + 0x0d810);
    tprintk("Testing printf\n");
    //REK:
    elf_header_t *elf;
    EVMM_DESC *ed;
    UINT32 apicbase;
    VMM_STARTUP_STRUCT startup_struct __attribute__ ((aligned(8))); 
    VMM_APPLICATION_PARAMS_STRUCT application_params_struct __attribute__ ((aligned(8))); 
    VMM_GUEST_STARTUP g0 __attribute__ ((aligned(8)));
    VMM_MEMORY_LAYOUT *vmem;
    UINT32 version;
    UINT32 heap_base;
    UINT32 heap_size;
    UINT64 e820_addr;

    g_mbi = evmm_mbi;

    elf = (elf_header_t *)elf_image;
    //REK: need VMM_INPUT_PARAMS
    ed = (EVMM_DESC *)(elf_image + sizeof(EVMM_DESC));
    version = elf->e_version;
    apicbase = rdmsr(MSR_APICBASE);
    //	probably assert (apicbase & APICBASE_BSP) coz currently we handle only BSP

    apicbase = rdmsr(MSR_APICBASE);
    if (apicbase & APICBASE_BSP) {
	//THIS BSP, pass this to the evmm main
    }
    version = elf->e_version;
			
    memcpy(&g0, (void *)((UINT32)ed + ed->guest1_start * 512), sizeof(g0));
    g0.cpu_states_array = STATES0_BASE(ed);
    g0.cpu_states_count = 1;
    g0.devices_array    = 0;

    memcpy((void *)&startup_struct, (void *)((UINT32)ed + ed->startup_start * 512), 
	   sizeof(startup_struct));

    startup_struct.primary_guest_startup_state = (UINT64)(UINT32)&g0;
    vmem = startup_struct.vmm_memory_layout;

    //	REK: need to understand what guest state is needed for proper initialization.
    /*
	vmem[thunk_image].base_address = THUNK_BASE(ed);
	vmem[thunk_image].total_size   = THUNK_SIZE;
	vmem[thunk_image].image_size   = UVMM_PAGE_ALIGN_4K(thunk->load_size);
	vmem[uvmm_image].base_address  = EVMM_BASE(ed);
	vmem[uvmm_image].total_size    = EVMM_SIZE(ed);
	vmem[uvmm_image].image_size    = UVMM_PAGE_ALIGN_4K(uvmm->load_size);
    */

    heap_base = HEAP_BASE(ed);
    heap_size = HEAP_SIZE;

    InitializeMemoryManager((UINT64 *)&heap_base, (UINT64 *)&heap_size);
    SetupIDT();

    // (2) Build E820 table.

    if (get_e820_table(ed, &e820_addr) != 0)
    return;

    // r = decompress( (void *)((UINT32)ed + ed->evmm_start * 512),
    //					ed->evmm_count * 512, &p_evmm);

    vmm_bsp_proc_main(apicbase, startup_struct, application_params_struct);
}


//REK: need to add code to setup gdt, segment registers and then jump to the
//entry point.
int jump_evmm_image(void *entry_point)
{
    __asm__ __volatile__ (
      "    jmp (%%ecx);    "
      "    ud2;           "
      :: "a" (MB_MAGIC), "b" (g_mbi), "c" (entry_point));

    return 1;
}

