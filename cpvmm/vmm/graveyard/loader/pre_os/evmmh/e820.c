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

#include "vmm_defs.h"
#include "vmm_arch_defs.h"
#include "vmm_startup.h"
#include "evmm_desc.h"

typedef struct
{
    UINT32 flags;
    UINT32 mem_low;
    UINT32 mem_high;
    UINT32 boot_dev;
    UINT32 cmdline;
    UINT32 mods_count;
    UINT32 mods_addr;
    UINT32 symbols[4];
    UINT32 mmap_len;
    UINT32 mmap_addr;
    UINT32 drv_len;
    UINT32 drv_addr;
    UINT32 config;
    UINT32 loader_name;
    UINT32 apm_table;
    UINT32 videos[6];
} mb_info;

#pragma pack(1)
typedef struct
{
    UINT32 size;
    UINT64 addr;
    UINT64 len;
    UINT32 type;
} mb_map;
#pragma pack()

#pragma pack(1)
typedef struct {
  UINT32 type;
  UINT64 paddr;
  UINT64 vaddr;
  UINT64 pages;
  UINT64 attr;
} sfi_mem_dsc;

typedef struct {
    UINT32 sig;
    UINT32 len;
    UINT8 rev;
    UINT8 cksum;
    UINT8 oem_id[6];
    UINT64 oem_tab_id;
} sfi_header;
#pragma pack()

/////////////////////////////////////////////////////////////////////////////

int get_e820_table_from_multiboot(EVMM_DESC *td, UINT64 *e820_addr)
{
    VMM_GUEST_CPU_STARTUP_STATE *s;
    INT15_E820_MEMORY_MAP *e820;
    UINT32 start;
    UINT32 next;
    UINT32 end;
    mb_info *inf;
    int i;

    s = (VMM_GUEST_CPU_STARTUP_STATE *)STATES0_BASE(td);
    inf = (mb_info *)(s->gp.reg[IA32_REG_RBX]);

    if (((inf->flags & 0x00000003) == 0) || (inf->mmap_len > 4096)) 
        return -1;

    e820 = (INT15_E820_MEMORY_MAP *)vmm_page_alloc(1);

    if (e820 == NULL)
        return -1;

    start = inf->mmap_addr;
    end = inf->mmap_addr + inf->mmap_len;
    i = 0;

    for (next = start; next < end; next += ((mb_map *)next)->size + 4)
    {
        mb_map *map = (mb_map *)next;
        e820->memory_map_entry[i].basic_entry.base_address = map->addr;
        e820->memory_map_entry[i].basic_entry.length = map->len;
        e820->memory_map_entry[i].basic_entry.address_range_type = map->type;
        e820->memory_map_entry[i].extended_attributes.uint32 = 1;
        i ++;
    }

    e820->memory_map_size = i * sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
    *e820_addr = (UINT64)(UINT32)e820;
    return 0;
}

/////////////////////////////////////////////////////////////////////////////

int copy_e820_table_from_efi(EVMM_DESC *td, UINT64 *e820_addr)
{
    VMM_GUEST_CPU_STARTUP_STATE *s;
    INT15_E820_MEMORY_MAP *e820;
    void *inf;

    s = (VMM_GUEST_CPU_STARTUP_STATE *)STATES0_BASE(td);
    inf = (void *)(s->gp.reg[IA32_REG_RBX]);

    e820 = (INT15_E820_MEMORY_MAP *)vmm_page_alloc(1);

    if (e820 == NULL)
        return -1;

    memcpy(e820, inf, 4096);
    *e820_addr = (UINT64)(UINT32)e820;

    return 0;
}

/////////////////////////////////////////////////////////////////////////////

// Find sfi table between 'start' and 'end' with signature 'sig.'
// Searching is done for every 'step' bytes.

static int find_sfi_table(
    UINT32 start, UINT32 end, UINT32 step, UINT32 table_level, UINT32 sig,
    UINT32 *table, UINT32 *size
)
{
    UINT32 addr;

    for (addr = start; addr <= end; addr += step)
    {
        sfi_header *hdr;

        hdr = (table_level == 0) ?
            (sfi_header *)addr : *((sfi_header **)addr);

        if ((hdr != 0) && (hdr->sig == sig))
        {
//            UINT32 sum = 0;
//            int i;

//            for (i = 0; i < hdr->len; i +=4)
//                sum += ((UINT32 *)hdr)[i];

//            if (sum != 0)
//                return -1;

            *table = (UINT32)(hdr + 1);
            *size = (hdr->len - sizeof(*hdr));
            return 0;
        }
    }

    return -1;
}

/////////////////////////////////////////////////////////////////////////////

static INT15_E820_RANGE_TYPE sfi_e820_type(UINT32 type)
{
    switch(type)
    {
        case 1: // EfiLoaderCode:
        case 2: // EfiLoaderData:
        case 3: // EfiBootServicesCode:
        case 4: // EfiBootServicesData:
        case 5: // EfiRuntimeServicesCode:
        case 6: // EfiRuntimeServicesData:
        case 7: // EfiConventionalMemory:
            return INT15_E820_ADDRESS_RANGE_TYPE_MEMORY;

        case 9: // EfiACPIReclaimMemory:
            return INT15_E820_ADDRESS_RANGE_TYPE_ACPI;

        case 10: // EfiACPIMemoryNVS:
            return INT15_E820_ADDRESS_RANGE_TYPE_NVS;

        default:
            return INT15_E820_ADDRESS_RANGE_TYPE_RESERVED;
    }
}

/////////////////////////////////////////////////////////////////////////////

int get_e820_table_from_sfi(EVMM_DESC *td, UINT64 *e820_addr)
{
    #define SYST 0x54535953
    #define MMAP 0x50414d4d

    INT15_E820_MEMORY_MAP *e820;
    INT15_E820_MEMORY_MAP_ENTRY_EXT *blk;

    UINT32 table;
    UINT32 size;
    sfi_mem_dsc *dsc;
    int cnt;
    int r;
    int i;

    r = find_sfi_table(0xe0000, 0xfffff, 16, 0, SYST, &table, &size);

    if (r != 0)
        return -1;

    r = find_sfi_table(table, table + size - 1, 8, 1, MMAP, &table, &size);

    if (r != 0)
        return -1;

    dsc = (sfi_mem_dsc *)table;
    cnt = size / sizeof(sfi_mem_dsc);

    e820 = (INT15_E820_MEMORY_MAP *)vmm_page_alloc(1);

    if (e820 == NULL)
        return -1;

    blk = e820->memory_map_entry;

    for (i = 0; i < cnt; i ++)
    {
        blk[i].basic_entry.base_address = dsc[i].paddr;
        blk[i].basic_entry.length = dsc[i].pages * 0x1000;
        blk[i].basic_entry.address_range_type = sfi_e820_type(dsc[i].type);
        blk[i].extended_attributes.Bits.enabled = 1;
    }

    e820->memory_map_size = cnt * sizeof(*blk);
    *e820_addr = (UINT64)(UINT32)e820;
    return 0;
}

// End of file
