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

