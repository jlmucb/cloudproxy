/*
 * File: bootstrap_entry.c
 * Description: Get tbooted and boot 64 bit evmm
 * Author: John Manferdelli
 *
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *           http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bootstrap_types.h"
#include "bootstrap_string.h"
#include "bootstrap_print.h"
#include "bootstrap_ia.h"

#include "multiboot.h"
#include "e820.h"
#include "elf64.h"
#include "linux_defns.h"
#include "elf_defns.h"
#include "tboot.h"

#include "vmm_defs.h"
#include "em64t_defs.h"
#include "ia32_defs.h"
#include "ia32_low_level.h"
#include "x32_init64.h"
#include "vmm_startup.h"


// this is all 32 bit code

#define JLMDEBUG
// Remove this soon
tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;


#define PSE_BIT     0x10
#define PAE_BIT     0x20
#define PAGE_SIZE   (1024 * 4) 
#define PAGE_MASK   (~(PAGE_SIZE-1))
#define PAGE_UP(a) ((a+(PAGE_SIZE-1))&PAGE_MASK)


// -------------------------------------------------------------------------


//   These are the variables for machine setup
//       Consult evmm-init-notes.txt

// start and end of bootstrap, no header, start is load address
extern uint32_t _start_bootstrap, _end_bootstrap;


#define EVMM_DEFAULT_START_ADDR 0x70000000 
#define LINUX_DEFAULT_LOAD_ADDRESS 0x100000
#define EVMM_HEAP_SIZE 0x100000
#define EVMM_HEAP_BASE (EVMM_DEFAULT_START_ADDR- EVMM_HEAP_SIZE)


//      Memory layout on start32_evmm entry
uint32_t bootstrap_start= 0;    // this is the bootstrap image start address
uint32_t bootstrap_end= 0;      // this is the bootstrap image end address
uint32_t evmm_start= 0;         // location of evmm start
uint32_t evmm_end= 0;           // location of evmm image start
uint32_t linux_start= 0;        // location of linux imag start
uint32_t linux_end= 0;          // location of evmm start
uint32_t initram_start= 0;      // location of initram image start
uint32_t initram_end= 0;        // location of initram image end


//      Post relocation addresses
uint32_t evmm_start_address= 0;         // this is the address of evmm after relocation (0x0e00...)
uint32_t vmm_main_entry_point= 0;       // address of vmm_main
uint32_t evmm_heap_base= 0;             // start of initial evmm heap
uint32_t evmm_heap_current= 0; 
uint32_t evmm_heap_top= 0;
uint32_t evmm_heap_size= 0;             // size of initial evmm heap
uint32_t evmm_initial_stack= 0;         // initial evmm stack
char*    evmm_command_line= NULL;       // evmm command line

//      linux guest
uint32_t linux_start_address= 0;   // this is the address of the linux protected mode image
uint32_t initram_start_address= 0; // this is the address of the initram for linux
uint32_t linux_entry_address= 0;   // this is the address of the eip in the guest
uint32_t linux_esi_register= 0;    // this is the value of the esi register on guest entry
uint32_t linux_esp_register= 0;    // this is the value of the esp on entry to the guest linux
uint32_t linux_stack_base= 0;      // this is the base of the stack on entry to linux
uint32_t linux_stack_size= 0;      // this is the size of the stack that the linux guest has
char*    linux_command_line= NULL;

// boot parameters for linux guest
uint32_t linux_original_boot_parameters= 0;
uint32_t linux_boot_params= 0;


// -------------------------------------------------------------------------


//      initial evmm heap implementation


void setup_evmm_heap(uint32_t heap_base_address, uint32_t heap_bytes)
{
    evmm_heap_current = evmm_heap_base = heap_base_address;
    evmm_heap_top = evmm_heap_base + heap_bytes;
}


void *evmm_page_alloc(uint32_t pages)
{
    uint32_t address;
    uint32_t size = pages * PAGE_SIZE;

    address = ALIGN_FORWARD(evmm_heap_current, PAGE_SIZE);
    evmm_heap_current = address + size;
    vmm_memset((void*)address, 0, size);
    return (void*)address;
}


// -------------------------------------------------------------------------


//  Machine state and mode transition data structures


#define TOTAL_MEM 0x100000000 
typedef struct {
    INIT32_STRUCT s;
    uint32_t data[32];
} INIT32_STRUCT_SAFE;


static IA32_GDTR                        gdtr_32;
static IA32_GDTR                        gdtr_64;  // still in 32-bit mode
static uint16_t                         cs_64= 0;
static uint32_t                         p_cr4= 0;

static uint64_t                         evmm_reserved = 0;
static uint32_t                         local_apic_id = 0;
static EM64T_CODE_SEGMENT_DESCRIPTOR*   p_gdt_64= NULL;
static EM64T_PML4 *                     pml4_table= NULL;
static EM64T_PDPE *                     pdp_table= NULL;
static EM64T_PDE_2MB *                  pd_table= NULL;

static INIT64_STRUCT                    init64;
static INIT64_STRUCT *                  p_init64_data = &init64;
static INIT32_STRUCT_SAFE               init32;
uint16_t                                p_cr3 = 0;

int                                     evmm_num_of_aps= 0;
uint32_t                                low_mem = 0x8000;


// -------------------------------------------------------------------------


// machine setup and paging


void  ia32_read_gdtr(IA32_GDTR *p_descriptor)
{
    asm volatile(
        "\n movl %[p_descriptor], %%edx"
        "\n\t sgdt (%%edx)"
    :[p_descriptor] "=g" (p_descriptor)
    :: "%edx");
}


void  ia32_write_gdtr(IA32_GDTR *p_descriptor)
{
    asm volatile(
        "\n movl %[p_descriptor], %%edx"
        "\n\t lgdt  (%%edx)"
    ::[p_descriptor] "g" (p_descriptor) 
    :"%edx");
}


void  ia32_write_cr3(uint32_t value)
{
    asm volatile(
        "\n movl %[value], %%eax \n\t"
        "\n\t movl %%eax, %%cr3"
    ::[value] "m" (value)
    : "%eax", "cc");
}


uint32_t  ia32_read_cr4(void)
{
    uint32_t ret;
    asm volatile(
        "\n .byte 0x0F"
        "\n\t .byte 0x20"
        "\n\t .byte 0xE0"       //mov eax, cr4
        "\n\t movl %%eax, %[ret]"
    :[ret] "=m" (ret) 
    :: "%eax");
    return ret;
}

void  ia32_write_cr4(uint32_t value)
{
    asm volatile(
        "\n movl %[value], %%eax"
        "\n\t .byte 0x0F"
        "\n\t .byte 0x22"
        "\n\t .byte 0xE0"       //mov cr4, eax
    ::[value] "m" (value)
    :"%eax");
}

void  ia32_write_msr(uint32_t msr_id, uint64_t *p_value)
{
    asm volatile(
        "\n movl %[p_value], %%ecx"
        "\n\t movl (%%ecx), %%eax"
        "\n\t movl 4(%%ecx), %%edx"
        "\n\t movl %[msr_id], %%ecx"
        "\n\t wrmsr"        //write from EDX:EAX into MSR[ECX]
    ::[msr_id] "g" (msr_id), [p_value] "p" (p_value)
    :"%eax", "%ecx", "%edx");
}

void setup_evmm_stack()
{
    EM64T_CODE_SEGMENT_DESCRIPTOR *tmp_gdt_64 = p_gdt_64;
    int i;

    // data segment for eVmm stacks
    for (i = 1; i < UVMM_DEFAULT_STACK_SIZE_PAGES+1; i++) {
        tmp_gdt_64 = p_gdt_64 + (i * PAGE_4KB_SIZE);
        (* tmp_gdt_64).hi.readable = 1;
        (* tmp_gdt_64).hi.conforming = 0;
        (* tmp_gdt_64).hi.mbo_11 = 0;
        (* tmp_gdt_64).hi.mbo_12 = 1;
        (* tmp_gdt_64).hi.dpl = 0;
        (* tmp_gdt_64).hi.present = 1;
        (* tmp_gdt_64).hi.long_mode = 1;      // important !!!
        (* tmp_gdt_64).hi.default_size= 0;    // important !!!
        (* tmp_gdt_64).hi.granularity= 1;
     }
    evmm_initial_stack = (uint32_t) p_gdt_64 + (UVMM_DEFAULT_STACK_SIZE_PAGES * PAGE_4KB_SIZE);
}


void x32_gdt64_setup(void)
{
    uint32_t last_index;
    // 1 page for code segment, and the rest for stack
    p_gdt_64 = (EM64T_CODE_SEGMENT_DESCRIPTOR *)evmm_page_alloc (1 + 
                        UVMM_DEFAULT_STACK_SIZE_PAGES);
    // zero gdt
    vmm_memset(p_gdt_64, 0, PAGE_4KB_SIZE);

    // read 32-bit GDTR
    ia32_read_gdtr(&gdtr_32);

    // clone it to the new 64-bit GDT
     vmm_memcpy(p_gdt_64, (void *) gdtr_32.base, gdtr_32.limit+1);

    // build and append to GDT 64-bit mode code-segment entry
    // check if the last entry is zero, and if so, substitute it
    last_index = gdtr_32.limit / sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR);

    if (*(uint64_t *) &p_gdt_64[last_index] != 0) {
        last_index++;
    }

    // code segment for eVmm code
    p_gdt_64[last_index].hi.accessed = 0;
    p_gdt_64[last_index].hi.readable = 1;
    p_gdt_64[last_index].hi.conforming = 1;
    p_gdt_64[last_index].hi.mbo_11 = 1;
    p_gdt_64[last_index].hi.mbo_12 = 1;
    p_gdt_64[last_index].hi.dpl = 0;
    p_gdt_64[last_index].hi.present = 1;
    p_gdt_64[last_index].hi.long_mode = 1;    // important !!!
    p_gdt_64[last_index].hi.default_size= 0;  // important !!!
    p_gdt_64[last_index].hi.granularity= 1;

    // prepare GDTR
    gdtr_64.base  = (uint32_t) p_gdt_64;
    // !!! TBD !!! will be extended by TSS
    gdtr_64.limit = gdtr_32.limit + sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR) * 2; 
    cs_64 = last_index * sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR) ;
}


void x32_gdt64_load(void)
{
    ia32_write_gdtr(&gdtr_64);
}


uint16_t x32_gdt64_get_cs(void)
{
    return cs_64;
}


void x32_gdt64_get_gdtr(IA32_GDTR *p_gdtr)
{
    *p_gdtr = gdtr_64;
}


static EM64T_CR3 cr3_for_x64 = {0};

//  x32_pt64_setup_paging: establish paging tables for x64 -bit mode, 
//     2MB pages while running in 32-bit mode.
//     It should scope full 32-bit space, i.e. 4G
void x32_pt64_setup_paging(uint64_t memory_size)
{
    uint32_t pdpt_entry_id;
    uint32_t pdt_entry_id;
    uint32_t address = 0;

    if (memory_size > TOTAL_MEM)
        memory_size = TOTAL_MEM;

    // To cover 4G-byte addrerss space the minimum set is
    // PML4    - 1entry
    // PDPT    - 4 entries
    // PDT     - 2048 entries
    pml4_table = (EM64T_PML4 *) evmm_page_alloc(1);
    vmm_memset(pml4_table, 0, PAGE_4KB_SIZE);

    pdp_table = (EM64T_PDPE *) evmm_page_alloc(1);
    vmm_memset(pdp_table, 0, PAGE_4KB_SIZE);

    // only one  entry is enough in PML4 table
    pml4_table[0].lo.base_address_lo = (uint32_t) pdp_table >> 12;
    pml4_table[0].lo.present = 1;
    pml4_table[0].lo.rw = 1;
    pml4_table[0].lo.us = 0;
    pml4_table[0].lo.pwt = 0;
    pml4_table[0].lo.pcd = 0;
    pml4_table[0].lo.accessed = 0;
    pml4_table[0].lo.ignored = 0;
    pml4_table[0].lo.zeroes = 0;
    pml4_table[0].lo.avl = 0;

    // 4  entries is enough in PDPT
    for (pdpt_entry_id = 0; pdpt_entry_id < 4; ++pdpt_entry_id) {
        pdp_table[pdpt_entry_id].lo.present = 1;
        pdp_table[pdpt_entry_id].lo.rw = 1;
        pdp_table[pdpt_entry_id].lo.us = 0;
        pdp_table[pdpt_entry_id].lo.pwt = 0;
        pdp_table[pdpt_entry_id].lo.pcd = 0;
        pdp_table[pdpt_entry_id].lo.accessed = 0;
        pdp_table[pdpt_entry_id].lo.ignored = 0;
        pdp_table[pdpt_entry_id].lo.zeroes = 0;
        pdp_table[pdpt_entry_id].lo.avl = 0;

        pd_table = (EM64T_PDE_2MB *) evmm_page_alloc(1);
        vmm_memset(pd_table, 0, PAGE_4KB_SIZE);
        pdp_table[pdpt_entry_id].lo.base_address_lo = (uint32_t) pd_table >> 12;

        for (pdt_entry_id = 0; pdt_entry_id < 512; 
                ++pdt_entry_id, address += PAGE_2MB_SIZE) {
            pd_table[pdt_entry_id].lo.present = 1;
            pd_table[pdt_entry_id].lo.rw = 1;
            pd_table[pdt_entry_id].lo.us = 0;
            pd_table[pdt_entry_id].lo.pwt = 0;
            pd_table[pdt_entry_id].lo.pcd = 0;
            pd_table[pdt_entry_id].lo.accessed  = 0;
            pd_table[pdt_entry_id].lo.dirty = 0;
            pd_table[pdt_entry_id].lo.pse = 1;
            pd_table[pdt_entry_id].lo.global = 0;
            pd_table[pdt_entry_id].lo.avl = 0;
            pd_table[pdt_entry_id].lo.pat = 0;     //????
            pd_table[pdt_entry_id].lo.zeroes = 0;
            pd_table[pdt_entry_id].lo.base_address_lo = address >> 21;
        }
    }

    cr3_for_x64.lo.pwt = 0;
    cr3_for_x64.lo.pcd = 0;
    cr3_for_x64.lo.base_address_lo = ((uint32_t) pml4_table) >> 12;
}


void x32_pt64_load_cr3(void)
{
    ia32_write_cr3(*((uint32_t*) &(cr3_for_x64.lo)));
}


uint32_t x32_pt64_get_cr3(void)
{
    return *((uint32_t*) &(cr3_for_x64.lo));
}


int setup_64bit_paging()
{

    // setup gdt for 64-bit on BSP
    x32_gdt64_setup();
    x32_gdt64_get_gdtr(&init64.i64_gdtr);
    ia32_write_gdtr(&init64.i64_gdtr);

    // setup paging, control registers and flags on BSP
    x32_pt64_setup_paging(TOTAL_MEM);
    init64.i64_cr3 = x32_pt64_get_cr3();
    ia32_write_cr3(init64.i64_cr3);
    p_cr4 = ia32_read_cr4();
    BITMAP_SET(p_cr4, PAE_BIT | PSE_BIT);
    ia32_write_cr4(p_cr4);
    ia32_write_msr(0xC0000080, &p_init64_data->i64_efer);
    init64.i64_cs = cs_64;
    init64.i64_efer = 0;

    p_cr3 = init64.i64_cr3;
    return 0;
}


// -------------------------------------------------------------------------


// mbi and e820 support


#ifdef JLMDEBUG
void PrintMbi(const multiboot_info_t *mbi)
{
    /* print mbi for debug */
    unsigned int i;

    bprint("print mbi@%p ...\n", mbi);
    bprint("\t flags: 0x%x\n", mbi->flags);
    if ( mbi->flags & MBI_MEMLIMITS )
        bprint("\t mem_lower: %uKB, mem_upper: %uKB\n", mbi->mem_lower,
               mbi->mem_upper);
    if ( mbi->flags & MBI_BOOTDEV ) {
        bprint("\t boot_device.bios_driver: 0x%x\n",
               mbi->boot_device.bios_driver);
        bprint("\t boot_device.top_level_partition: 0x%x\n",
               mbi->boot_device.top_level_partition);
        bprint("\t boot_device.sub_partition: 0x%x\n",
               mbi->boot_device.sub_partition);
        bprint("\t boot_device.third_partition: 0x%x\n",
               mbi->boot_device.third_partition);
    }
    if ( mbi->flags & MBI_CMDLINE ) {
#define CHUNK_SIZE 72 
#if 0
        /* Break the command line up into 72 byte chunks */
        int   cmdlen = strlen((char*)mbi->cmdline);
        char *cmdptr = (char *)mbi->cmdline;
        char  chunk[CHUNK_SIZE+1];
        bprint("\t cmdline@0x%x: ", mbi->cmdline);
        chunk[CHUNK_SIZE] = '\0';
        while (cmdlen > 0) {
            vmm_strncpy(chunk, cmdptr, CHUNK_SIZE); 
            bprint("\n\t\"%s\"", chunk);
            cmdptr += CHUNK_SIZE;
            cmdlen -= CHUNK_SIZE;
        }
#endif
        bprint("\n");
    }

    if ( mbi->flags & MBI_MODULES ) {
        bprint("\t mods_count: %u, mods_addr: 0x%x\n", mbi->mods_count,
               mbi->mods_addr);
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
            bprint("\t     %d : mod_start: 0x%x, mod_end: 0x%x\n", i,
                   p->mod_start, p->mod_end);
            bprint("\t         string (@0x%x): \"%s\"\n", p->string,
                   (char *)p->string);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        bprint("\t aout :: tabsize: 0x%x, strsize: 0x%x, addr: 0x%x\n",
               p->tabsize, p->strsize, p->addr);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        bprint("\t elf :: num: %u, size: 0x%x, addr: 0x%x, shndx: 0x%x\n",
               p->num, p->size, p->addr, p->shndx);
    }
    if ( mbi->flags & MBI_MEMMAP ) {
        memory_map_t *p;
        bprint("\t mmap_length: 0x%x, mmap_addr: 0x%x\n", mbi->mmap_length,
               mbi->mmap_addr);
        for ( p = (memory_map_t *)mbi->mmap_addr;
              (uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
              p=(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
                bprint("\t     size: 0x%x, base_addr: 0x%04x%04x, "
                   "length: 0x%04x%04x, type: %u\n", p->size,
                   p->base_addr_high, p->base_addr_low,
                   p->length_high, p->length_low, p->type);
        }
    }
    if ( mbi->flags & MBI_DRIVES ) {
        bprint("\t drives_length: %u, drives_addr: 0x%x\n", mbi->drives_length,
               mbi->drives_addr);
    }
    if ( mbi->flags & MBI_CONFIG ) {
        bprint("\t config_table: 0x%x\n", mbi->config_table);
    }
    if ( mbi->flags & MBI_BTLDNAME ) {
        bprint("\t boot_loader_name@0x%x: %s\n",
               mbi->boot_loader_name, (char *)mbi->boot_loader_name);
    }
    if ( mbi->flags & MBI_APM ) {
        bprint("\t apm_table: 0x%x\n", mbi->apm_table);
    }
    if ( mbi->flags & MBI_VBE ) {
        bprint("\t vbe_control_info: 0x%x\n"
               "\t vbe_mode_info: 0x%x\n"
               "\t vbe_mode: 0x%x\n"
               "\t vbe_interface_seg: 0x%x\n"
               "\t vbe_interface_off: 0x%x\n"
               "\t vbe_interface_len: 0x%x\n",
               mbi->vbe_control_info,
               mbi->vbe_mode_info,
               mbi->vbe_mode,
               mbi->vbe_interface_seg,
               mbi->vbe_interface_off,
               mbi->vbe_interface_len
              );
    }
}
#endif // JLMDEBUG


module_t *get_module(const multiboot_info_t *mbi, unsigned int i)
{
    if ( mbi == NULL ) {
        bprint("Error: mbi pointer is zero.\n");
        return NULL;
    }

    if ( i >= mbi->mods_count ) {
        bprint("invalid module #\n");
        return NULL;
    }

    return (module_t *)(mbi->mods_addr + i * sizeof(module_t));
}


unsigned long max(unsigned long a, unsigned long b)
{
    if(b>a)
        return b;
    return a;
}


unsigned long get_mbi_mem_end(const multiboot_info_t *mbi)
{
    unsigned long end = (unsigned long)(mbi + 1);

    if ( mbi->flags & MBI_CMDLINE )
        end = max(end, mbi->cmdline + vmm_strlen((char *)mbi->cmdline) + 1);
    if ( mbi->flags & MBI_MODULES ) {
        end = max(end, mbi->mods_addr + mbi->mods_count * sizeof(module_t));
        unsigned int i;
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = get_module(mbi, i);
            end = max(end, p->string + vmm_strlen((char *)p->string) + 1);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        end = max(end, p->addr + p->tabsize
                       + sizeof(unsigned long) + p->strsize);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        end = max(end, p->addr + p->num * p->size);
    }
    if ( mbi->flags & MBI_MEMMAP )
        end = max(end, mbi->mmap_addr + mbi->mmap_length);
    if ( mbi->flags & MBI_DRIVES )
        end = max(end, mbi->drives_addr + mbi->drives_length);
    /* mbi->config_table field should contain */
    /*  "the address of the rom configuration table returned by the */
    /*  GET CONFIGURATION bios call", so skip it */
    if ( mbi->flags & MBI_BTLDNAME )
        end = max(end, mbi->boot_loader_name
                       + vmm_strlen((char *)mbi->boot_loader_name) + 1);
    if ( mbi->flags & MBI_APM )
        end = max(end, mbi->apm_table + 20);
    if ( mbi->flags & MBI_VBE ) {
        end = max(end, mbi->vbe_control_info + 512);
        end = max(end, mbi->vbe_mode_info + 256);
    }

    return PAGE_UP(end);
}


// -------------------------------------------------------------------------


// linux guest initialization definitions and globals

typedef struct VMM_INPUT_PARAMS_S {
    uint64_t local_apic_id;
    uint64_t startup_struct;
    uint64_t guest_params_struct; // change name
} VMM_INPUT_PARAMS;


static VMM_INPUT_PARAMS                 input_params;
static VMM_INPUT_PARAMS*                pointer_to_input_params= &input_params;

VMM_GUEST_STARTUP                       evmm_g0;
VMM_MEMORY_LAYOUT *                     evmm_vmem= NULL;
VMM_APPLICATION_PARAMS_STRUCT           evmm_a0;
VMM_APPLICATION_PARAMS_STRUCT*          evmm_p_a0= &evmm_a0;

// state of primary linux guest on startup
VMM_GUEST_CPU_STARTUP_STATE             linux_state;

static VMM_STARTUP_STRUCT               startup_struct;
static VMM_STARTUP_STRUCT *             p_startup_struct = &startup_struct;

#define MAX_E820_ENTRIES PAGE_SIZE/sizeof(INT15_E820_MEMORY_MAP)
#define UUID 0x1badb002

// expanded e820 table used be evmm
static unsigned int     evmm_num_e820_entries = 0;
INT15_E820_MEMORY_MAP*  evmm_e820= NULL;                // address of expanded e820 table for evmm
uint64_t                evmm_start_of_e820_table= 0ULL; // same but 64 bits

// for linux primary guest
#define LINUX_BOOT_CS 0x10
#define LINUX_BOOT_DS 0x18

// initial GDT table for linux guest
static const uint64_t gdt_table[] __attribute__ ((aligned(16))) = {
    0,
    0,
    0x00c09b000000ffff, // cs
    0x00c093000000ffff  // ds
};

static struct __packed {
        uint16_t length;
        uint32_t table;
} linux_gdt_desc;


static const cmdline_option_t linux_cmdline_options[] = {
    { "vga", "" },
    { "mem", "" },
    { NULL, NULL }
};
static char linux_param_values[ARRAY_SIZE(linux_cmdline_options)][MAX_VALUE_LEN];


uint32_t alloc_linux_stack(uint32_t pages)
{
    if (pages > 1)
        return 0;   // error

    uint32_t address;
    uint32_t size = pages * PAGE_SIZE;

    linux_stack_base = evmm_heap_base - PAGE_SIZE;
    linux_stack_size= size;
    address = ALIGN_FORWARD(linux_stack_base, PAGE_SIZE);
    vmm_memset((void*)address, 0, size);
    return address;
}


// -------------------------------------------------------------------------


// linux guest setup


void setup_linux_stack()
{
    EM64T_CODE_SEGMENT_DESCRIPTOR *tmp_ptr = 
            (EM64T_CODE_SEGMENT_DESCRIPTOR *)alloc_linux_stack(1);
    int i;

    // data segment for guest stack
    (* tmp_ptr).hi.readable = 1;
    (* tmp_ptr).hi.conforming = 0;
    (* tmp_ptr).hi.mbo_11 = 0;
    (* tmp_ptr).hi.mbo_12 = 1;
    (* tmp_ptr).hi.dpl = 0;
    (* tmp_ptr).hi.present = 1;
    (* tmp_ptr).hi.long_mode = 1;      // important !!!
    (* tmp_ptr).hi.default_size= 0;    // important !!!
    (* tmp_ptr).hi.granularity= 1;
    linux_esp_register= ((uint32_t)tmp_ptr) + PAGE_SIZE;
}


int linux_setup(void)
{
    uint32_t i;

    setup_linux_stack();
    linux_gdt_desc.length = (uint16_t)sizeof(gdt_table)-1;
    linux_gdt_desc.table = (uint32_t)&gdt_table;
    linux_state.size_of_this_struct = sizeof(linux_state);
    linux_state.version_of_this_struct = VMM_GUEST_CPU_STARTUP_STATE_VERSION;
    linux_state.reserved_1 = 0;

    //Zero out all the registers.  Then set the ones that linux expects.
    for (i = 0; i < IA32_REG_GP_COUNT; i++) {
        linux_state.gp.reg[i] = (uint64_t) 0;
    }
    linux_state.gp.reg[IA32_REG_RIP] = (uint64_t) linux_entry_address;
    linux_state.gp.reg[IA32_REG_RSI] = (uint64_t) linux_esi_register;
    linux_state.gp.reg[IA32_REG_RSP] = (uint64_t) linux_esp_register;
    for (i = 0; i < IA32_REG_XMM_COUNT; i++) {
        linux_state.xmm.reg[i].uint64[0] = (uint64_t)0;
        linux_state.xmm.reg[i].uint64[1] = (uint64_t)0;
    }
    linux_state.msr.msr_debugctl = 0;
    linux_state.msr.msr_efer = 0;
    linux_state.msr.msr_pat = 0;
    linux_state.msr.msr_sysenter_esp = 0;
    linux_state.msr.msr_sysenter_eip = 0;
    linux_state.msr.pending_exceptions = 0;
    linux_state.msr.msr_sysenter_cs = 0;
    linux_state.msr.interruptibility_state = 0;
    linux_state.msr.activity_state = 0;
    linux_state.msr.smbase = 0;
    for (i = 0; i < IA32_CTRL_COUNT; i++) {
        linux_state.control.cr[i] = 0;
    }
    linux_state.control.gdtr.base = (uint64_t)(uint32_t)&gdt_table;
    linux_state.control.gdtr.limit = (uint64_t)(uint32_t)gdt_table + sizeof(gdt_table) -1;

    for (i = 0; i < IA32_SEG_COUNT; i++) {
        linux_state.seg.segment[i].base = 0;
        linux_state.seg.segment[i].limit = 0;
    }
    //CHECK: got the base address from tboot, not sure about the limits of these segments/attributes.
    linux_state.seg.segment[IA32_SEG_CS].base = (uint64_t) LINUX_BOOT_CS;
    linux_state.seg.segment[IA32_SEG_DS].base = (uint64_t) LINUX_BOOT_DS;
    return 0;
}


// This builds the 24 byte extended 8820 table
static uint64_t evmm_get_e820_table(const multiboot_info_t *mbi) 
{
    uint32_t entry_offset = 0;
    int i= 0;

    evmm_e820 = (INT15_E820_MEMORY_MAP *)evmm_page_alloc(1);
    if (evmm_e820 == NULL)
        return (uint64_t)-1;

    while ( entry_offset < mbi->mmap_length ) {
        memory_map_t *entry = (memory_map_t *) (mbi->mmap_addr + entry_offset);
        evmm_e820->memory_map_entry[i].basic_entry.base_address = 
                            (((uint64_t)entry->base_addr_high)<< 32) + entry->base_addr_low;
        evmm_e820->memory_map_entry[i].basic_entry.length = 
                            (((uint64_t)entry->length_high)<< 32) + entry->length_low;
        evmm_e820->memory_map_entry[i].basic_entry.address_range_type= entry->type;
            evmm_e820->memory_map_entry[i].extended_attributes.uint32 = 1;
        i++;
       entry_offset += entry->size + sizeof(entry->size);
    }
    evmm_num_e820_entries = i;

    evmm_e820->memory_map_size = i * sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
    evmm_start_of_e820_table = (uint64_t)(uint32_t)evmm_e820;

    return evmm_start_of_e820_table;
}



void linux_parse_cmdline(const char *cmdline)
{
    cmdline_parse(cmdline, linux_cmdline_options, linux_param_values);
}


int get_linux_vga(int *vid_mode)
{
    const char *vga = get_option_val(linux_cmdline_options,
                                     linux_param_values, "vga");
    if ( vga == NULL || vid_mode == NULL )
        return 1;

    if ( vmm_strcmp(vga, "normal") == 0 )
        *vid_mode = 0xFFFF;
    else if ( vmm_strcmp(vga, "ext") == 0 )
        *vid_mode = 0xFFFE;
    else if ( vmm_strcmp(vga, "ask") == 0 )
        *vid_mode = 0xFFFD;
    else
        *vid_mode = vmm_strtoul(vga, NULL, 0);
    return 0;
}


unsigned long get_bootstrap_mem_end(void)
{
    return PAGE_UP(bootstrap_end);
}


static inline bool plus_overflow_u32(uint32_t x, uint32_t y)
{
    return ((((uint32_t)(~0)) - x) < y);
}


// expand linux kernel with kernel image and initrd image 
int expand_linux_image( multiboot_info_t* mbi,
                        uint32_t linux_image, uint32_t linux_size,
                        uint32_t initrd_image, uint32_t initrd_size,
                        uint32_t* entry_point)
{
    linux_kernel_header_t *hdr;
    uint32_t real_mode_base, protected_mode_base;
    unsigned long real_mode_size, protected_mode_size;
    // Note: real_mode_size + protected_mode_size = linux_size 
    uint32_t initrd_base;
    int vid_mode = 0;
    boot_params_t*  boot_params;

    // sanity check
    if ( linux_image == 0) {
        bprint("Error: Linux kernel image is zero.\n");
        return 1;
    }
    if ( linux_size == 0 ) {
        bprint("Error: Linux kernel size is zero.\n");
        return 1;
    }
    if ( linux_size < sizeof(linux_kernel_header_t) ) {
        bprint("Error: Linux kernel size is too small.\n");
        return 1;
    }
    hdr = (linux_kernel_header_t *)(linux_image + KERNEL_HEADER_OFFSET);
    if ( hdr == NULL ) {
        bprint("Error: Linux kernel header is zero.\n");
        return 1;
    }
    if ( entry_point == NULL ) {
        bprint("Error: Output pointer is zero.\n");
        return 1;
    }

    // recommended layout
    //    0x0000 - 0x7FFF     Real mode kernel
    //    0x8000 - 0x8FFF     Stack and heap
    //    0x9000 - 0x90FF     Kernel command line

    // if setup_sects is zero, set to default value 4 
    if ( hdr->setup_sects == 0 )
        hdr->setup_sects = DEFAULT_SECTOR_NUM;
    if ( hdr->setup_sects > MAX_SECTOR_NUM ) {
        bprint("Error: Linux setup sectors %d exceed maximum limitation 64.\n",
                hdr->setup_sects);
        return 1;
    }
    // set vid_mode
    linux_parse_cmdline((char *)mbi->cmdline);
    if ( get_linux_vga(&vid_mode) )
        hdr->vid_mode = vid_mode;

    // compare to the magic number 
    if ( hdr->header != HDRS_MAGIC ) {
        bprint("Error: Old kernel (< 2.6.20) is not supported by tboot.\n");
        return 1;
    }
    if ( hdr->version < 0x0205 ) {
        bprint("Error: Old kernel (<2.6.20) is not supported by tboot.\n");
        return 1;
    }
    // boot loader is grub, set type_of_loader to 0x7
    hdr->type_of_loader = LOADER_TYPE_GRUB;

    // set loadflags and heap_end_ptr 
    hdr->loadflags |= FLAG_CAN_USE_HEAP;         /* can use heap */
    hdr->heap_end_ptr = KERNEL_CMDLINE_OFFSET - BOOT_SECTOR_OFFSET;

    // load initrd and set ramdisk_image and ramdisk_size 
    // The initrd should typically be located as high in memory as
    //   possible, as it may otherwise get overwritten by the early
    //   kernel initialization sequence. 
    uint64_t mem_limit = 0x100000000ULL;

    uint64_t max_ram_base, max_ram_size;
    get_highest_sized_ram(initrd_size, mem_limit,
                          &max_ram_base, &max_ram_size);
    if ( max_ram_size == 0 ) {
        bprint("not enough RAM for initrd\n");
        return 1;
    }
    if ( initrd_size > max_ram_size ) {
        bprint("initrd_size is too large\n");
        return 1;
    }
    if ( max_ram_base > ((uint64_t)(uint32_t)(~0)) ) {
        bprint("max_ram_base is too high\n");
        return 1;
    }
    initrd_base = (max_ram_base + max_ram_size - initrd_size) & PAGE_MASK;

    // should not exceed initrd_addr_max 
    if ( (initrd_base + initrd_size) > hdr->initrd_addr_max ) {
        if ( hdr->initrd_addr_max < initrd_size ) {
            bprint("initrd_addr_max is too small\n");
            return 1;
        }
        initrd_base = hdr->initrd_addr_max - initrd_size;
        initrd_base = initrd_base & PAGE_MASK;
    }

    vmm_memcpy ((void *)initrd_base, (void*)initrd_image, initrd_size);
    bprint("Initrd from 0x%lx to 0x%lx\n",
           (unsigned long)initrd_base,
           (unsigned long)(initrd_base + initrd_size));

    hdr->ramdisk_image = initrd_base;
    hdr->ramdisk_size = initrd_size;

    // calc location of real mode part 
    // FIX (JLM) TBOOT defines
    real_mode_base = LEGACY_REAL_START;
    if ( mbi->flags & MBI_MEMLIMITS )
        real_mode_base = (mbi->mem_lower << 10) - REAL_MODE_SIZE;
    if ( real_mode_base < TBOOT_KERNEL_CMDLINE_ADDR +
         TBOOT_KERNEL_CMDLINE_SIZE )
        real_mode_base = TBOOT_KERNEL_CMDLINE_ADDR +
            TBOOT_KERNEL_CMDLINE_SIZE;
    if ( real_mode_base > LEGACY_REAL_START )
        real_mode_base = LEGACY_REAL_START;
    real_mode_size = (hdr->setup_sects + 1) * SECTOR_SIZE;
    if ( real_mode_size + sizeof(boot_params_t) > KERNEL_CMDLINE_OFFSET ) {
        bprint("realmode data is too large\n");
        return 1;
    }

    // calc location of protected mode part
    protected_mode_size = linux_size - real_mode_size;

    // if kernel is relocatable then move it above tboot 
    // else it may expand over top of tboot 
    if ( hdr->relocatable_kernel ) {
        protected_mode_base = (uint32_t)get_bootstrap_mem_end();
        /* fix possible mbi overwrite in grub2 case */
        /* assuming grub2 only used for relocatable kernel */
        /* assuming mbi & components are contiguous */
        unsigned long mbi_end = get_mbi_mem_end(mbi);
        if ( mbi_end > protected_mode_base )
            protected_mode_base = mbi_end;
        /* overflow? */
        if ( plus_overflow_u32(protected_mode_base,
                 hdr->kernel_alignment - 1) ) {
            bprint("protected_mode_base overflows\n");
            return 1;
        }
        /* round it up to kernel alignment */
        protected_mode_base = (protected_mode_base + hdr->kernel_alignment - 1)
                              & ~(hdr->kernel_alignment-1);
        hdr->code32_start = protected_mode_base;
    }
    else if ( hdr->loadflags & FLAG_LOAD_HIGH ) {
        protected_mode_base =  LINUX_DEFAULT_LOAD_ADDRESS; // bzImage:0x100000 
        if ( plus_overflow_u32(protected_mode_base, protected_mode_size) ) {
            bprint("protected_mode_base plus protected_mode_size overflows\n");
            return 1;
        }
        // Check: protected mode part cannot exceed mem_upper 
        if ( mbi->flags & MBI_MEMLIMITS )
            if ( (protected_mode_base + protected_mode_size)
                    > ((mbi->mem_upper << 10) + 0x100000) ) {
                bprint("Error: Linux protected mode part (0x%lx ~ 0x%lx) "
                       "exceeds mem_upper (0x%lx ~ 0x%lx).\n",
                       (unsigned long)protected_mode_base,
                       (unsigned long)(protected_mode_base + protected_mode_size),
                       (unsigned long)0x100000,
                       (unsigned long)((mbi->mem_upper << 10) + 0x100000));
                return 1;
            }
    }
    else {
        bprint("Error: Linux protected mode not loaded high\n");
        return 1;
    }

    // set cmd_line_ptr 
    hdr->cmd_line_ptr = real_mode_base + KERNEL_CMDLINE_OFFSET;

    // load protected-mode part 
    vmm_memcpy((void *)protected_mode_base, (void*)(linux_image + real_mode_size),
            protected_mode_size);
    bprint("Kernel (protected mode) from 0x%lx to 0x%lx\n",
           (unsigned long)protected_mode_base,
           (unsigned long)(protected_mode_base + protected_mode_size));

    // load real-mode part 
    vmm_memcpy((void *)real_mode_base, (void*)linux_image, real_mode_size);
    bprint("Kernel (real mode) from 0x%lx to 0x%lx\n",
           (unsigned long)real_mode_base,
           (unsigned long)(real_mode_base + real_mode_size));

    // copy cmdline 
    const char *kernel_cmdline = skip_filename((const char *)mbi->cmdline);
    vmm_memcpy((void *)hdr->cmd_line_ptr, kernel_cmdline, 
               vmm_strlen((const char*)kernel_cmdline));

    // need to put boot_params in real mode area so it gets mapped 
    boot_params = (boot_params_t *)(real_mode_base + real_mode_size);
    vmm_memset(boot_params, 0, sizeof(*boot_params));
    vmm_memcpy(&boot_params->hdr, hdr, sizeof(*hdr));

    // detect e820 table 
    if ( mbi->flags & MBI_MEMMAP ) {
        int i;

        memory_map_t *p = (memory_map_t *)mbi->mmap_addr;
        for ( i = 0; (uint32_t)p < mbi->mmap_addr + mbi->mmap_length; i++ ) {
            boot_params->e820_map[i].addr = ((uint64_t)p->base_addr_high << 32)
                                            | (uint64_t)p->base_addr_low;
            boot_params->e820_map[i].size = ((uint64_t)p->length_high << 32)
                                            | (uint64_t)p->length_low;
            boot_params->e820_map[i].type = p->type;
            p = (void *)p + p->size + sizeof(p->size);
        }
        boot_params->e820_entries = i;
    }

    screen_info_t *screen = (screen_info_t *)&boot_params->screen_info;
    screen->orig_video_mode = 3;       /* BIOS 80*25 text mode */
    screen->orig_video_lines = 25;
    screen->orig_video_cols = 80;
    screen->orig_video_points = 16;    /* set font height to 16 pixels */
    screen->orig_video_isVGA = 1;      /* use VGA text screen setups */
    screen->orig_y = 24;               /* start display text in the last line
                                          of screen */
    linux_original_boot_parameters= (uint32_t) boot_params;
    *entry_point = hdr->code32_start;
    return 0;
}


// relocate and setup variables for evmm entry
int prepare_primary_guest_args(multiboot_info_t *mbi)
{
    // put arguments one page prior to guest esp (which is normally one page before evmm heap)
    if(linux_esp_register==0) {
        bprint("cant set linux esp\n");
        return 1;
    }

    linux_boot_params= (linux_esp_register-2*PAGE_SIZE);
    boot_params_t* new_boot_params= (boot_params_t*)linux_boot_params;

    vmm_memcpy((void*)linux_boot_params, (void*)linux_original_boot_parameters, sizeof(boot_params_t));

    uint32_t linux_e820_table= linux_boot_params + sizeof(boot_params_t);
    set_e820_copy_location(linux_e820_table, E820MAX);

    // set address of copied tboot shared page 
    vmm_memcpy((void*)new_boot_params->tboot_shared_addr, (void*)&shared_page, sizeof(shared_page));

    // copy 820 pages for linux
    if(copy_e820_map(mbi)==false) {
        bprint("cant copy e820 table\n");
        return 1;
    }
    new_boot_params->e820_entries= get_num_e820_ents();

    // set esi register
    linux_esi_register= linux_boot_params;

    return 0;
}


int prepare_linux_image_for_evmm(multiboot_info_t *mbi)
{
    if ( linux_start== 0)
        return 1;

    module_t* m = get_module(mbi, 2);
    uint32_t initrd_image = (uint32_t)m->mod_start;
    uint32_t initrd_size = m->mod_end - m->mod_start;
    expand_linux_image(mbi, linux_start, linux_end-linux_start,
                       initrd_image, initrd_size, &linux_entry_address);
    if(prepare_primary_guest_args(mbi)!=0) {
        return 1;
    }

    // CHECK(JLM)
    linux_start_address= linux_entry_address;
    bprint("Linux kernel @%p...\n", (void*)linux_entry_address);
    return 0;
}


#define MIN_ANONYMOUS_GUEST_ID  30000
typedef enum _GUEST_FLAGS {
   GUEST_IS_PRIMARY_FLAG = 0,
   GUEST_IS_NMI_OWNER_FLAG,
   GUEST_IS_ACPI_OWNER_FLAG,
   GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG,
   GUEST_BIOS_ACCESS_ENABLED_FLAG,
   GUEST_SAVED_IMAGE_IS_COMPRESSED_FLAG
} GUEST_FLAGS;


int prepare_evmm_startup_arguments(const multiboot_info_t *mbi)
{
    // Guest state initialization for relocated inage
    evmm_g0.size_of_this_struct = sizeof(evmm_g0);
    evmm_g0.version_of_this_struct = VMM_GUEST_STARTUP_VERSION;
    evmm_g0.flags = 0;
    BITMAP_SET(evmm_g0.flags, VMM_GUEST_FLAG_LAUNCH_IMMEDIATELY);
    BIT_SET(evmm_g0.flags, GUEST_IS_PRIMARY_FLAG | GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG);
    evmm_g0.guest_magic_number = MIN_ANONYMOUS_GUEST_ID;
    evmm_g0.cpu_affinity = -1;
    evmm_g0.cpu_states_count = 1;
    evmm_g0.devices_count = 0;
    evmm_g0.image_size = linux_end - linux_start;
    //FIX:  What does this answer mean?  My question is WHAT address needs to be
    // passed:  the address of protected mode Linux or ALL of linux,  Does it
    // include the EVMM HEAP area
    evmm_g0.image_address= linux_start_address;
    evmm_g0.image_offset_in_guest_physical_memory = linux_start_address;
    evmm_g0.physical_memory_size = 0; 

    // setup the registers (control and GP) that will be put in VMCS to init guest
    linux_setup(); 
    evmm_g0.cpu_states_array = (uint32_t)&linux_state;

    //     This pointer makes sense only if the devices_count > 0
    evmm_g0.devices_array = 0;

    // Startup struct initialization
    p_startup_struct->version_of_this_struct = VMM_STARTUP_STRUCT_VERSION;
    p_startup_struct->number_of_processors_at_install_time = 1;     // only BSP for now
    p_startup_struct->number_of_processors_at_boot_time = 1;        // only BSP for now
    p_startup_struct->number_of_secondary_guests = 0; 
    p_startup_struct->size_of_vmm_stack = UVMM_DEFAULT_STACK_SIZE_PAGES; 
    p_startup_struct->unsupported_vendor_id = 0; 
    p_startup_struct->unsupported_device_id = 0; 
    p_startup_struct->flags = 0; 
    
    p_startup_struct->default_device_owner= UUID;
    p_startup_struct->acpi_owner= UUID; 
    p_startup_struct->nmi_owner= UUID; 
    p_startup_struct->primary_guest_startup_state = (uint64_t)(uint32_t)&evmm_g0;

    // FIX: I think the memory layout is not needed for the primary
    // Also, note that the image size includes the heap.  Should the base_address
    // be the start of the evmm image or the evmm heap?
    evmm_vmem = (VMM_MEMORY_LAYOUT *) evmm_page_alloc(1);
    (p_startup_struct->vmm_memory_layout[0]).total_size = (evmm_end - evmm_start) + 
            evmm_heap_size + p_startup_struct->size_of_vmm_stack;
    (p_startup_struct->vmm_memory_layout[0]).image_size = (evmm_end - evmm_start);
    (p_startup_struct->vmm_memory_layout[0]).base_address = evmm_start_address;
    (p_startup_struct->vmm_memory_layout[0]).entry_point =  vmm_main_entry_point;
#if 0
    (p_startup_struct->vmm_memory_layout[1]).total_size = (linux_end - linux_start); //+linux's heap and stack size
    (p_startup_struct->vmm_memory_layout[1]).image_size = (linux_end - linux_start);
    (p_startup_struct->vmm_memory_layout[1]).base_address = linux_start;
    // QUESTION (JLM):  Check the line below.  It is only right if linux has a 64 bit elf header
    (p_startup_struct->vmm_memory_layout[1]).entry_point = linux_start + entryOffset(linux_start);
    (p_startup_struct->vmm_memory_layout[2]).total_size = (initram_end - initram_start);
    (p_startup_struct->vmm_memory_layout[2]).image_size = (initram_end - initram_start);
    (p_startup_struct->vmm_memory_layout[2]).base_address = initram_start;
    (p_startup_struct->vmm_memory_layout[2]).entry_point = initram_start+entryOffset(initram_start);
#endif

    // set up evmm e820 table
    p_startup_struct->physical_memory_layout_E820 = evmm_get_e820_table(mbi);

    // application parameters
    // This structure is not used so the setting is probably OK.
    evmm_a0.size_of_this_struct = sizeof(VMM_APPLICATION_PARAMS_STRUCT); 
    evmm_a0.number_of_params = 0;
    evmm_a0.session_id = 0;
    evmm_a0.address_entry_list = 0;
    evmm_a0.entry_number = 0;
#if 0
    evmm_a0.fadt_gpa = NULL;
    evmm_a0.dmar_gpa = NULL;
#endif

    if (p_startup_struct->physical_memory_layout_E820 == -1) {
        bprint("Error getting e820 table\n");
        return 1;
    }
    return 0;
}


// -------------------------------------------------------------------------


// Functions for relocating images


elf64_phdr* get_program_load_header(uint32_t image)
{
    elf64_hdr*  hdr = (elf64_hdr*) image;
    elf64_phdr* prog_header= NULL;
    int         i;

#ifdef JLMDEBUG1
    bprint("get_program_load_header: %d segments, entry size is %d, offset: 0x%08x\n",
            (int)hdr->e_phnum, (uint32_t)hdr->e_phentsize, (uint32_t)hdr->e_phoff);
#endif
    for(i=0; i<(int)hdr->e_phnum;i++) {
        prog_header= (elf64_phdr*)(image+(uint32_t)hdr->e_phoff+i*((uint32_t)hdr->e_phentsize));
#ifdef JLMDEBUG1
        bprint("segment entry: %d 0x%08x, offset: 0x%08x\n",
                (int)prog_header->p_type, (uint32_t)prog_header->p_vaddr,
                (uint32_t)prog_header->p_offset);
#endif
        if(prog_header->p_type==ELF64_PT_LOAD) {
            return prog_header;
        }
    }
    return NULL;
}


#define EM_X86_64 62
uint64_t OriginalEntryAddress(uint32_t base)
{
    elf64_hdr* elf= (elf64_hdr*) base;
    if(elf->e_machine!=EM_X86_64)
        return 0ULL;
    return elf->e_entry;
}


// -------------------------------------------------------------------------


// main
//     tboot jumps in here
int start32_evmm(uint32_t magic, uint32_t initial_entry, multiboot_info_t* mbi)
{
    extern void SetupIDT();
    int i;

    // reinitialize screen printing
    bootstrap_partial_reset();
#ifdef JLMDEBUG
    bprint("start32_evmm entry, mbi: %08x, initial_entry: %08x, magic: %08x\n",
            (uint32_t)mbi, initial_entry, magic);
#endif

    // We assume the standard grub layout with three modules after bootstrap: 
    //    64-bit evmm, the linux image and initram fs.
    // Everything is decompressed EXCEPT the protected mode portion of linux
    int l= mbi->mmap_length/sizeof(memory_map_t);
    if (l<3) {
        bprint("bootstrap error: wrong number of modules\n");
        LOOP_FOREVER
    }

    // get initial layout information for images
    module_t* m;

    bootstrap_start= (uint32_t)&_start_bootstrap;
    bootstrap_end= (uint32_t)&_end_bootstrap;

    m= get_module(mbi, 0);
    evmm_start= (uint32_t)m->mod_start;
    evmm_end= (uint32_t)m->mod_end;
    evmm_command_line= (char*)m->string;

    m= get_module(mbi, 1);
    linux_start= (uint32_t)m->mod_start;
    linux_end= (uint32_t)m->mod_end;
    linux_command_line= (char*)m->string;

    if(l>2) {
        m= get_module(mbi, 2);
        initram_start= (uint32_t)m->mod_start;
        initram_end= (uint32_t)m->mod_end;
    }
#ifdef JLMDEBUG
    // shared page
    bprint("shared_page data:\n");
    bprint("\t tboot_base: 0x%08x\n", shared_page->tboot_base);
    bprint("\t tboot_size: 0x%x\n", shared_page->tboot_size);
    
    // image info
    bprint("bootstrap_start, bootstrap_end: 0x%08x 0x%08x, size: %d\n", 
            bootstrap_start, bootstrap_end, bootstrap_end-bootstrap_start);
    bprint("evmm_start, evmm_end: 0x%08x 0x%08x\n", evmm_start, evmm_end);
    if(evmm_command_line==0)
        bprint("evmm command line is NULL\n");
    else
        bprint("evmm command line: %s\n", evmm_command_line);
    bprint("linux_start, linux_end: 0x%08x 0x%08x\n", linux_start, linux_end);
    if(linux_command_line==0)
        bprint("linux command line is NULL\n");
    else
        bprint("linux command line: %s\n", linux_command_line);
    bprint("initram_start, initram_end: 0x%08x 0x%08x\n", initram_start, initram_end);
#endif // JLMDEBUG

    // get CPU info
    uint32_t info;
    asm volatile (
        "\tmovl    $1, %%eax\n"
        "\tcpuid\n"
        "\tmovl    %%ebx, %[info]\n"
    : [info] "=m" (info)
    : 
    : "%eax", "%ebx", "%ecx", "%edx");
    // NOTE: changed shift form 16 to 18 to get the right answer
    evmm_num_of_aps = ((info>>18)&0xff)-1;
    if (evmm_num_of_aps < 0)
        evmm_num_of_aps = 0; 

#ifdef JLMDEBUG
    bprint("\t%d APs, %d, reset to 0\n", evmm_num_of_aps, info);
#endif
    evmm_num_of_aps = 0;  // BSP only for now

    init32.s.i32_low_memory_page = low_mem;
    init32.s.i32_num_of_aps = evmm_num_of_aps;

    // set up evmm heap addresses and range
    setup_evmm_heap(EVMM_HEAP_BASE, EVMM_HEAP_SIZE);

    // Relocate evmm_image 
    evmm_start_address= EVMM_DEFAULT_START_ADDR;
    elf64_phdr* prog_header=  get_program_load_header(evmm_start);
    if(prog_header==NULL) {
        bprint("Cant find load program header\n");
        LOOP_FOREVER
    }

    uint32_t evmm_start_load_segment= 0;
    uint32_t evmm_load_segment_size= 0;

    evmm_start_load_segment= evmm_start+((uint32_t)prog_header->p_offset);
    evmm_load_segment_size= (uint32_t) prog_header->p_memsz;

    if(((uint32_t)(prog_header->p_vaddr))!=evmm_start_address) {
        bprint("evmm load address is not default default: 0x%08x, actual: 0x%08x\n",
                evmm_start_address, evmm_start_load_segment);
        LOOP_FOREVER
    }

    vmm_memcpy((void *)evmm_start_address, (const void*) evmm_start_load_segment,
               (uint32_t) (prog_header->p_filesz));
    vmm_memset((void *)(evmm_start_load_segment+(uint32_t)(prog_header->p_filesz)),0,
               (uint32_t)(prog_header->p_memsz-prog_header->p_filesz));

    // Get entry point
    vmm_main_entry_point =  (uint32_t)OriginalEntryAddress(evmm_start);
    if(vmm_main_entry_point==0) {
        bprint("OriginalEntryAddress: bad elf format\n");
        LOOP_FOREVER
    }

#ifdef JLMDEBUG
    bprint("\tevmm_heap_base evmm_heap_size: 0x%08x 0x%08x\n", 
            evmm_heap_base, evmm_heap_size);
    bprint("\trelocated evmm_start_address: 0x%08x\nvmm_main_entry_point: 0x%08x\n", 
            evmm_start_address, vmm_main_entry_point);
    bprint("\tprogram header load address: 0x%08x, load segment size: 0x%08x\n\n",
            (uint32_t)(prog_header->p_vaddr), evmm_load_segment_size);
#endif
    LOOP_FOREVER

    // Set up evmm IDT Note(JLM): Is this necessary?
    SetupIDT();

    // setup gdt for 64-bit on BSP
    if(setup_64bit_paging()!=0) {
      bprint("Unable to setup 64 bit paging\n");
      LOOP_FOREVER
    }

    // Allocate stack and set rsp (esp)
    setup_evmm_stack();

#ifdef JLMDEBUG
    bprint("\tevmm_initial_stack: 0x%08x\n", evmm_initial_stack);
    bprint("evmm relocated to %08x, entry point: %08x\n",
            evmm_start_address, vmm_main_entry_point);
#endif

    if(prepare_linux_image_for_evmm(mbi)) {
        bprint("Cant prepare linux image\n");
        LOOP_FOREVER
    }

    // reserve bootstrap
    if(!e820_reserve_region(evmm_e820, bootstrap_start, (bootstrap_end - bootstrap_start))) {
      bprint("Unable to reserve bootstrap region in e820 table\n");
      LOOP_FOREVER
    } 
    // reserve linux arguments and stack
    if(!e820_reserve_region(evmm_e820, linux_boot_params, evmm_heap_base-linux_boot_params)) {
      bprint("Unable to reserve bootstrap region in e820 table\n");
      LOOP_FOREVER
    } 
#if 0
    // I don't think this is necessary
    if (!e820_reserve_region(evmm_e820, evmm_heap_base, (evmm_heap_size+(evmm_end-evmm_start)))) {
        bprint("Unable to reserve evmm region in e820 table\n");
        LOOP_FOREVER
    }
#endif

    if(prepare_evmm_startup_arguments(mbi)!=0) {
        bprint("Error setting up evmm startup arguments\n");
        LOOP_FOREVER
    }

    // FIX(RNB):  put APs in 64 bit mode with stack.  (In ifdefed code)
    // FIX (JLM):  In evmm, exclude tboot and bootstrap areas from primary space
    // FIX(JLM):  allocate  debug area for return from evmm print and print it.

    // set up evmm stack for vmm_main call and flip tp 64 bit mode
    //  vmm_main call:
    //      vmm_main(uint32_t local_apic_id, uint64_t startup_struct_u, 
    //               uint64_t application_params_struct_u, 
    //               uint64_t reserved UNUSED)
    asm volatile (
        // evmm_initial_stack points to the start of the stack
        "movl   %[evmm_initial_stack], %%esp\n"
        // prepare arguments for 64-bit mode
        // there are 3 arguments
        // align stack and push them on 8-byte alignment
        "\txor  %%eax, %%eax\n"
        "\tand  $7, %%esp\n"
        "\tpush %%eax\n"
        "\tpush %[evmm_reserved]\n"
        "\tpush %%eax\n"
        "\tpush %[evmm_p_a0]\n"
        "\tpush %%eax\n"
        "\tpush %[p_startup_struct]\n"
        "\tpush %%eax\n"
        "\tpush %[local_apic_id]\n"

        "\tcli\n"
        // push segment and offset
        "\tpush  %[cs_64]\n"

        // for following retf
        "\tpush 1f\n"
        "\tmovl %[vmm_main_entry_point], %%ebx\n"

        "\tmovl %[p_cr3], %%eax\n"
        // initialize CR3 with PML4 base
        // "\tmovl 4(%%esp), %%eax\n"
        "\tmovl %%eax, %%cr3 \n"

        // enable 64-bit mode
        // EFER MSR register
        "\tmovl 0x0C0000080, %%ecx\n"
        // read EFER into EAX
        "\trdmsr\n"
        // set EFER.LME=1
        "\tbts $8, %%eax\n"
        // write EFER
        "\twrmsr\n"

        // enable paging CR0.PG=1
        "\tmovl %%cr0, %%eax\n"
        "\tbts  $31, %%eax\n"
        "\tmovl %%eax, %%cr0\n"

        // at this point we are in 32-bit compatibility mode
        // LMA=1, CS.L=0, CS.D=1
        // jump from 32bit compatibility mode into 64bit mode.
        "\tretf\n"

"1:\n"
        // in 64bit this is actually pop rcx
        "\tpop %%ecx\n"
        // in 64bit this is actually pop rdx
        "\tpop %%edx\n"
        "\t.byte 0x41\n"
        // pop r8
        "\t.byte 0x58\n"
        "\t.byte 0x41\n"
        // pop r9
        "\t.byte 0x59\n"
        // in 64bit this is actually sub  0x18, %%rsp
        "\t.byte 0x48\n"
        "\tsubl 0x18, %%esp\n"
        // in 64bit this is actually
        // "\t call %%ebx\n"
        "\tjmp (%[vmm_main_entry_point])\n"
        "\tud2\n"
    :: [local_apic_id] "m" (local_apic_id), [p_startup_struct] "m" (p_startup_struct), 
       [evmm_p_a0] "m" (evmm_p_a0), [evmm_reserved] "m" (evmm_reserved), 
       [vmm_main_entry_point] "m" (vmm_main_entry_point), [evmm_initial_stack] "m" (evmm_initial_stack), 
       [cs_64] "m" (cs_64), [p_cr3] "m" (p_cr3)
    : "%eax", "%ebx", "%ecx", "%edx");

    return 0;
}

