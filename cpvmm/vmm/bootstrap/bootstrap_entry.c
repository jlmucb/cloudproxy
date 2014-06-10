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
#define MULTIAPS_ENABLED

// JLM: Remove this soon 
#ifdef TBOOT_SHARED_PAGE
tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;
#else
tboot_shared_t *shared_page = (tboot_shared_t *)NULL;
#endif


#define PSE_BIT     0x10
#define PAE_BIT     0x20
#define PAGE_SIZE   (1024 * 4) 
#define PAGE_MASK   (~(PAGE_SIZE-1))
#define PAGE_UP(a) ((a+(PAGE_SIZE-1))&PAGE_MASK)
#define MAXPROCESSORS 64


#define LOWBOOTPARAMS


// -------------------------------------------------------------------------


//   These are the variables for machine setup
//       Consult evmm-init-notes.txt

// start and end of bootstrap, no header, start is load address
extern uint32_t _start_bootstrap, _end_bootstrap;


#define EVMM_DEFAULT_START_ADDR  0x70000000 
#define LINUX_DEFAULT_LOAD_ADDRESS 0x100000
#define EVMM_HEAP_SIZE 0x100000
#define EVMM_HEAP_BASE (EVMM_DEFAULT_START_ADDR- EVMM_HEAP_SIZE)
#define UVMM_DEFAULT_HEAP 0x5000000


//      Memory layout on start32_evmm entry
uint32_t tboot_start= 0;        // tboot image start address
uint32_t tboot_end= 0;          // tboot image end address
uint32_t bootstrap_start= 0;    // bootstrap image start address
uint32_t bootstrap_end= 0;      // bootstrap image end address
uint32_t evmm_start= 0;         // location of evmm start
uint32_t evmm_end= 0;           // location of evmm image start
uint32_t linux_start= 0;        // location of linux imag start
uint32_t linux_end= 0;          // location of evmm start
uint32_t initram_start= 0;      // location of initram image start
uint32_t initram_end= 0;        // location of initram image end


// Post relocation addresses
uint32_t evmm_start_address= 0;         // address of evmm after relocation
uint32_t evmm_image_size= 0;            // image size
uint32_t evmm_orig_mem_size= 0;         // original memsize
uint32_t evmm_mem_size= 0;              // memory size (rounded up)
uint32_t evmm_total_size= 0;            // total size (includes heap)
uint32_t vmm_main_entry_point= 0;       // address of vmm_main after relocation
uint32_t evmm_heap_base= 0;             // start of initial evmm heap
uint32_t evmm_heap_current= 0; 
uint32_t evmm_heap_top= 0;
uint32_t evmm_heap_size= 0;             // size of initial evmm heap
uint32_t evmm_bsp_stack_base= 0;        // low address where stack is allocated
uint32_t evmm_bsp_stack= 0;             // initial bsp evmm stack
uint32_t evmm_stack_pointers_array[MAXPROCESSORS];
char*    evmm_command_line= NULL;       // evmm command line

multiboot_info_t  linux_mbi;            // mbi for linux

extern unsigned int max_e820_entries;   // copied e820 globals
extern unsigned int g_nr_map;           // copied e820 globals
extern memory_map_t *g_copy_e820_map;   // copied e820 globals
memory_map_t bootstrap_e820[E820MAX];   // our e820 map

// linux guest
uint32_t linux_real_mode_start= 0;      // address of real mode
uint32_t linux_real_mode_size= 0;       // size of real mode size
uint32_t linux_protected_mode_start= 0; // address of protected mode
uint32_t linux_protected_mode_size= 0;  // size of protected mode
uint32_t linux_start_address= 0;        // start address of image
uint32_t initram_start_address= 0;      // address of the initram 
uint32_t linux_entry_address= 0;        // address of the eip guest entry
uint32_t linux_edi_register= 0;         // edi register on guest entry
uint32_t linux_esp_register= 0;         // esp on guest entry
uint32_t linux_stack_base= 0;           // base of the stack on entry
uint32_t linux_stack_size= 0;           // stack size on guest entry
char*    linux_command_line= NULL;      // old command line
char*    new_cmdline= NULL;             // new command line

// boot parameters for linux guest
uint32_t linux_original_boot_parameters= 0;
uint32_t linux_boot_parameters= 0;


// -------------------------------------------------------------------------


//      initial evmm heap implementation


void setup_evmm_heap(uint32_t heap_base_address, uint32_t heap_bytes)
{
    evmm_heap_current = evmm_heap_base = heap_base_address;
    evmm_heap_top = evmm_heap_base + heap_bytes;
    evmm_heap_size= heap_bytes;
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
#define TOTAL_MEM 0x100000000ULL

static uint32_t                         evmm64_cs_selector= 0;
static uint32_t                         evmm64_ds_selector= 0;

static uint32_t                         evmm64_cr4= 0;
static uint32_t                         evmm64_cr3 = 0;

static IA32_GDTR                        gdtr_32;
static IA32_GDTR                        gdtr_64;  // still in 32-bit mode

// location of page in evmm heap that holds 64 bit descriptor table
static uint32_t                         evmm_descriptor_table= 0;
static EM64T_PML4 *                     pml4_table= NULL;
static EM64T_PDPE *                     pdp_table= NULL;
static EM64T_PDE_2MB *                  pd_table= NULL;

static INIT64_STRUCT                    init64;
static INIT32_STRUCT                    init32;

uint32_t                                low_mem = 0x8000;
int                                     evmm_num_of_aps= 0;
static uint64_t                         evmm_reserved = 0;
static uint32_t                         local_apic_id = 0;

static IA32_GDTR                        tboot_gdtr_32;
uint16_t                                tboot_cs_selector= 0;
static uint32_t                         tboot_cs_base= 0;
static uint32_t                         tboot_cs_limit= 0;
static uint16_t                         tboot_cs_attr= 0;
uint16_t                                tboot_ds_selector= 0;
static uint32_t                         tboot_ds_base= 0;
static uint32_t                         tboot_ds_limit= 0;
static uint16_t                         tboot_ds_attr= 0;
uint16_t                                tboot_ss_selector= 0;
static uint32_t                         tboot_ss_base= 0;
static uint32_t                         tboot_ss_limit= 0;
static uint16_t                         tboot_ss_attr= 0;
static uint64_t                         tboot_msr_debugctl= 0;
static uint64_t                         tboot_msr_efer= 0;
static uint64_t                         tboot_msr_pat= 0;
static uint64_t                         tboot_msr_sysenter_cs= 0;
static uint64_t                         tboot_msr_sysenter_esp= 0;
static uint64_t                         tboot_msr_sysenter_eip= 0;
static uint16_t                         tboot_tr_selector= 0;
static uint32_t                         tboot_tr_base= 0;
static uint32_t                         tboot_tr_limit= 0;
static uint16_t                         tboot_tr_attr= 0;

static uint32_t                         tboot_cr0= 0;
static uint32_t                         tboot_cr2= 0;
static uint32_t                         tboot_cr3= 0;
static uint32_t                         tboot_cr4= 0;

// guest gdt
static IA32_GDTR __attribute__((aligned (16))) guest_gdtr;
uint64_t __attribute__((aligned (16)))         guest_gdt[16] = {
    0x0000000000000000,
    0x0000000000000000,         // NULL descriptor 
    0x00c09b000000ffff,         // __KERNEL_CS 
    0x00c093000000ffff,         // __KERNEL_DS 
    0x00808b000000ffff,         // TS descriptor 
    0x0000000000000000,         // TS continued 
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
};
static uint16_t                         guest_cs_selector= 0;
static uint32_t                         guest_cs_base= 0;
static uint32_t                         guest_cs_limit= 0;
static uint16_t                         guest_cs_attr= 0;
static uint16_t                         guest_ds_selector= 0;
static uint32_t                         guest_ds_base= 0;
static uint32_t                         guest_ds_limit= 0;
static uint16_t                         guest_ds_attr= 0;
static uint16_t                         guest_ss_selector= 0;
static uint32_t                         guest_ss_base= 0;
static uint32_t                         guest_ss_limit= 0;
static uint16_t                         guest_ss_attr= 0;
static uint64_t                         guest_msr_debugctl= 0;
static uint64_t                         guest_msr_efer= 0;
static uint64_t                         guest_msr_pat= 0;
static uint64_t                         guest_msr_sysenter_cs= 0;
static uint64_t                         guest_msr_sysenter_esp= 0;
static uint64_t                         guest_msr_sysenter_eip= 0;
static uint16_t                         guest_tr_selector= 0;
static uint32_t                         guest_tr_base= 0;
static uint32_t                         guest_tr_limit= 0;
static uint16_t                         guest_tr_attr= 0;

static uint32_t                         guest_cr0= 0;
static uint32_t                         guest_cr2= 0;
static uint32_t                         guest_cr3= 0;
static uint32_t                         guest_cr4= 0;


// -------------------------------------------------------------------------


// machine setup and paging


int ia32_get_selector(uint32_t* p, uint32_t* base, uint32_t* limit, uint16_t* access)
{
    IA32_SEGMENT_DESCRIPTOR* desc= (IA32_SEGMENT_DESCRIPTOR*)p;
    IA32_SEGMENT_DESCRIPTOR_ATTR attr;

    *base= (UINT64)((desc->gen.lo.base_address_15_00) |
        (desc->gen.hi.base_address_23_16 << 16) |
        (desc->gen.hi.base_address_31_24 << 24));
    *limit= (UINT32)( (desc->gen.lo.limit_15_00) |
        (desc->gen.hi.limit_19_16 << 16));
    if(desc->gen.hi.granularity)
        *limit = (*limit << 12) | 0x00000fff;
    attr.attr16 = desc->gen_attr.attributes;
    attr.bits.limit_19_16 = 0;
    *access= (uint32_t) attr.attr16;
    return 0;
}


void ia32_write_ts(uint16_t ts)
{
    __asm__ volatile(
        "\tmovw %[ts],%%ax\n"
        "\tltr  %%ax\n"
    ::[ts] "g" (ts)
    : "%ax");
}


uint16_t ia32_read_ts()
{
    uint16_t  ts= 0;

    __asm__ volatile(
        "\txorw %%ax,%%ax\n"
        "\tstr  %%ax\n"
        "\tmovw %%ax, %[ts]\n"
    :[ts] "=g" (ts)
    : : "%ax");
    return ts;
}


uint16_t ia32_read_cs()
{
    uint16_t  cs= 0;

    __asm__ volatile(
        "\txorw %%ax,%%ax\n"
        "\tmovw %%cs, %%ax\n"
        "\tmovw %%ax, %[cs]\n"
    :[cs] "=g" (cs)
    : : "%ax");
    return cs;
}


uint16_t ia32_read_ds()
{
    uint16_t  ds= 0;

    __asm__ volatile(
        "\txorw %%ax,%%ax\n"
        "\tmovw %%ds,%%ax\n"
        "\tmovw %%ax, %[ds]\n"
    :[ds] "=g" (ds)
    : : "%ax");
    return ds;
}


uint16_t ia32_read_es()
{
    uint16_t  es= 0;

    __asm__ volatile(
        "\txorw %%ax,%%ax\n"
        "\tmovw %%es,%%ax\n"
        "\tmovw %%ax, %[es]\n"
    :[es] "=g" (es)
    : : "%ax");
    return es;
}


uint16_t ia32_read_fs()
{
    uint16_t  fs= 0;

    __asm__ volatile(
        "\txorw %%ax,%%ax\n"
        "\tmovw %%fs,%%ax\n"
        "\tmovw %%ax, %[fs]\n"
    :[fs] "=g" (fs)
    : : "%ax");
    return fs;
}


uint16_t ia32_read_gs()
{
    uint16_t  gs= 0;

    __asm__ volatile(
        "\txorw %%ax,%%ax\n"
        "\tmovw %%gs,%%ax\n"
        "\tmovw %%ax, %[gs]\n"
    :[gs] "=g" (gs)
    : : "%ax");
    return gs;
}


uint16_t ia32_read_ss()
{
    uint16_t  ss= 0;

    __asm__ volatile(
        "\txorw %%ax,%%ax\n"
        "\tmovw %%ss,%%ax\n"
        "\tmovw %%ax, %[ss]\n"
    :[ss] "=g" (ss)
    : : "%ax");
    return ss;
}


void read_cr0(uint32_t* ret)
{
    __asm__ volatile(
        "\tmovl  %[ret],%%ebx\n"
        "\tmovl  %%cr0,%%eax\n"
        "\tmovl %%eax, (%%ebx)\n"
    ::[ret] "p" (ret) 
    : "%eax","%ebx");
}


void read_cr2(uint32_t* ret)
{
    __asm__ volatile(
        "\tmovl  %[ret],%%ebx\n"
        "\tmovl  %%cr2,%%eax\n"
        "\tmovl %%eax, (%%ebx)\n"
    ::[ret] "p" (ret) 
    : "%eax","%ebx");
}


void read_cr3(uint32_t* ret)
{
    __asm__ volatile(
        "\tmovl  %[ret],%%ebx\n"
        "\tmovl  %%cr3,%%eax\n"
        "\tmovl %%eax, (%%ebx)\n"
    ::[ret] "p" (ret) 
    : "%eax","%ebx");
}


void  write_cr3(uint32_t value)
{
    __asm__ volatile(
        "\tmovl     %[value], %%eax\n"
        "\t movl    %%eax, %%cr3\n"
    ::[value] "m" (value)
    : "%eax", "cc");
}


void read_cr4(uint32_t* ret)
{
    __asm__ volatile(
        "\tmovl  %[ret],%%ebx\n"
        "\tmovl  %%cr4,%%eax\n"
        "\tmovl %%eax, (%%ebx)\n"
    ::[ret] "r" (ret) 
    : "%eax","%ebx");
}


void write_cr4(uint32_t val)
{
    __asm__ volatile(
        "\tmovl  %[val],%%eax\n"
        "\tmovl  %%eax, %%cr4\n"
    ::[val] "p" (val) 
    : "%eax","%ebx");
}


void  ia32_read_msr(uint32_t msr_id, uint64_t *p_value)
{
    __asm__ volatile(
        "\tmovl %[msr_id], %%ecx\n"
        "\trdmsr\n"        //write from EDX:EAX into MSR[ECX]
        "\tmovl %[p_value], %%ecx\n"
        "\tmovl %%eax, (%%ecx)\n"
        "\tmovl %%edx, 4(%%ecx)\n"
    ::[msr_id] "g" (msr_id), [p_value] "p" (p_value)
    :"%eax", "%ecx", "%edx");
}


void  ia32_write_msr(uint32_t msr_id, uint64_t *p_value)
{
    __asm__ volatile(
        "\tmovl %[p_value], %%ecx\n"
        "\tmovl (%%ecx), %%eax\n"
        "\tmovl 4(%%ecx), %%edx\n"
        "\tmovl %[msr_id], %%ecx\n"
        "\twrmsr"        //write from EDX:EAX into MSR[ECX]
    ::[msr_id] "g" (msr_id), [p_value] "p" (p_value)
    :"%eax", "%ecx", "%edx");
}


int setup_evmm_stacks()
{
    // bsp stack
    evmm_bsp_stack_base= (uint32_t) 
                evmm_page_alloc(UVMM_DEFAULT_STACK_SIZE_PAGES);
    if(evmm_bsp_stack_base==0) {
        return 1;
    }
    vmm_memset((void*)evmm_bsp_stack_base, 0, 
               PAGE_4KB_SIZE*UVMM_DEFAULT_STACK_SIZE_PAGES);
    // stack grows down
    evmm_bsp_stack= evmm_bsp_stack_base+
                        PAGE_4KB_SIZE*UVMM_DEFAULT_STACK_SIZE_PAGES;
    evmm_stack_pointers_array[0]= evmm_bsp_stack;

    // ap stacks
    uint32_t evmm_ap_stack_base= 0;
    uint32_t evmm_ap_stack= 0;
    int i;
    for(i=0; i<evmm_num_of_aps;i++) {
        evmm_ap_stack_base= (uint32_t) 
                evmm_page_alloc(UVMM_DEFAULT_STACK_SIZE_PAGES);
        if(evmm_ap_stack_base==0) {
            return 1;
        }
        // stack grows down
        evmm_ap_stack= evmm_ap_stack_base+
                        PAGE_4KB_SIZE*UVMM_DEFAULT_STACK_SIZE_PAGES;
        evmm_stack_pointers_array[i+1]= evmm_ap_stack;
    }
    return 0;
}


void setup_64bit_descriptors(void)
{
    // 1 page for segment descriptors
    evmm_descriptor_table = (uint32_t) evmm_page_alloc(1);

    // zero gdt
    vmm_memset((void*)evmm_descriptor_table, 0, PAGE_4KB_SIZE);

    // read 32-bit GDTR
    __asm__ volatile (
       "\tsgdt  %[gdtr_32]\n"
    :[gdtr_32] "=m" (gdtr_32)
    ::);

    // copy it to the new 64-bit GDT
    vmm_memcpy((void*)evmm_descriptor_table, (void *) gdtr_32.base, gdtr_32.limit+1);

    uint32_t  descriptor_base= ((uint32_t)evmm_descriptor_table+gdtr_32.limit+1);

    // 16 byte aligned
    descriptor_base= (descriptor_base+15)&(~0xf);

    uint64_t* end_of_desciptor_table= (uint64_t*) descriptor_base;
    // cs descriptor
    end_of_desciptor_table[0]= 0x00a09a0000000000ULL;
    end_of_desciptor_table[1]= 0x0000000000000000ULL;
    // ds descriptor
    end_of_desciptor_table[2]= 0x00a0920000000000ULL;
    end_of_desciptor_table[3]= 0x0000000000000000ULL;

    // selectors
    evmm64_cs_selector = (uint32_t)(&end_of_desciptor_table[0]) - 
                         (uint32_t)evmm_descriptor_table;
    evmm64_ds_selector = (uint32_t)(&end_of_desciptor_table[2]) - 
                         (uint32_t)evmm_descriptor_table;

    // set 64 bit
    gdtr_64.base= (uint32_t) evmm_descriptor_table;
    gdtr_64.limit= gdtr_32.limit + (uint32_t)(&end_of_desciptor_table[4])-
                    (uint32_t)(&end_of_desciptor_table[0]);

#ifdef JLMDEBUG
   bprint("\nevmm64_cs_selector: %d, evmm64_ds_selector: %d\n", 
          evmm64_cs_selector, evmm64_ds_selector);
   bprint("\ngdtr_32, base: 0x%08x, limit: %d\n", 
          gdtr_32.base, gdtr_32.limit);
   HexDump((uint8_t*)gdtr_32.base, (uint8_t*)gdtr_32.base+gdtr_32.limit+1);
   bprint("\ngdtr_64, base: 0x%08x, limit: %d\n", 
          gdtr_64.base, gdtr_64.limit);
   HexDump((uint8_t*)gdtr_64.base, (uint8_t*)gdtr_64.base+gdtr_64.limit+1);
   // LOOP_FOREVER
#endif
    // load gdtr
    // ia32_write_gdtr(&gdtr_64);
    __asm__ volatile (
       "\tlgdt  %[gdtr_64]\n"
    :[gdtr_64] "=m" (gdtr_64)
    ::);
}


//     2MB pages while running in 32-bit mode.
//     It should scope full 32-bit space, i.e. 4G
void setup_64bit_paging(uint64_t memory_size)
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
    // FIX(JLM): add flags here to set caching
    evmm64_cr3= (((uint32_t) pml4_table) & 0xfffff000);
}


int setup_64bit()
{
    // setup_64 bit for 64-bit on BSP
    setup_64bit_descriptors();

    // setup paging, control registers and flags on BSP
    setup_64bit_paging(TOTAL_MEM);

    // set cr3 and cr4
    write_cr3(evmm64_cr3);
    read_cr4(&evmm64_cr4);
    // evmm64_cr4 = ia32_read_cr4();
    BITMAP_SET(evmm64_cr4, PAE_BIT|PSE_BIT);
    write_cr4(evmm64_cr4);

    // we don't really use this structure
    init64.i64_gdtr= gdtr_64;
    init64.i64_cr3= evmm64_cr3;  // note we dont use the structure
    init64.i64_cs = evmm64_cs_selector;
    init64.i64_efer = 0;
    return 0;
}


// -------------------------------------------------------------------------


extern void startap_main(INIT32_STRUCT *p_init32, INIT64_STRUCT *p_init64,
                   VMM_STARTUP_STRUCT *p_startup, uint32_t entry_point);


void start_64bit_mode_on_aps(uint32_t stack_pointer, uint32_t start_address, 
                uint32_t segment, uint32_t* arg1, uint32_t* arg2, 
                uint32_t* arg3, uint32_t* arg4)
{
#ifdef JLMDEBUG
    bprint("start_64bit_mode_on_aps %p *p\n", stack_pointer, start_address);
#endif
    __asm__ volatile (

        "\tcli\n"

        // move start address to ebx for jump
        "\tmovl %[start_address], %%ebx\n"

        // initialize CR3 with PML4 base
        "\tmovl %[evmm64_cr3], %%eax\n"
        "\tmovl %%eax, %%cr3 \n"

        // evmm_initial_stack points to the start of the stack
        "movl   %[stack_pointer], %%esp\n"
        "\tandl  $0xfffffff8, %%esp\n"

        // prepare arguments for 64-bit mode
        // there are 4 arguments (including reserved)
        "\txor  %%eax, %%eax\n"
        "\tpush %%eax\n"
        "\tpush %[arg4]\n"
        "\tpush %%eax\n"
        "\tpush %[arg3]\n"
        "\tpush %%eax\n"
        "\tpush %[arg2]\n"
        "\tpush %%eax\n"
        "\tpush %[arg1]\n"

        // enable 64-bit mode
        // EFER MSR register
        "\tmovl $0x0c0000080, %%ecx\n"
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
        // mode switch
        "ljmp   $64, $1f\n"

"1:\n"
        // in 64 bit this is actually pop rdi (arg1)
        "\tpop %%edi\n"
        // in 64 bit this is actually pop rsi (arg2)
        "\tpop %%esi\n"
        // in 64 bit this is actually pop rdx (arg3)
        "\tpop %%edx\n"
        // in 64 bit this is actually pop rcx (arg4)
        "\tpop %%ecx\n"

        "\tjmp *%%ebx\n"
        "\tud2\n"
        :
        : [arg1] "g" (arg1), [arg2] "g" (arg2), [arg3] "g" (arg3), [arg4] "g" (arg4), 
          [start_address] "g" (start_address), [segment] "g" (segment), 
          [stack_pointer] "m" (stack_pointer), [evmm64_cr3] "m" (evmm64_cr3)
        : "%eax", "%ebx", "%ecx", "%edx");
}


void init64_on_aps(uint32_t stack_pointer, INIT64_STRUCT *p_init64_data, 
                    uint32_t start_address, void * arg1, void * arg2, 
                    void * arg3, void * arg4)
{
    uint32_t cr4;

#ifdef JLMDEBUG
    bprint("init64_on_aps %p *p\n", stack_pointer, start_address);
#endif
    // CHECK(JLM): is this right (cr4)?
    // ia32_write_gdtr(&p_init64_data->i64_gdtr);
    __asm__ volatile (
       "\tsgdt  %[gdtr_64]\n"
    :[gdtr_64] "=m" (gdtr_64)
    ::);
    write_cr3(p_init64_data->i64_cr3);
    read_cr4(&cr4);
    BITMAP_SET(cr4, PAE_BIT|PSE_BIT);
    write_cr4(cr4);
    start_64bit_mode_on_aps(stack_pointer, start_address, 
                   p_init64_data->i64_cs, arg1, arg2, arg3, arg4);
#ifdef JLMDEBUG
    bprint("init64_on_aps done\n");
    LOOP_FOREVER
#endif
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
    else {
        bprint("no command line\n");
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
#endif


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
    // mbi->config_table field should contain
    //  "the address of the rom configuration table returned by the
    //  GET CONFIGURATION bios call", so skip it 
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
    uint64_t guest_params_struct;
} VMM_INPUT_PARAMS;

VMM_GUEST_STARTUP                       evmm_g0;
VMM_APPLICATION_PARAMS_STRUCT           evmm_a0;
VMM_APPLICATION_PARAMS_STRUCT*          evmm_p_a0= &evmm_a0;

// state of primary linux guest on startup
VMM_GUEST_CPU_STARTUP_STATE      guest_processor_state[MAXPROCESSORS];
VMM_STARTUP_STRUCT               startup_struct;
VMM_STARTUP_STRUCT *             p_startup_struct = &startup_struct;

#define PRIMARY_MAGIC 0x0

// expanded e820 table used by evmm
static unsigned int     evmm_num_e820_entries = 0;
INT15_E820_MEMORY_MAP*  evmm_e820= NULL;
uint64_t                evmm_start_of_e820_table= 0ULL; // 64 bits version

static const cmdline_option_t linux_cmdline_options[] = {
    { "vga", "" },
    { "mem", "" },
    { NULL, NULL }
};
static char linux_param_values[ARRAY_SIZE(linux_cmdline_options)][MAX_VALUE_LEN];


// -------------------------------------------------------------------------


// linux memory initialization and guest setup


//  Linux data layout
//      Start of linux data area    <-- evmm_heap_base - 3*PAGE_SIZE
//          boot_parameters               <- offset 0
//          command line                  <- offset sizeof(boot_params_t)
//      4K stack                    <-- evmm_heap_base - PAGE_SIZE
//      evmm_heap_base              <-- where linux_esp_register will point
int allocate_linux_data()
{
    // setup linux stack
    linux_stack_base = evmm_heap_base-PAGE_SIZE;
    linux_stack_size= PAGE_SIZE;
    vmm_memset((void*)linux_stack_base, 0, PAGE_SIZE); 

    // linux data area
#ifdef LOWBOOTPARAMS
    linux_boot_parameters= 0x20000;
#else
    linux_boot_parameters= (linux_stack_base-linux_stack_size-2*PAGE_SIZE);
#endif
    vmm_memset((void*)linux_boot_parameters, 0, 2*PAGE_SIZE); 
    return 0;
}


#ifndef  Ia32VmxVmcsGuestSleepStateWaitForSipi
// defined in vmx_vmcs.h
#define  Ia32VmxVmcsGuestSleepStateWaitForSipi 3
#endif


int linux_setup(void)
{
    uint32_t        i;
    IA32_IDTR       idtr;
    // stack grows down, BSP only
    linux_esp_register= linux_stack_base+PAGE_SIZE;

    // guest state from table
    guest_gdtr.base= (uint32_t)&guest_gdt[0];
    guest_gdtr.limit= 63;
    guest_cs_selector= 0x10;
    guest_cs_base= 0;
    guest_cs_limit= 0xffffffff;
    guest_cs_attr=  0xc09b;
    guest_ds_selector= 0x18;
    guest_ds_base= 0;
    guest_ds_limit= 0xffffffff;
    guest_ds_attr= 0xc093;
    guest_ss_selector= 0x18;
    guest_ss_base=  0;
    guest_ss_limit=  0xffffffff;
    guest_ss_attr= 0xc093;
    guest_tr_selector= 0x20;
    guest_tr_base= 0;
    guest_tr_limit= 0x0000ffff;
    guest_tr_attr= 0x0000808b;

    guest_msr_debugctl= tboot_msr_debugctl;
    guest_msr_efer= tboot_msr_efer;
    guest_msr_pat= tboot_msr_pat;
    guest_msr_sysenter_cs= tboot_msr_sysenter_cs;
    guest_msr_sysenter_esp= tboot_msr_sysenter_esp;
    guest_msr_sysenter_eip= tboot_msr_sysenter_eip;

    guest_cr0= tboot_cr0;
    guest_cr2= tboot_cr2;
    guest_cr3= 0;
    guest_cr4= tboot_cr4;

    // AP's are in real mode waiting for sipi (halt state)
    // Set the VMCS GUEST ACTIVITY STATE in the VMCS Guest State Area
    // to "halted."
    // Bootstrap processor is 0
    int k;
    for(k=0; k<=evmm_num_of_aps; k++) {
        guest_processor_state[k].size_of_this_struct = 
                        sizeof(VMM_GUEST_CPU_STARTUP_STATE);
        guest_processor_state[k].version_of_this_struct = 
                        VMM_GUEST_CPU_STARTUP_STATE_VERSION;
        guest_processor_state[k].reserved_1 = 0;

        // zero out all the registers.  Then set the ones that linux expects.
        for (i = 0; i < IA32_REG_GP_COUNT; i++) {
            guest_processor_state[k].gp.reg[i]= (uint64_t) 0;
        }

        guest_processor_state[k].gp.reg[IA32_REG_RIP]= (uint64_t)linux_entry_address;
        guest_processor_state[k].gp.reg[IA32_REG_RDI]= (uint64_t) linux_edi_register;
        guest_processor_state[k].gp.reg[IA32_REG_RSI]= (uint64_t) linux_edi_register;
        guest_processor_state[k].gp.reg[IA32_REG_RSP]= (uint64_t) 
                        evmm_stack_pointers_array[k];
        guest_processor_state[k].gp.reg[IA32_REG_RFLAGS] = 0x02;
        guest_processor_state[k].gp.reg[IA32_REG_RBP] = 0;
    
        for (i = 0; i < IA32_REG_XMM_COUNT; i++) {
            guest_processor_state[k].xmm.reg[i].uint64[0] = (uint64_t)0;
            guest_processor_state[k].xmm.reg[i].uint64[1] = (uint64_t)0;
        }
        guest_processor_state[k].msr.msr_debugctl= guest_msr_debugctl;
        guest_processor_state[k].msr.msr_efer= guest_msr_efer;
        guest_processor_state[k].msr.msr_pat= guest_msr_pat;
        guest_processor_state[k].msr.msr_sysenter_esp= guest_msr_sysenter_esp;
        guest_processor_state[k].msr.msr_sysenter_eip= guest_msr_sysenter_eip;
        guest_processor_state[k].msr.msr_sysenter_cs= guest_msr_sysenter_cs;
        guest_processor_state[k].msr.pending_exceptions = 0;
        guest_processor_state[k].msr.interruptibility_state = 0;
        guest_processor_state[k].msr.activity_state = 0;
        guest_processor_state[k].msr.smbase = 0;
     
        for (i = 0; i < IA32_CTRL_COUNT; i++) {
            guest_processor_state[k].control.cr[i] = 0;
        }
        guest_processor_state[k].control.cr[IA32_CTRL_CR0]= (uint64_t) guest_cr0;
        guest_processor_state[k].control.cr[IA32_CTRL_CR2]= (uint64_t) guest_cr2;
        guest_processor_state[k].control.cr[IA32_CTRL_CR3] = (uint64_t) guest_cr3; 
        guest_processor_state[k].control.cr[IA32_CTRL_CR4]= (uint64_t) guest_cr4;

        for (i = 0; i < IA32_SEG_COUNT; i++) {
            guest_processor_state[k].seg.segment[i].base = 0;
            guest_processor_state[k].seg.segment[i].limit = 0;
        }
   
        guest_processor_state[k].control.gdtr.base = (uint64_t)(uint32_t)
                        guest_gdtr.base;
        guest_processor_state[k].control.gdtr.limit = (uint64_t)(uint32_t)
                        guest_gdtr.limit;

        __asm__ volatile (
           "\tsgdt  %[idtr]\n"
        :[idtr] "=m" (idtr)
        ::);

        guest_processor_state[k].control.idtr.base = (UINT64)idtr.base;
        guest_processor_state[k].control.idtr.limit = (UINT32)idtr.limit;
    
        guest_processor_state[k].seg.segment[IA32_SEG_CS].selector = 
                        (uint64_t) guest_cs_selector;
        guest_processor_state[k].seg.segment[IA32_SEG_DS].selector = 
                        (uint64_t) guest_ds_selector;
        guest_processor_state[k].seg.segment[IA32_SEG_SS].selector = 
                        (uint64_t) guest_ss_selector;
        guest_processor_state[k].seg.segment[IA32_SEG_ES].selector = 
                        (uint64_t) guest_ds_selector;
        guest_processor_state[k].seg.segment[IA32_SEG_FS].selector = 
                        (uint64_t) guest_ds_selector;
        guest_processor_state[k].seg.segment[IA32_SEG_GS].selector = 
                        (uint64_t) guest_ds_selector;
        guest_processor_state[k].seg.segment[IA32_SEG_TR].selector= 
                        (uint64_t) guest_tr_selector;

        guest_processor_state[k].seg.segment[IA32_SEG_CS].base = guest_cs_base;
        guest_processor_state[k].seg.segment[IA32_SEG_DS].base = guest_ds_base;
        guest_processor_state[k].seg.segment[IA32_SEG_SS].base = guest_ss_base;
        guest_processor_state[k].seg.segment[IA32_SEG_ES].base = guest_ds_base;
        guest_processor_state[k].seg.segment[IA32_SEG_FS].base = guest_ds_base;
        guest_processor_state[k].seg.segment[IA32_SEG_GS].base = guest_ds_base;
        guest_processor_state[k].seg.segment[IA32_SEG_TR].base = guest_ds_base;

        guest_processor_state[k].seg.segment[IA32_SEG_CS].limit = guest_cs_limit;
        guest_processor_state[k].seg.segment[IA32_SEG_DS].limit = guest_ds_limit;
        guest_processor_state[k].seg.segment[IA32_SEG_SS].limit = guest_ss_limit;
        guest_processor_state[k].seg.segment[IA32_SEG_ES].limit = guest_ds_limit;
        guest_processor_state[k].seg.segment[IA32_SEG_FS].limit = guest_ds_limit;
        guest_processor_state[k].seg.segment[IA32_SEG_GS].limit = guest_ds_limit;
        guest_processor_state[k].seg.segment[IA32_SEG_TR].limit = guest_tr_limit;

        guest_processor_state[k].seg.segment[IA32_SEG_CS].attributes = guest_cs_attr;
        guest_processor_state[k].seg.segment[IA32_SEG_DS].attributes = guest_ds_attr;
        guest_processor_state[k].seg.segment[IA32_SEG_SS].attributes = guest_ss_attr;
        guest_processor_state[k].seg.segment[IA32_SEG_ES].attributes = guest_ds_attr;
        guest_processor_state[k].seg.segment[IA32_SEG_FS].attributes = guest_ds_attr;
        guest_processor_state[k].seg.segment[IA32_SEG_GS].attributes = guest_ds_attr;
        guest_processor_state[k].seg.segment[IA32_SEG_TR].attributes = guest_tr_attr;
    
        guest_processor_state[k].seg.segment[IA32_SEG_LDTR].selector= 0x0;
        guest_processor_state[k].seg.segment[IA32_SEG_LDTR].base= 0x0;
        guest_processor_state[k].seg.segment[IA32_SEG_LDTR].limit= 0xffffffff;
        guest_processor_state[k].seg.segment[IA32_SEG_LDTR].attributes= 0x00010000;
    }
    return 0;
}


// This builds the 24 byte extended e820 table
static uint64_t evmm_get_e820_table(const multiboot_info_t *mbi) 
{
    uint32_t entry_offset = 0;
    int i= 0;

    evmm_e820 = (INT15_E820_MEMORY_MAP *)evmm_page_alloc(1);
    if (evmm_e820 == NULL)
        return (uint64_t)-1;

    while ( entry_offset < mbi->mmap_length ) {
        memory_map_t *entry = (memory_map_t *) 
                    (mbi->mmap_addr + entry_offset);
        evmm_e820->memory_map_entry[i].basic_entry.base_address = 
                    (((uint64_t)entry->base_addr_high)<<32)+entry->base_addr_low;
        evmm_e820->memory_map_entry[i].basic_entry.length = 
                    (((uint64_t)entry->length_high)<<32)+entry->length_low;
        evmm_e820->memory_map_entry[i].basic_entry.address_range_type= 
                    entry->type;
        evmm_e820->memory_map_entry[i].extended_attributes.uint32 = 1;
        i++;
       entry_offset += entry->size + sizeof(entry->size);
    }
    evmm_num_e820_entries = i;
    evmm_e820->memory_map_size = i*sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
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
    linux_parse_cmdline(linux_command_line);
    if (get_linux_vga(&vid_mode))
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
    hdr->loadflags |= FLAG_CAN_USE_HEAP;         // can use heap
    hdr->heap_end_ptr = KERNEL_CMDLINE_OFFSET - BOOT_SECTOR_OFFSET;

    // load initrd and set ramdisk_image and ramdisk_size 
    // The initrd should typically be located as high in memory as
    //   possible, as it may otherwise get overwritten by the early
    //   kernel initialization sequence. 
    uint64_t mem_limit = TOTAL_MEM;

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
#if 1
        protected_mode_base =  0x02000000;
        hdr->loadflags|= 0x40;  // keep segments
#else
        bprint("relocatable kernel\n");
        protected_mode_base = (uint32_t)get_bootstrap_mem_end();
        /* fix possible mbi overwrite in grub2 case */
        /* assuming grub2 only used for relocatable kernel */
        /* assuming mbi & components are contiguous */
        unsigned long mbi_end = get_mbi_mem_end(mbi);
        if ( mbi_end > protected_mode_base )
            protected_mode_base = mbi_end;
        // overflow? 
        if ( plus_overflow_u32(protected_mode_base,
                 hdr->kernel_alignment - 1) ) {
            bprint("protected_mode_base overflows\n");
            return 1;
        }
        // round it up to kernel alignment
        protected_mode_base= (protected_mode_base+hdr->kernel_alignment-1)
                              & ~(hdr->kernel_alignment-1);
#endif
        hdr->code32_start = protected_mode_base;
    }
    else if ( hdr->loadflags & FLAG_LOAD_HIGH ) {
        protected_mode_base =  LINUX_DEFAULT_LOAD_ADDRESS; // bzImage:0x100000 
        if ( plus_overflow_u32(protected_mode_base, protected_mode_size) ) {
            bprint("protected_mode_base+protected_mode_size overflows\n");
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
    vmm_memcpy((void *)protected_mode_base, 
               (void*)(linux_image + real_mode_size),
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
    if ( mbi->flags & MBI_CMDLINE ) {
        const char *kernel_cmdline = skip_filename((const char *)mbi->cmdline);
        vmm_memcpy((void *)hdr->cmd_line_ptr, kernel_cmdline, 
               vmm_strlen((const char*)kernel_cmdline));
    }

    // need to put boot_params in real mode area so it gets mapped 
    boot_params = (boot_params_t *)(real_mode_base + real_mode_size);
    vmm_memset(boot_params, 0, sizeof(*boot_params));
    vmm_memcpy(&boot_params->hdr, hdr, sizeof(*hdr));

    // copy e820 table to boot parameters
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
    screen->orig_video_mode = 3;       // BIOS 80*25 text mode
    screen->orig_video_lines = 25;
    screen->orig_video_cols = 80;
    screen->orig_video_points = 16;    // set font height to 16 pixels
    screen->orig_video_isVGA = 1;      // use VGA text screen setups 
    screen->orig_y = 24;               // last line of screen 
    linux_original_boot_parameters= (uint32_t) boot_params;
    linux_real_mode_start= real_mode_base;
    linux_real_mode_size= real_mode_size;
    linux_protected_mode_start= protected_mode_base;
    linux_protected_mode_size= protected_mode_size;
    initram_start_address= initrd_base;
    *entry_point = hdr->code32_start;
    return 0;
}


#ifdef INCLUDETBOOTCMDLINE
int adjust_kernel_cmdline(multiboot_info_t *mbi,
                          const void *tboot_shared_addr)
{
    const char *old_cmdline;

    if ( mbi->flags & MBI_CMDLINE && mbi->cmdline != 0 )
        old_cmdline = (const char *)mbi->cmdline;
    else
        old_cmdline = "";

    vscnprintf(new_cmdline, TBOOT_KERNEL_CMDLINE_SIZE, "%s tboot=%p",
             old_cmdline, tboot_shared_addr);
    new_cmdline[TBOOT_KERNEL_CMDLINE_SIZE - 1] = '\0';

    mbi->cmdline = (u32)new_cmdline;
    mbi->flags |= MBI_CMDLINE;

    return 0;
}
#endif


// relocate and setup variables for evmm entry
int prepare_primary_guest_args(multiboot_info_t *mbi)
{
  (void)mbi;
    if(linux_original_boot_parameters==0) {
        bprint("original boot parameters not set\n");
        return 1;
    }
    if(linux_boot_parameters==0) {
      bprint("linux boot parameter area fails\n");
      LOOP_FOREVER
    }
    vmm_memcpy((void*)linux_boot_parameters, (void*)linux_original_boot_parameters,
               sizeof(boot_params_t));
    boot_params_t* new_boot_params= (boot_params_t*)linux_boot_parameters;
    new_boot_params->e820_entries= g_nr_map;

    // set address of copied tboot shared page 
#ifdef TBOOT_SHARED_PAGE
    *(uint64_t *)(new_boot_params->tboot_shared_addr)= (uint32_t)shared_page;
#else
    *(uint64_t *)(new_boot_params->tboot_shared_addr)= 0;
#endif

    // copy command line after boot parameters
    new_cmdline= (char*)(linux_boot_parameters+sizeof(boot_params_t));
#ifdef INCLUDETBOOTCMDLINE
    if(adjust_kernel_cmdline(mbi, (const void*)new_boot_params->tboot_shared_addr)!=0) {
      bprint("cant adjust linux command line\n");
      LOOP_FOREVER
    }
#else
    if(linux_command_line!=0) {
        vmm_memcpy((void*)new_cmdline, (void*) linux_command_line,
               vmm_strlen((char*)linux_command_line)+1);
        new_boot_params->hdr.cmdline_size= vmm_strlen(new_cmdline)+1;
        new_boot_params->hdr.cmd_line_ptr= (uint32_t) new_cmdline;
    }
    else {
        new_cmdline= NULL;
        new_boot_params->hdr.cmdline_size= 0;
        new_boot_params->hdr.cmd_line_ptr= (uint32_t) 0;
    }
#endif
    // set edi register
    linux_edi_register= linux_boot_parameters;
#ifdef JLMDEBUG1  // TEST1
    bprint("edi reg: %08x\n", linux_edi_register);
    bprint("cmd_ptr: %08x, code32_start: %08x\n", new_boot_params->hdr.cmd_line_ptr, 
new_boot_params->hdr.code32_start);
    LOOP_FOREVER
#endif
    return 0;
}


int prepare_linux_image_for_evmm(multiboot_info_t *mbi)
{
    if (linux_start==0 || initram_start==0) {
        bprint("bad linux image or initram image\n");
        return 1;
    }

    // make linux mbi 
    // get correct command line and correct mbi
    vmm_memset((void*) &linux_mbi, 0, sizeof(multiboot_info_t));
    vmm_memcpy((void*) &linux_mbi, (void*)mbi, sizeof(multiboot_info_t));
#ifdef JLMDEBUG1
    if ( mbi->flags & MBI_CMDLINE ) {
        bprint("copied mbi has a command line\n");
    }
    else {
        bprint("copied mbi does not have a command line\n");
    }
    bprint("original mbi, %d modules, size %d\n", 
           mbi->mods_count, sizeof(multiboot_info_t));
#endif
    if(linux_command_line!=0) {
        mbi->flags|= MBI_CMDLINE;
        mbi->cmdline= (uint32_t)linux_command_line;
    }
    linux_mbi.mods_count--;
    linux_mbi.mods_addr+= sizeof(module_t);
    linux_mbi.mmap_addr= (uint32_t)g_copy_e820_map;
    linux_mbi.mmap_length= g_nr_map*sizeof(memory_map_t);

#ifdef JLMDEBUG1
    bprint("linux mbi, %d modules\n", linux_mbi.mods_count);
#endif

    if(expand_linux_image(&linux_mbi, linux_start, linux_end-linux_start,
                       initram_start, initram_end-initram_start, 
                       &linux_entry_address)!=0) {
        bprint("cannot expand linux image\n");
        return 1;
    }
#ifdef JLMDEBUG1
    bprint("linux_real_mode_start, linux_real_mode_size: 0x%08x %d\n",
            linux_real_mode_start, linux_real_mode_size);
    bprint("linux_protected_mode_start, linux_protected_mode_size: 0x%08x %d\n",
            linux_protected_mode_start, linux_protected_mode_size);
    bprint("initram_start_address: 0x%08x\n", initram_start_address);
#endif
    if(prepare_primary_guest_args(&linux_mbi)!=0) {
        bprint("cannot prepare_primary_guest_args\n");
        return 1;
    }
    // CHECK
    linux_start_address= linux_protected_mode_start;

#ifdef JLMDEBUG1
    // print header
    linux_kernel_header_t* hdr = (linux_kernel_header_t*)
                (linux_start + KERNEL_HEADER_OFFSET);
    bprint("linux header\n");
    bprint("setup_sects 0x%02x, code32_start 0x%08x\n", 
        hdr->setup_sects, hdr->code32_start);
    bprint("payload offset 0x%08x, payload length 0x%08x\n",
        hdr->payload_offset, hdr->payload_length);
    bprint("heap_end_ptr 0x%08x, command line: 0x%08x\n", 
        hdr->heap_end_ptr, hdr->cmd_line_ptr);
    bprint("ramdisk image 0x%08x, ramdisk size %d\n", 
        hdr->ramdisk_image, hdr->ramdisk_size);
#endif
    bprint("Linux kernel @%p...\n", (void*)linux_entry_address);
    return 0;
}


#define MIN_ANONYMOUS_GUEST_ID  30000
#define GUEST_IS_PRIMARY_FLAG 1
#define GUEST_IS_NMI_OWNER_FLAG 2
#define GUEST_IS_ACPI_OWNER_FLAG 4
#define GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG 8
#define GUEST_BIOS_ACCESS_ENABLED_FLAG 16
#define GUEST_SAVED_IMAGE_IS_COMPRESSED_FLAG 32


int prepare_primary_guest_environment(const multiboot_info_t *mbi)
{
    // setup stack ,control and gp registers for VMCS to init guest
    // Guest wakes up in 32 bit protected mode with arguments in edi
    linux_setup(); 

    // Guest state initialization for relocated inage
    evmm_g0.size_of_this_struct = sizeof(VMM_GUEST_STARTUP);
    evmm_g0.version_of_this_struct = VMM_GUEST_STARTUP_VERSION;
    evmm_g0.flags = 0;
    BITMAP_SET(evmm_g0.flags, VMM_GUEST_FLAG_LAUNCH_IMMEDIATELY);
    evmm_g0.flags= GUEST_IS_PRIMARY_FLAG | GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG;
    evmm_g0.guest_magic_number = MIN_ANONYMOUS_GUEST_ID;
    evmm_g0.cpu_affinity = -1;
    evmm_g0.cpu_states_count = 1+evmm_num_of_aps;
    evmm_g0.devices_count = 0;
    evmm_g0.image_size = 0; // linux_end - linux_start;
    evmm_g0.image_address= linux_start_address;
    evmm_g0.image_offset_in_guest_physical_memory = linux_start_address;
    evmm_g0.physical_memory_size = 0; 

    // linux state was prepared by linux_setup
    evmm_g0.cpu_states_array = (uint32_t)guest_processor_state;

    // This pointer makes sense only if the devices_count > 0
    evmm_g0.devices_array = 0;

    // Startup struct initialization
    p_startup_struct->version_of_this_struct = VMM_STARTUP_STRUCT_VERSION;
    p_startup_struct->size_of_this_struct = sizeof(VMM_STARTUP_STRUCT);
    p_startup_struct->number_of_processors_at_install_time = 1+evmm_num_of_aps;
    p_startup_struct->number_of_processors_at_boot_time = 1+evmm_num_of_aps;
    p_startup_struct->number_of_secondary_guests = 0; 
    p_startup_struct->size_of_vmm_stack = UVMM_DEFAULT_STACK_SIZE_PAGES; 
    p_startup_struct->unsupported_vendor_id = 0; 
    p_startup_struct->unsupported_device_id = 0; 
    p_startup_struct->flags = 0; 
    
    p_startup_struct->default_device_owner= PRIMARY_MAGIC;
    p_startup_struct->acpi_owner= PRIMARY_MAGIC; 
    p_startup_struct->nmi_owner= PRIMARY_MAGIC; 
    p_startup_struct->primary_guest_startup_state = 
                                (uint64_t)(uint32_t)&evmm_g0;

    // excluded regions
    p_startup_struct->num_excluded_regions= 4;
    // remove evmm from ept
    // tmroeder: switched from evmm_image_size to evmm_mem_size
    (p_startup_struct->vmm_memory_layout[0]).image_size = 
                        evmm_mem_size;
    (p_startup_struct->vmm_memory_layout[0]).total_size = 
                        evmm_total_size;
    (p_startup_struct->vmm_memory_layout[0]).base_address = 
                        evmm_start_address;
    (p_startup_struct->vmm_memory_layout[0]).entry_point =  
                        vmm_main_entry_point;
    // remove evmm initial data from ept
    (p_startup_struct->vmm_memory_layout[1]).image_size = 
                        evmm_heap_size;
    (p_startup_struct->vmm_memory_layout[1]).total_size =  
                        evmm_heap_size;
    (p_startup_struct->vmm_memory_layout[1]).base_address =  
                        evmm_heap_base;
    (p_startup_struct->vmm_memory_layout[1]).entry_point =  
                        evmm_heap_base;
    // remove tboot from ept
    (p_startup_struct->vmm_memory_layout[2]).image_size = 
                        tboot_end-tboot_start;
    (p_startup_struct->vmm_memory_layout[2]).total_size =  
                        tboot_end-tboot_start;
    (p_startup_struct->vmm_memory_layout[2]).base_address =  
                        tboot_start;
    (p_startup_struct->vmm_memory_layout[2]).entry_point =  
                        tboot_start;
    // remove bootstrap from ept
    (p_startup_struct->vmm_memory_layout[3]).image_size = 
                        bootstrap_end-bootstrap_start;
    (p_startup_struct->vmm_memory_layout[3]).total_size = 
                        bootstrap_end-bootstrap_start;
    (p_startup_struct->vmm_memory_layout[3]).base_address =  
                        bootstrap_start;
    (p_startup_struct->vmm_memory_layout[3]).entry_point =  
                        bootstrap_start;

    // set up evmm e820 table
    p_startup_struct->physical_memory_layout_E820 = evmm_get_e820_table(mbi);
    if (p_startup_struct->physical_memory_layout_E820 == (uint32_t)-1) {
        bprint("Error getting e820 table\n");
        return 1;
    }

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


// get rid of hole from tboot
// from 0x4005000 to 0xb83f3000
/*uint32_t size;
        uint32_t base_addr_low;
        uint32_t base_addr_high;
        uint32_t length_low;
        uint32_t length_high;
        uint32_t type;
 */
void fixe820map()
{
    unsigned int           i;
    memory_map_t *entry;

    for(i=0; i<g_nr_map; i++) {
        entry= &bootstrap_e820[i];
        if(entry->base_addr_low<0xa0000000 && 
           (entry->base_addr_low+entry->size)>0xa0000000 &&
           entry->base_addr_high==0) {
            entry->type= E820_RAM;
            break;
        }
    }
}


// -------------------------------------------------------------------------


// main
//     tboot jumps in here
int start32_evmm(uint32_t magic, multiboot_info_t* mbi, uint32_t initial_entry) 
{
    int         i;
    module_t*   m;

    // reinitialize screen printing
    bootstrap_partial_reset();
#ifdef JLMDEBUG
    bprint("start32_evmm, mbi: %08x, initial_entry: %08x, magic: %08x\n",
            (uint32_t)mbi, initial_entry, magic);
#endif

    // print out the registers
    // set mbi to 0x10000
    bprint("shared_page = %p\n", shared_page);
    mbi = (multiboot_info_t*)0x10000;
    // tboot start/end, this is the only data from the shared
    // page we use
#ifdef TBOOT_SHARED_PAGE
    tboot_start= shared_page->tboot_base;
    tboot_end= shared_page->tboot_base+shared_page->tboot_size;
#else
    tboot_start= 0;
    tboot_end= 0;
#endif

    // bootstrap's start (load) address and its end address
    bootstrap_start= (uint32_t)&_start_bootstrap;
    bootstrap_end= (uint32_t)&_end_bootstrap;

    // We assume the standard with three modules after bootstrap: 
    //    64-bit evmm, the linux image and initram fs.
    // Everything is decompressed EXCEPT the protected mode portion of linux
    int l= mbi->mods_count;
    if (l!=3) {
        bprint("bootstrap error: wrong number of modules %d\n", l);
        LOOP_FOREVER
    }

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
    bprint("tboot_start, tboot_end: 0x%08x 0x%08x\n", tboot_start, tboot_end);
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
#endif

    // initialize stack array
    for(i=0;i<MAXPROCESSORS;i++)
        evmm_stack_pointers_array[i]=  0;

    // get CPU info
    uint32_t info;
    __asm__ volatile (
        "\tmovl    $1, %%eax\n"
        "\tcpuid\n"
        "\tmovl    %%ebx, %[info]\n"
    : [info] "=m" (info)
    : : "%eax", "%ebx", "%ecx", "%edx");
    // NOTE: changed shift from 16 to 18 to get the right answer
    evmm_num_of_aps = ((info>>18)&0xff)-1;
    if(evmm_num_of_aps < 0)
        evmm_num_of_aps = 0; 
    if(evmm_num_of_aps>=MAXPROCESSORS) {
        bprint("Too many aps (%d), resetting to %d\n", evmm_num_of_aps, MAXPROCESSORS);
        evmm_num_of_aps = MAXPROCESSORS-1; 
    }
#ifndef MULTIAPS_ENABLED
    evmm_num_of_aps = 0;
#endif

    // get tboot gdtr
    __asm__ volatile (
       "\tsgdt  %[tboot_gdtr_32]\n"
   :[tboot_gdtr_32] "=m" (tboot_gdtr_32)
   ::);

    // make a fake TSS to keep vmcs happy
    *((UINT64*)tboot_gdtr_32.base+24)= 0x00808b0000000000ULL;
    *((UINT64*)tboot_gdtr_32.base+32)= 0ULL;
    tboot_gdtr_32.limit= 39;
    tboot_tr_attr= 0x0000808b;
    tboot_tr_limit= 0xffffffff;
    ia32_write_ts(24);

    tboot_cs_selector= ia32_read_cs();
    tboot_ds_selector= ia32_read_ds();
    tboot_ss_selector= ia32_read_ss();
    tboot_tr_selector= ia32_read_ts();
    ia32_read_msr(IA32_MSR_DEBUGCTL, &tboot_msr_debugctl);
    ia32_read_msr(IA32_MSR_EFER, &tboot_msr_efer);
    ia32_read_msr(IA32_MSR_PAT, &tboot_msr_pat);
    ia32_read_msr(IA32_MSR_SYSENTER_ESP, &tboot_msr_sysenter_esp);
    ia32_read_msr(IA32_MSR_SYSENTER_EIP, &tboot_msr_sysenter_eip);
    ia32_read_msr(IA32_MSR_SYSENTER_CS, &tboot_msr_sysenter_cs);
    read_cr0(&tboot_cr0);
    read_cr2(&tboot_cr2);
    read_cr3(&tboot_cr3);
    read_cr4(&tboot_cr4);

    uint32_t*  p;
    p= (uint32_t*)(tboot_gdtr_32.base+tboot_cs_selector); 
    ia32_get_selector(p, &tboot_cs_base, &tboot_cs_limit, &tboot_cs_attr);
    p= (uint32_t*)(tboot_gdtr_32.base+tboot_ds_selector); 
    ia32_get_selector(p, &tboot_ds_base, &tboot_ds_limit, &tboot_ds_attr);
    p= (uint32_t*)(tboot_gdtr_32.base+tboot_ss_selector); 
    ia32_get_selector(p, &tboot_ss_base, &tboot_ss_limit, &tboot_ss_attr);
    p= (uint32_t*)(tboot_gdtr_32.base+tboot_tr_selector); 
    ia32_get_selector(p, &tboot_tr_base, &tboot_tr_limit, &tboot_tr_attr);
#ifdef JLMDEBUG
    bprint("gdt base: %08x, limit: %04x\n", tboot_gdtr_32.base, tboot_gdtr_32.limit);
    bprint("tboot cs selector: %04x, base: %08x, limit: %04x, attr: %04x\n",
           tboot_cs_selector, tboot_cs_base, tboot_cs_limit, tboot_cs_attr);
    bprint("tboot ds selector: %04x, base: %08x, limit: %04x, attr: %04x\n",
           tboot_ds_selector, tboot_ds_base, tboot_ds_limit, tboot_ds_attr);
    bprint("tboot ss selector: %04x, base: %08x, limit: %04x, attr: %04x\n",
           tboot_ss_selector, tboot_ss_base, tboot_ss_limit, tboot_ss_attr);
    bprint("tboot tr selector: %04x, base: %08x, limit: %04x, attr: %04x\n",
           tboot_tr_selector, tboot_tr_base, tboot_tr_limit, tboot_tr_attr);
    bprint("msr_debugctl: 0x%016llx\n", tboot_msr_debugctl);
    bprint("msr_efer: 0x%016llx\n", tboot_msr_efer);
    bprint("msr_pat: 0x%016llx\n", tboot_msr_pat);
    bprint("msr_sysenter_esp: 0x%016llx\n", tboot_msr_sysenter_esp);
    bprint("msr_sysenter_eip: 0x%016llx\n", tboot_msr_sysenter_eip);
    bprint("msr_sysenter_cs: 0x%016llx\n", tboot_msr_sysenter_cs);
#endif

    init32.i32_low_memory_page = low_mem;
    init32.i32_num_of_aps = evmm_num_of_aps;

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
    evmm_start_load_segment= evmm_start+((uint32_t)prog_header->p_offset);
    evmm_image_size= (uint32_t) prog_header->p_filesz;
    evmm_orig_mem_size= (uint32_t) prog_header->p_memsz;
    evmm_mem_size= PAGE_UP(evmm_orig_mem_size);  // full page
    evmm_total_size= evmm_mem_size+UVMM_DEFAULT_HEAP;         

    if(((uint32_t)(prog_header->p_vaddr))!=evmm_start_address) {
        bprint("evmm load address is not default: 0x%08x, actual: 0x%08x\n",
                evmm_start_address, evmm_start_load_segment);
        LOOP_FOREVER
    }

    vmm_memcpy((void *)evmm_start_address, 
               (const void*) evmm_start_load_segment,
               evmm_image_size);
    // zero everything after image
    vmm_memset((void *)(evmm_start_address+evmm_image_size),
               0, evmm_total_size-evmm_image_size);

    // Get entry point
    vmm_main_entry_point =  (uint32_t)OriginalEntryAddress(evmm_start);
    if(vmm_main_entry_point==0) {
        bprint("OriginalEntryAddress: bad elf format\n");
        LOOP_FOREVER
    }

#ifdef JLMDEBUG1
    bprint("\tevmm_heap_base evmm_heap_size: 0x%08x 0x%08x\n", 
            evmm_heap_base, evmm_heap_size);
    bprint("\trelocated evmm_start_address: 0x%08x\nvmm_main_entry_point: 0x%08x\n", 
            evmm_start_address, vmm_main_entry_point);
    bprint("\tprogram header load address: 0x%08x, image size: 0x%08x, total size: 0x%08x\n",
            (uint32_t)(prog_header->p_vaddr), evmm_image_size, evmm_total_size);
#endif

    // setup our e820 table (20 byte format)
    max_e820_entries= E820MAX;   // copied e820 globals
    g_nr_map= 0;
    g_copy_e820_map= bootstrap_e820;
    if(copy_e820_map(mbi)!=true) {
        bprint("cant copy e820 map\n");
        LOOP_FOREVER
    }

#ifdef JLMDEBUG1
    bprint("%d e820 entries after copy, original had %d\n", 
            g_nr_map, mbi->mmap_length/sizeof(memory_map_t));
#endif

    // tboot reserves the region were putting stuff in (see below)
    // Tboot's explaination
    //      Tboot reserves the following regions: 0x20200000 - 0x40004000,
    //      0x40005000 - 0xb88f3000, 0xb9bff000 - 0xb9c00000
    //      because some legacy bios's put USB buffers there
    //      which causes problems if they are DMA protected.
    //      we're going to ignore this because we want to
    //      put bootstrap and evmm here.
    // What BIOS's have this problem?
    // Answer:
    // Both igfx & legacy USB support might reserve small chunks of memory 
    // (0x20000000~0x20200000 is for igfx, 0x40004000~0x40005000 is for usb). 
    // Even in latest Lenovo laptop these memory holes is still existing.
    // Tboot added a min_ram=0xXXXXXXXX option to get the usable memory 
    // back if the size exceeds the number in this option, but the side 
    // effect is the device memory before the reenabled usabled ram will 
    // be DMA protected.
    fixe820map();

    // reserve bootstrap
    if(!e820_reserve_ram(bootstrap_start, (bootstrap_end - bootstrap_start))) {
      bprint("Unable to reserve bootstrap region in e820 table\n");
      LOOP_FOREVER
    } 

    // JLM(FIX):the start and end should be at page boundries
    // reserve evmm area
    // need to include additional heap too evmm_total_size
    if (!e820_reserve_ram(evmm_heap_base, (evmm_heap_base+evmm_heap_size+evmm_total_size))) {
        bprint("Unable to reserve evmm region in e820 table\n");
        LOOP_FOREVER
    }

#ifdef JLMDEBUG1
    bprint("start of evmm exclusion: 0x%08x, end of exclusion: 0x%08lx\n",
           evmm_heap_base, evmm_heap_base+evmm_heap_size+evmm_total_size);
    bprint("%d e820 entries after new reservations\n", g_nr_map);
    print_map(&g_copy_e820_map[5], 10);
#endif

#ifdef SETUPIDT
    extern void SetupIDT(); // this is not needed
    SetupIDT();
#endif

    // setup gdt for 64-bit on BSP
    if(setup_64bit()!=0) {
      bprint("Unable to setup 64 bit paging\n");
      LOOP_FOREVER
    }

    // Allocate stack and set rsp (esp)
    if(setup_evmm_stacks()!=0) {
      bprint("can't allocate stack\n");
      LOOP_FOREVER
    }

#ifdef JLMDEBUG
    bprint("evmm_bsp_stack: 0x%08x\n", evmm_bsp_stack);
    bprint("%d processors, stacks:\n", 1+evmm_num_of_aps);
    for(i=0; i<=evmm_num_of_aps; i++) {
        bprint("%08x ", evmm_stack_pointers_array[i]);
    }
    bprint("\n");
#endif

    // this is used by the wakup code in sipi init
    // CHECK(JLM): maybe this should be  &evmm_stack_pointers_array[1]
    init32.i32_esp= evmm_stack_pointers_array;

    // We need to allocate this before guest setup
    if(allocate_linux_data()!=0) {
      bprint("Cant allocate data area for primary linux guest\n");
      LOOP_FOREVER
    }

    // mark linux data area as reserved
#ifdef LOWBOOTPARAMS
    if(!e820_reserve_ram(linux_stack_base,
                         evmm_heap_base-linux_stack_base)) {
      bprint("Unable to reserve bootstrap region in e820 table\n");
      LOOP_FOREVER
    }
    if(!e820_reserve_ram(linux_boot_parameters, 2*PAGE_SIZE)) {
      bprint("Unable to reserve bootstrap region in e820 table\n");
      LOOP_FOREVER
    }
#else
    if(!e820_reserve_ram(linux_boot_parameters, 
                         evmm_heap_base-linux_boot_parameters)) {
      bprint("Unable to reserve bootstrap region in e820 table\n");
      LOOP_FOREVER
    }
#endif

    // prepare linux for evmm
    if(prepare_linux_image_for_evmm(mbi)) {
        bprint("Cant prepare linux image\n");
        LOOP_FOREVER
    }

    // copy linux data that is passed to linux in call
    if(prepare_primary_guest_environment(&linux_mbi)!=0) {
        bprint("Error setting up evmm startup arguments\n");
        LOOP_FOREVER
    }

#ifdef JLMDEBUG1
    // Print final parameters for linux
    boot_params_t* new_boot_params= (boot_params_t*)linux_boot_parameters;
    bprint("Final Linux parameters\n");
    bprint("\tShared page address: 0x%016lx %d e820 entries\n", 
           (long unsigned int)*(uint64_t*)new_boot_params->tboot_shared_addr,
           new_boot_params->e820_entries);
    bprint("\tCode32_start: 0x%08x, ramdisk: 0x%08x, ramdisk size: %d\n",
           new_boot_params->hdr.code32_start,
           new_boot_params->hdr.ramdisk_image,
           new_boot_params->hdr.ramdisk_size);
    char* s= (char*) new_boot_params->hdr.cmd_line_ptr;
    if(s!=NULL || vmm_strlen(s)<100) {
        bprint("\tcommand line: %s\n", s);
    }
    else {
        bprint("\tinvalid command line\n");
    }
#endif
#ifdef JLMDEBUG1
    bprint("code at evmm start\n");
    HexDump((uint8_t*)evmm_start_address, (uint8_t*)evmm_start_address+10);
    HexDump((uint8_t*)linux_start_address, (uint8_t*)linux_start_address+10);
#endif

    // FIX (JLM):  In evmm, exclude tboot and bootstrap areas from primary space
    // CHECK (JLM):  check that everything is measured (bootstrap, evmm)

    // set up evmm stack for vmm_main call and flip tp 64 bit mode
    //  vmm_main call:
    //      vmm_main(uint32_t local_apic_id, uint64_t startup_struct_u, 
    //               uint64_t application_params_struct_u, 
    //               uint64_t reserved UNUSED)

#ifdef JLMDEBUG
    bprint("evmm_image_size: 0x%016lx, evmm_mem_size: 0x%016lx\n",
            (long unsigned int)evmm_image_size, (long unsigned int)evmm_mem_size);
    bprint("Orig extra mem: 0x%016lx, diff: 0x%016lx\n",
            (long unsigned int)evmm_orig_mem_size, 
            (long unsigned int)(evmm_orig_mem_size-evmm_image_size));
    bprint("evmm_total_size: 0x%016lx\n",
            (long unsigned int)evmm_total_size);
    bprint("Evmm descriptor table, cs selector: 0x%08x, cr3: 0x%08x\n", 
           (uint32_t) evmm64_cs_selector, (uint32_t) evmm64_cr3);
    HexDump((uint8_t*)gdtr_64.base, 
            (uint8_t*)gdtr_64.base+gdtr_64.limit);
    bprint("Tboot descriptors, cs_sel: %04x, ds_sel: %04x, ss_sel: %04x, tr_sel: %04x:\n",
            tboot_cs_selector,tboot_ds_selector,
            tboot_ss_selector, tboot_tr_selector);
    bprint("Tboot attrs, cs_attr: %08x, ds_attr: %08x, ss_attr: %08x, tr_attr: %08x:\n",
            tboot_cs_attr,tboot_ds_attr,
            tboot_ss_attr, tboot_tr_attr);
    bprint("Tboot limits, cs_limit: %04x, ds_limit: %04x, ss_limit: %04x, tr_limit: %04x:\n",
            tboot_cs_limit,tboot_ds_limit, tboot_ss_limit, tboot_tr_limit);
    HexDump((uint8_t*)(tboot_gdtr_32.base), 
            (uint8_t*)(tboot_gdtr_32.base+tboot_gdtr_32.limit));
    bprint("cr0: %08x, cr2: %08x, cr3: %08x, cr4: %08x\n", guest_cr0, 
           guest_cr2, guest_cr3, guest_cr4);
    bprint("Guest descriptor table, cs_sel: %04x, ds_sel: %04x, ss_sel: %04x, tr_sel: %04x:\n",
            guest_cs_selector, guest_ds_selector,
            guest_ss_selector, guest_tr_selector);
    HexDump((uint8_t*)(guest_gdtr.base), 
            (uint8_t*)(guest_gdtr.base+guest_gdtr.limit));
    bprint("arguments to vmm_main: ");
    bprint("apic %d, p_startup_struct, 0x%08x\n",
       (int) local_apic_id, (int) p_startup_struct);
    bprint("linux stack base: %08x, linux_edi_reg: %08x\n",
           linux_stack_base, linux_edi_register);
    bprint("\tapplication struct 0x%08x, reserved, 0x%08x\n",
           (int)evmm_p_a0, (int)evmm_reserved);
#endif
#ifdef JLMDEBUG1
    boot_params_t* linux_boot_params= (boot_params_t*)linux_boot_parameters;
    bprint("bootparams at: %p, e820 map in boot params to linux (%d entries)\n",
          linux_boot_params, linux_boot_params->e820_entries);
    bprint("command line: %s\n", 
           (char*) (linux_boot_parameters+sizeof(boot_params_t)));
    e820entry_t* pent= linux_boot_params->e820_map;
    for(i=0; i<linux_boot_params->e820_entries;i++) {
        bprint("\taddr: %016llx, size: %lld, type: %d\n",
                pent->addr, pent->size, pent->type);
        pent++;
    }
#endif

    if(evmm64_cs_selector!=64) {
        bprint("cs_selector is wrong, 0x08x\n", evmm64_cs_selector);
        LOOP_FOREVER
    }

    if (evmm_num_of_aps > 0) {
#ifdef JLMDEBUG
        bprint("about to call startap_main, %d aps\n", evmm_num_of_aps);
        bprint("&init32: %p\n", &init32);
        bprint("&init64: %p\n", &init64);
        bprint("p_startup_struct: %p\n", p_startup_struct);
        bprint("vmm_main_entry_point: %p\n", vmm_main_entry_point);
#endif
        startap_main(&init32, &init64, p_startup_struct, vmm_main_entry_point);
    }

    __asm__ volatile (

        "\tcli\n"

        // move entry point to ebx for jump
        "\tmovl %[vmm_main_entry_point], %%ebx\n"

        // initialize CR3 with PML4 base
        "\tmovl %[evmm64_cr3], %%eax\n"
        "\tmovl %%eax, %%cr3 \n"

        // evmm_initial_stack points to the start of the stack
        "\tmovl   %[evmm_bsp_stack], %%esp\n"
        "\tandl  $0xfffffff8, %%esp\n"

        // prepare arguments for 64-bit mode
        // there are 4 arguments (including reserved)
        "\txor  %%eax, %%eax\n"
        "\tpush %%eax\n"
        "\tpush %[evmm_reserved]\n"
        "\tpush %%eax\n"
        "\tpush %[evmm_p_a0]\n"
        "\tpush %%eax\n"
        "\tpush %[p_startup_struct]\n"
        "\tpush %%eax\n"
        "\tpush %[local_apic_id]\n"

        // enable 64-bit mode
        // EFER MSR register
        "\tmovl $0x0c0000080, %%ecx\n"
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

        // mode switch
        "ljmp   $64, $1f\n"

"1:\n"
        // in 64 bit this is actually pop rdi (local apic)
        "\tpop %%edi\n"
        // in 64 bit this is actually pop rsi (startup struct)
        "\tpop %%esi\n"
        // in 64 bit this is actually pop rdx (application struct)
        "\tpop %%edx\n"
        // in 64 bit this is actually pop rcx (reserved)
        "\tpop %%ecx\n"

        "\tjmp *%%ebx\n"
        "\tud2\n"
    :: [vmm_main_entry_point] "m" (vmm_main_entry_point), 
       [evmm_bsp_stack] "m" (evmm_bsp_stack), [evmm64_cr3] "m" (evmm64_cr3),
       [evmm64_cs_selector] "m" (evmm64_cs_selector), 
       [evmm_reserved] "m" (evmm_reserved), 
       [evmm_p_a0] "m" (evmm_p_a0), [p_startup_struct] "m" (p_startup_struct),
       [local_apic_id] "m" (local_apic_id)
    :);

    return 0;
}

