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


// this is all 32 bit code

#include "vmm_defs.h"
typedef long long unsigned uint64_t;
typedef unsigned uint32_t;
typedef short unsigned uint16_t;
typedef unsigned char uint8_t;
typedef int bool;
typedef short unsigned u16;
typedef unsigned char u8;

#include "multiboot.h"
#include "elf_defns.h"
#include "tboot.h"
#include "e820.h"
#include "linux_defns.h"

#include "em64t_defs.h"
#include "ia32_defs.h"
#include "ia32_low_level.h"
#include "x32_init64.h"

#define PSE_BIT     0x10
#define PAE_BIT     0x20

#define PAGE_SIZE (1024 * 4)
UINT32  heap_base;
UINT32  heap_current;
UINT32  heap_tops;


// Rekha to put globals she needs here

static VMM_INPUT_PARAMS  input_params;
static VMM_INPUT_PARAMS  *pointer_to_input_params= &input_params;

static VMM_STARTUP_STRUCT startup_struct;
static VMM_STARTUP_STRUCT *pointer_to_startup_struct= &startup_struct;

multiboot_info_t *g_mbi= NULL;



void ia32_write_gdtr(IA32_GDTR *p_descriptor)
{
    asm volatile (
        "\tmovl  %[p_descriptor], %%edx\n"
        "\tlgdt  (%%edx)\n"
    : 
    : [p_descriptor] "m" (p_descriptor)
    : "%edx");
}


void ia32_write_cr3(UINT32 value)
{
    asm volatile (
        "\tmovl   %[value], %%eax\n"
        "\tmovl   %%eax, %%eax\n"
    : 
    : [value] "m" (value)
    : "%eax");
}

UINT32 ia32_read_cr4(void)
{
    asm volatile (
        "\t.byte( 0x0F)\n"
        "\t.byte( 0x20)\n"
        // mov eax, cr4
        "\t.byte( 0xE0)\n"
    : 
    :
    : "%eax");
}

void ia32_write_cr4(UINT32 value)
{
    asm volatile (
        "\tmovl    %[value],%%eax\n"
        "\t.byte( 0x0F)\n"
        "\t.byte( 0x22)\n"
        // mov cr4, eax
        "\t.byte( 0xE0)\n"
    : 
    : [value] "m" (value)
    : "%eax");
}

void ia32_write_msr(UINT32 msr_id, UINT64 *p_value)
{
    asm volatile (
        "\tmovl    %[p_value], %%ecx\n"
        "\tmovl    (%%ecx), %%eax\n"
        "\tmovl    4(%%ecx), %%edx\n"
        "\tmovl    %[msr_id], %%ecx\n"
        // write from EDX:EAX into MSR[ECX]
        "\twrmsr \n"
    : 
    : [msr_id] "m" (msr_id),  [p_value] "m" (p_value)
    : "%eax", "%ecx", "%edx");
}

//REK: START
VOID ZeroMem( VOID*   Address, UINT32  Size)
{
  UINT8* Source;

  Source = (UINT8*)Address;
  while (Size--) {
    *Source++ = 0;
  }
}

VOID* AllocateMemory( UINT32 size_request)
{
  UINT32 Address;

  if (heap_current + size_request > heap_tops) {
        /*
      printk("Allocation request exceeds heap's size\r\n");
      printk("Heap current = 0x", heap_current);
      printk("Requested size =0x", size_request);
      printk("Heap tops = 0x", heap_tops);
        */

    return NULL;
  }
  Address = heap_current;
  heap_current+=size_request;
  ZeroMem((VOID*)Address, size_request);
  return (VOID*)Address;
}


VOID InitializeMemoryManager(UINT64 * HeapBaseAddress, UINT64 *    HeapBytes)
{
  heap_current = heap_base = *(UINT32*)HeapBaseAddress;
  heap_tops = heap_base + *(UINT32*)HeapBytes;
}

VOID CopyMem( VOID *Dest, VOID *Source, UINT32 Size)
{
  UINT8 *d = (UINT8*)Dest;
  UINT8 *s = (UINT8*)Source;

  while (Size--) {
    *d++ = *s++;
  }
}

BOOLEAN CompareMem( VOID *Source1, VOID *Source2, UINT32 Size)
{
  UINT8 *s1 = (UINT8*)Source1;
  UINT8 *s2 = (UINT8*)Source2;

  while (Size--) {
    if (*s1++ != *s2++) {
    //      printk("Compare mem failed\n");
      return FALSE;
    }
  }
  return TRUE;
}

void * evmm_page_alloc(UINT32 pages)
{
    UINT32 address;
    UINT32 size = pages * PAGE_SIZE;

    address = ALIGN_FORWARD(heap_current, PAGE_SIZE);
    heap_current = address + size;
    ZeroMem((void*)address, size);
    return (void*)address;
}

static IA32_GDTR        gdtr_32;
static IA32_GDTR        gdtr_64;  // still in 32-bit mode
static UINT16           cs_64;

void  ia32_read_gdtr(IA32_GDTR *p_descriptor)
{
    asm volatile(
        "\n movl %[p_descriptor], %%edx"
        "\n\t sgdt (%%edx)"
    :[p_descriptor] "=g" (p_descriptor)
    :: "%edx");
}

void x32_gdt64_setup(void)
{
    EM64T_CODE_SEGMENT_DESCRIPTOR *p_gdt_64;
    UINT32 last_index;

    // allocate page for 64-bit GDT
    p_gdt_64 = evmm_page_alloc(1);  // 1 page should be sufficient ???
    // vmm_memset(p_gdt_64, 0, PAGE_4KB_SIZE);
    memset(p_gdt_64, 0, PAGE_4KB_SIZE);

    // read 32-bit GDTR
    ia32_read_gdtr(&gdtr_32);

    // clone it to the new 64-bit GDT
    // vmm_memcpy(p_gdt_64, (void *) gdtr_32.base, gdtr_32.limit+1);
    memcpy(p_gdt_64, (void *) gdtr_32.base, gdtr_32.limit+1);

    // build and append to GDT 64-bit mode code-segment entry
    // check if the last entry is zero, and if so, substitute it

    last_index = gdtr_32.limit / sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR);

    if (*(UINT64 *) &p_gdt_64[last_index] != 0) {
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
    p_gdt_64[last_index].hi.default_size= 0;        // important !!!
    p_gdt_64[last_index].hi.granularity= 1;

    // data segment for eVmm stacks
    p_gdt_64[last_index + 1].hi.accessed = 0;
    p_gdt_64[last_index + 1].hi.readable = 1;
    p_gdt_64[last_index + 1].hi.conforming = 0;
    p_gdt_64[last_index + 1].hi.mbo_11 = 0;
    p_gdt_64[last_index + 1].hi.mbo_12 = 1;
    p_gdt_64[last_index + 1].hi.dpl = 0;
    p_gdt_64[last_index + 1].hi.present = 1;
    p_gdt_64[last_index + 1].hi.long_mode = 1;    // important !!!
    p_gdt_64[last_index + 1].hi.default_size= 0;    // important !!!
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

static EM64T_CR3 cr3_for_x64 = { 0 };


/*---------------------------------------------------------*
*  FUNCTION             : x32_pt64_setup_paging
*  PURPOSE              : establish paging tables for x64 -bit mode, 2MB pages
*                               : while running in 32-bit mode.
*                               : It should scope full 32-bit space, i.e. 4G
*  ARGUMENTS    :
*  RETURNS              : void
*---------------------------------------------------------*/
void x32_pt64_setup_paging(UINT64 memory_size)
{
    EM64T_PML4      *pml4_table;
    EM64T_PDPE      *pdp_table;
    EM64T_PDE_2MB   *pd_table;

    UINT32 pdpt_entry_id;
    UINT32 pdt_entry_id;
    UINT32 address = 0;

    if (memory_size >= 0x100000000)
        memory_size = 0x100000000;

    // To cover 4G-byte addrerss space the minimum set is
    // PML4    - 1entry
    // PDPT    - 4 entries
    // PDT             - 2048 entries

    pml4_table = (EM64T_PML4 *) evmm_page_alloc(1);
    // vmm_memset(pml4_table, 0, PAGE_4KB_SIZE);
    memset(pml4_table, 0, PAGE_4KB_SIZE);

    pdp_table = (EM64T_PDPE *) evmm_page_alloc(1);
    // vmm_memset(pdp_table, 0, PAGE_4KB_SIZE);
    memset(pdp_table, 0, PAGE_4KB_SIZE);

    // only one  entry is enough in PML4 table
    pml4_table[0].lo.base_address_lo = (UINT32) pdp_table >> 12;
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
        // vmm_memset(pd_table, 0, PAGE_4KB_SIZE);
        memset(pd_table, 0, PAGE_4KB_SIZE);
        pdp_table[pdpt_entry_id].lo.base_address_lo = (UINT32) pd_table >> 12;

        for (pdt_entry_id = 0; pdt_entry_id < 512; ++pdt_entry_id, address += PAGE_2MB_SIZE) {
            pd_table[pdt_entry_id].lo.present       = 1;
            pd_table[pdt_entry_id].lo.rw            = 1;
            pd_table[pdt_entry_id].lo.us            = 0;
            pd_table[pdt_entry_id].lo.pwt           = 0;
            pd_table[pdt_entry_id].lo.pcd           = 0;
            pd_table[pdt_entry_id].lo.accessed  = 0;
            pd_table[pdt_entry_id].lo.dirty         = 0;
            pd_table[pdt_entry_id].lo.pse           = 1;
            pd_table[pdt_entry_id].lo.global        = 0;
            pd_table[pdt_entry_id].lo.avl           = 0;
            pd_table[pdt_entry_id].lo.pat           = 0;     //????
            pd_table[pdt_entry_id].lo.zeroes        = 0;
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
int jump_evmm_image(void *entry_point)
{
    __asm__ __volatile__ (
      "    jmp (%%ecx);    "
      "    ud2;           "
      :: "a" (MB_MAGIC), "b" (g_mbi), "c" (entry_point));

    return 1;
}
//REK: END


// void start_64bit_mode(
//      address MUST BE 32-bit wide, because it delivered to 64-bit code 
//      using 32-bit push/retf commands
//      __attribute__((cdecl)) 
void start_64bit_mode(UINT32 address, UINT32 segment, UINT32* arg1, 
                        UINT32* arg2, UINT32* arg3, UINT32* arg4)
{
    asm volatile (
        // prepare arguments for 64-bit mode
        // there are 3 arguments
        // align stack and push them on 8-byte alignment
        "\txor      %%eax, %%eax\n"
        "\tand      $7, %%esp\n"
        "\tpush     %%eax\n"
        "\tpush     %[arg4]\n"
        "\tpush     %%eax\n"
        "\tpush     %[arg3]\n"
        "\tpush     %%eax\n"
        "\tpush     %[arg2]\n"
        "\tpush     %%eax\n"
        "\tpush     %[arg1]\n"

        "\tcli\n"
        // push segment and offset
        "\tpush   %[segment]\n"

        // for following retf
        "\tpush  START64\n"
        "\tmov   %[address], %%ebx\n"

        // initialize CR3 with PML4 base
        // mov   eax, [esp+4]
        // mov   cr3, eax
        // enable 64-bit mode

        // EFER MSR register
        "\tmov      0x0C0000080, %%ecx\n"

        // read EFER into EAX
        "\trdmsr\n"

        // set EFER.LME=1
        "\tbts     $8, %%eax\n"

        // write EFER
        "\twrmsr\n"

        // enable paging CR0.PG=1
        "\tmov     %%cr0, %%eax\n"
        "\tbts     $31, %%eax\n"
        "\tmov     %%eax, %%cr0\n"

        // at this point we are in 32-bit compatibility mode
        // LMA=1, CS.L=0, CS.D=1
        // jump from 32bit compatibility mode into 64bit mode.
        "\tret\n"

"START64:\n"
        // in 64bit this is actually pop rcx
        "\tpop    %%ecx\n"
        // in 64bit this is actually pop rdx
        "\tpop    %%edx\n"

        "\t.byte  0x41\n"
        // pop r8
        "\t.byte  0x58\n"
        "\t.byte  0x41\n"
        // pop r9
        "\t.byte  0x59\n"
        // in 64bit this is actually sub  0x18, %%rsp
        "\t.byte 0x48\n"

        "\tsub    0x18, %%esp\n"
        // in 64bit this is actually
        "\tcall   %%ebx\n"

        : 
        : [arg1] "m" (arg1), [arg2] "m" (arg2), [arg3] "m" (arg3), [arg4] "m" (arg4), 
          [address] "m" (address), [segment] "m" (segment)
        : "%eax", "%ebx", "%ecx", "%edx");
}


void x32_init64_start( INIT64_STRUCT *p_init64_data, UINT32 address_of_64bit_code,
                      void * arg1, void * arg2, void * arg3, void * arg4)
{
    UINT32 cr4;

    ia32_write_gdtr(&p_init64_data->i64_gdtr);
    ia32_write_cr3(p_init64_data->i64_cr3);
    cr4 = ia32_read_cr4();
    BITMAP_SET(cr4, PAE_BIT | PSE_BIT);
    ia32_write_cr4(cr4);
    ia32_write_msr(0xC0000080, &p_init64_data->i64_efer);
    start_64bit_mode(address_of_64bit_code, p_init64_data->i64_cs, arg1, arg2, arg3, arg4);
}


void PrintMbi(const multiboot_info_t *mbi, tboot_printk myprintk)
{
    /* print mbi for debug */
    unsigned int i;

    myprintk("print mbi@%p ...\n", mbi);
    myprintk("\t flags: 0x%x\n", mbi->flags);
    if ( mbi->flags & MBI_MEMLIMITS )
        myprintk("\t mem_lower: %uKB, mem_upper: %uKB\n", mbi->mem_lower,
               mbi->mem_upper);
    if ( mbi->flags & MBI_BOOTDEV ) {
        myprintk("\t boot_device.bios_driver: 0x%x\n",
               mbi->boot_device.bios_driver);
        myprintk("\t boot_device.top_level_partition: 0x%x\n",
               mbi->boot_device.top_level_partition);
        myprintk("\t boot_device.sub_partition: 0x%x\n",
               mbi->boot_device.sub_partition);
        myprintk("\t boot_device.third_partition: 0x%x\n",
               mbi->boot_device.third_partition);
    }
    if ( mbi->flags & MBI_CMDLINE ) {
# define CHUNK_SIZE 72 
        /* Break the command line up into 72 byte chunks */
        int   cmdlen = strlen(mbi->cmdline);
        char *cmdptr = (char *)mbi->cmdline;
        char  chunk[CHUNK_SIZE+1];
        myprintk("\t cmdline@0x%x: ", mbi->cmdline);
        chunk[CHUNK_SIZE] = '\0';
        while (cmdlen > 0) {
            strncpy(chunk, cmdptr, CHUNK_SIZE); 
            myprintk("\n\t\"%s\"", chunk);
            cmdptr += CHUNK_SIZE;
            cmdlen -= CHUNK_SIZE;
        }
        myprintk("\n");
    }

    if ( mbi->flags & MBI_MODULES ) {
        myprintk("\t mods_count: %u, mods_addr: 0x%x\n", mbi->mods_count,
               mbi->mods_addr);
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
            myprintk("\t     %d : mod_start: 0x%x, mod_end: 0x%x\n", i,
                   p->mod_start, p->mod_end);
            myprintk("\t         string (@0x%x): \"%s\"\n", p->string,
                   (char *)p->string);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        myprintk("\t aout :: tabsize: 0x%x, strsize: 0x%x, addr: 0x%x\n",
               p->tabsize, p->strsize, p->addr);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        myprintk("\t elf :: num: %u, size: 0x%x, addr: 0x%x, shndx: 0x%x\n",
               p->num, p->size, p->addr, p->shndx);
    }
    if ( mbi->flags & MBI_MEMMAP ) {
        memory_map_t *p;
        myprintk("\t mmap_length: 0x%x, mmap_addr: 0x%x\n", mbi->mmap_length,
               mbi->mmap_addr);
        for ( p = (memory_map_t *)mbi->mmap_addr;
              (uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
              p=(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
                myprintk("\t     size: 0x%x, base_addr: 0x%04x%04x, "
                   "length: 0x%04x%04x, type: %u\n", p->size,
                   p->base_addr_high, p->base_addr_low,
                   p->length_high, p->length_low, p->type);
        }
    }
    if ( mbi->flags & MBI_DRIVES ) {
        myprintk("\t drives_length: %u, drives_addr: 0x%x\n", mbi->drives_length,
               mbi->drives_addr);
    }
    if ( mbi->flags & MBI_CONFIG ) {
        myprintk("\t config_table: 0x%x\n", mbi->config_table);
    }
    if ( mbi->flags & MBI_BTLDNAME ) {
        myprintk("\t boot_loader_name@0x%x: %s\n",
               mbi->boot_loader_name, (char *)mbi->boot_loader_name);
    }
    if ( mbi->flags & MBI_APM ) {
        myprintk("\t apm_table: 0x%x\n", mbi->apm_table);
    }
    if ( mbi->flags & MBI_VBE ) {
        myprintk("\t vbe_control_info: 0x%x\n"
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


// TODO(tmroeder): this should be the real base, but I want it to compile.
//uint64_t tboot_shared_page = 0;
// tboot jumps in here
int main(int an, char** av) {
    int i;

    // john's tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;
    tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;

    // john's g_mbi,  multiboot_info_t * my_mbi= 0x10000;
    multiboot_info_t * my_mbi= 0x10000;

    // john's boot_params boot_params_t *my_boot_params= 0x94200
    boot_params_t *my_boot_params= 0x94200;


    // toms: tboot_printk tprintk = (tboot_printk)(0x80d7f0);
    // john's: tboot_printk tprintk = (tboot_printk)(0x80d660);
    tboot_printk tprintk = (tboot_printk)(0x80d660);

    tprintk("<3>Testing printf\n");
    tprintk("<3>evmm entry %d arguments\n", an);
    if(an<10) {
        // this only works for the lunux type, not elf
        for(i=0; i<an; i++) {
            tprintk("av[%d]= %d\n", av[i]);
        }
    }
    
    // shared page
    tprintk("shared_page data:\n");
    tprintk("\t version: %d\n", shared_page->version);
    tprintk("\t log_addr: 0x%08x\n", shared_page->log_addr);
    tprintk("\t shutdown_entry: 0x%08x\n", shared_page->shutdown_entry);
    tprintk("\t shutdown_type: %d\n", shared_page->shutdown_type);
    tprintk("\t tboot_base: 0x%08x\n", shared_page->tboot_base);
    tprintk("\t tboot_size: 0x%x\n", shared_page->tboot_size);
    tprintk("\t num_in_wfs: %u\n", shared_page->num_in_wfs);
    tprintk("\t flags: 0x%8.8x\n", shared_page->flags);
    tprintk("\t ap_wake_addr: 0x%08x\n", (uint32_t)shared_page->ap_wake_addr);
    tprintk("\t ap_wake_trigger: %u\n", shared_page->ap_wake_trigger);

    // mbi
    PrintMbi(my_mbi, tprintk);
    // my_mbi->mmap_addr; my_mbi->mmap_length;
    int l= my_mbi->mmap_length/sizeof(memory_map_t);
    tprintk("%d e820 entries\n", l);
    uint32_t entry_offset = 0;
    i= 0;
    while ( entry_offset < my_mbi->mmap_length ) {
        memory_map_t *entry = (memory_map_t *) (my_mbi->mmap_addr + entry_offset);
        tprintk("entry %02d: size: %08x, addr_low: %08x, addr_high: %08x\n  len_low: %08x, len_high: %08x, type: %08x\n",
                i, entry->size, entry->base_addr_low, entry->base_addr_high,
                entry->length_low, entry->length_high, entry->type);
        i++;
        entry_offset += entry->size + sizeof(entry->size);
    }
    tprintk("%d total\n", l);

    // TODO(tmroeder): remove this debugging while loop later
    while(1) ;

    // setup gdt? (for 64-bit)

    // flip into 64 bit mode

    // set up evmm stack 

    // set up evmm heap

    // set up evmm_main call stack

    // get evmm_main entry point

    // jump to evmm_main
    // int evmm_main (multiboot_info_t *evmm_mbi, const void *elf_image, int size) 
    // jump_evmm_image(void *entry_point)
}

