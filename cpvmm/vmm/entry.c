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

#include "vmm_defs.h"
typedef long long unsigned uint64_t;
typedef unsigned uint32_t;
typedef short unsigned uint16_t;
typedef unsigned char uint8_t;
typedef int bool;
#include "multiboot.h"
#include "elf_defns.h"
#include "tboot.h"

// this is all 32 bit code

// implement transition to 64-bit execution mode

#include "ia32_low_level.h"
#include "x32_init64.h"

#define PSE_BIT     0x10
#define PAE_BIT     0x20


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


int jump_evmm_image(void *entry_point)
{
    __asm__ __volatile__ (
      "    jmp (%%ecx);    "
      "    ud2;           "
      :: "a" (MB_MAGIC), "b" (g_mbi), "c" (entry_point));

    return 1;
}


// void __cdecl start_64bit_mode(
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


#ifdef PRINTALL
void PrintMbi(const multiboot_info_t *mbi)
{
    /* print mbi for debug */
    unsigned int i;

    printk("print mbi@%p ...\n", mbi);
    printk("\t flags: 0x%x\n", mbi->flags);
    if ( mbi->flags & MBI_MEMLIMITS )
        printk("\t mem_lower: %uKB, mem_upper: %uKB\n", mbi->mem_lower,
               mbi->mem_upper);
    if ( mbi->flags & MBI_BOOTDEV ) {
        printk("\t boot_device.bios_driver: 0x%x\n",
               mbi->boot_device.bios_driver);
        printk("\t boot_device.top_level_partition: 0x%x\n",
               mbi->boot_device.top_level_partition);
        printk("\t boot_device.sub_partition: 0x%x\n",
               mbi->boot_device.sub_partition);
        printk("\t boot_device.third_partition: 0x%x\n",
               mbi->boot_device.third_partition);
    }
    if ( mbi->flags & MBI_CMDLINE ) {
# define CHUNK_SIZE 72 
        /* Break the command line up into 72 byte chunks */
        int   cmdlen = strlen(mbi->cmdline);
        char *cmdptr = (char *)mbi->cmdline;
        char  chunk[CHUNK_SIZE+1];
        printk("\t cmdline@0x%x: ", mbi->cmdline);
        chunk[CHUNK_SIZE] = '\0';
        while (cmdlen > 0) {
            strncpy(chunk, cmdptr, CHUNK_SIZE); 
            printk("\n\t\"%s\"", chunk);
            cmdptr += CHUNK_SIZE;
            cmdlen -= CHUNK_SIZE;
        }
        printk("\n");
    }

    if ( mbi->flags & MBI_MODULES ) {
        printk("\t mods_count: %u, mods_addr: 0x%x\n", mbi->mods_count,
               mbi->mods_addr);
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
            printk("\t     %d : mod_start: 0x%x, mod_end: 0x%x\n", i,
                   p->mod_start, p->mod_end);
            printk("\t         string (@0x%x): \"%s\"\n", p->string,
                   (char *)p->string);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        printk("\t aout :: tabsize: 0x%x, strsize: 0x%x, addr: 0x%x\n",
               p->tabsize, p->strsize, p->addr);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        printk("\t elf :: num: %u, size: 0x%x, addr: 0x%x, shndx: 0x%x\n",
               p->num, p->size, p->addr, p->shndx);
    }
    if ( mbi->flags & MBI_MEMMAP ) {
        memory_map_t *p;
        printk("\t mmap_length: 0x%x, mmap_addr: 0x%x\n", mbi->mmap_length,
               mbi->mmap_addr);
        for ( p = (memory_map_t *)mbi->mmap_addr;
              (uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
              p=(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
	        printk("\t     size: 0x%x, base_addr: 0x%04x%04x, "
                   "length: 0x%04x%04x, type: %u\n", p->size,
                   p->base_addr_high, p->base_addr_low,
                   p->length_high, p->length_low, p->type);
        }
    }
    if ( mbi->flags & MBI_DRIVES ) {
        printk("\t drives_length: %u, drives_addr: 0x%x\n", mbi->drives_length,
               mbi->drives_addr);
    }
    if ( mbi->flags & MBI_CONFIG ) {
        printk("\t config_table: 0x%x\n", mbi->config_table);
    }
    if ( mbi->flags & MBI_BTLDNAME ) {
        printk("\t boot_loader_name@0x%x: %s\n",
               mbi->boot_loader_name, (char *)mbi->boot_loader_name);
    }
    if ( mbi->flags & MBI_APM ) {
        printk("\t apm_table: 0x%x\n", mbi->apm_table);
    }
    if ( mbi->flags & MBI_VBE ) {
        printk("\t vbe_control_info: 0x%x\n"
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


void print_shared(const tboot_shared_t *tboot_shared)
{
    printk("tboot_shared data:\n");
    printk("\t version: %d\n", tboot_shared->version);
    printk("\t log_addr: 0x%08x\n", tboot_shared->log_addr);
    printk("\t shutdown_entry: 0x%08x\n", tboot_shared->shutdown_entry);
    printk("\t shutdown_type: %d\n", tboot_shared->shutdown_type);
    printk("\t tboot_base: 0x%08x\n", tboot_shared->tboot_base);
    printk("\t tboot_size: 0x%x\n", tboot_shared->tboot_size);
    printk("\t num_in_wfs: %u\n", tboot_shared->num_in_wfs);
    printk("\t flags: 0x%8.8x\n", tboot_shared->flags);
    printk("\t ap_wake_addr: 0x%08x\n", (uint32_t)tboot_shared->ap_wake_addr);
    printk("\t ap_wake_trigger: %u\n", tboot_shared->ap_wake_trigger);
}
#endif


typedef void (*tboot_printk)(const char *fmt, ...);
// TODO(tmroeder): this should be the real base, but I want it to compile.
//uint64_t tboot_shared_page = 0;
// tboot jumps in here
int main(int an, char** av) {
    int i;

    //tboot_shared_t *shared_page = (tboot_shared_t *)(tboot_shared_page);
    // toms: tboot_printk tprintk = (tboot_printk)(0x80d7f0);
    // john's: tboot_printk tprintk = (tboot_printk)(0x80d630);
    tboot_printk tprintk = (tboot_printk)(0x80d630);

    tprintk("<3>Testing printf\n");
    tprintk("<3>evmm entry %d arguments\n", an);
    for(i=0; i<an; i++) {
        tprintk("av[%d]= %d\n", av[i]);
    }
    
    // shared page

    // mbi
    // mbi pointer is passed in begin_launch in tboot
    //     pass address in main arguments?

    // TODO(tmroeder): remove this debugging while loop later
    while(1) ;

    // setup gdt?

    // flip into 64 bit mode

    // set up evmm stack 

    // set up evmm heap

    // set up evmm_main call stack

    // get evmm_main entry point

    // jump to evmm_main
    // int evmm_main (multiboot_info_t *evmm_mbi, const void *elf_image, int size) 
    // jump_evmm_image(void *entry_point)
}

