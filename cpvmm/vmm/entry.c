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


#if 0
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
#endif


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
#endif


typedef void (*tboot_printk)(const char *fmt, ...);
// TODO(tmroeder): this should be the real base, but I want it to compile.
//uint64_t tboot_shared_page = 0;
// tboot jumps in here
int main(int an, char** av) {
    int i;

    // john's tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;
    tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;

    // toms: tboot_printk tprintk = (tboot_printk)(0x80d7f0);
    // john's: tboot_printk tprintk = (tboot_printk)(0x80d630);
    tboot_printk tprintk = (tboot_printk)(0x80d630);

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
    // mbi pointer is passed in begin_launch in tboot
    //     pass address in main arguments?

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

#if 0


typedef struct
{
    INIT32_STRUCT s;
    UINT32 data[32];
} INIT32_STRUCT_SAFE;


#define get_e820_table get_e820_table_from_multiboot

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

    while (1) ;
}
#endif 

