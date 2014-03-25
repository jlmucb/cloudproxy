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
typedef short unsigned u16;
typedef unsigned char u8;
typedef int bool;

#include "multiboot.h"
#include "elf_defns.h"
#include "elf64.h"
#include "tboot.h"
#include "e820.h"
#include "linux_defns.h"

#include "em64t_defs.h"
#include "ia32_defs.h"
#include "ia32_low_level.h"
#include "x32_init64.h"
#include "vmm_startup.h"

#define JLMDEBUG

#define PSE_BIT     0x10
#define PAE_BIT     0x20

#define PAGE_SIZE   (1024 * 4) 
#define PAGE_MASK   (~(PAGE_SIZE-1))

#define MAX_E820_ENTRIES PAGE_SIZE/sizeof(INT15_E820_MEMORY_MAP)
#define UUID 0x1badb002

void _mystart()
{
}

// IA-32 Interrupt Descriptor Table - Gate Descriptor 
typedef struct { 
    UINT32  OffsetLow:16;   // Offset bits 15..0 
    UINT32  Selector:16;    // Selector 
    UINT32  Reserved_0:8;   // Reserved
    UINT32  GateType:8;     // Gate Type.  See #defines above
    UINT32  OffsetHigh:16;  // Offset bits 31..16
} IA32_IDT_GATE_DESCRIPTOR;

// Descriptor for the Global Descriptor Table(GDT) and Interrupt Descriptor Table(IDT)
typedef struct {
  UINT16  Limit;
  UINT32  Base;
} IA32_DESCRIPTOR;

typedef struct {
    INIT32_STRUCT s;
    UINT32 data[32];
} INIT32_STRUCT_SAFE;

typedef enum {
  Ia32ExceptionVectorDivideError,
  Ia32ExceptionVectorDebugBreakPoint,
  Ia32ExceptionVectorNmi,
  Ia32ExceptionVectorBreakPoint,
  Ia32ExceptionVectorOverflow,
  Ia32ExceptionVectorBoundRangeExceeded,
  Ia32ExceptionVectorUndefinedOpcode,
  Ia32ExceptionVectorNoMathCoprocessor,
  Ia32ExceptionVectorDoubleFault,
  Ia32ExceptionVectorReserved0x09,
  Ia32ExceptionVectorInvalidTaskSegmentSelector,
  Ia32ExceptionVectorSegmentNotPresent,
  Ia32ExceptionVectorStackSegmentFault,
  Ia32ExceptionVectorGeneralProtectionFault,
  Ia32ExceptionVectorPageFault,
  Ia32ExceptionVectorReserved0x0F,
  Ia32ExceptionVectorMathFault,
  Ia32ExceptionVectorAlignmentCheck,
  Ia32ExceptionVectorMachineCheck,
  Ia32ExceptionVectorSimdFloatingPointNumericError,
  Ia32ExceptionVectorReservedSimdFloatingPointNumericError,
  Ia32ExceptionVectorReserved0x14,
  Ia32ExceptionVectorReserved0x15,
  Ia32ExceptionVectorReserved0x16,
  Ia32ExceptionVectorReserved0x17,
  Ia32ExceptionVectorReserved0x18,
  Ia32ExceptionVectorReserved0x19,
  Ia32ExceptionVectorReserved0x1A,
  Ia32ExceptionVectorReserved0x1B,
  Ia32ExceptionVectorReserved0x1C,
  Ia32ExceptionVectorReserved0x1D,
  Ia32ExceptionVectorReserved0x1E,
  Ia32ExceptionVectorReserved0x1F
} IA32_EXCEPTION_VECTORS;

// Ring 0 Interrupt Descriptor Table - Gate Types
#define IA32_IDT_GATE_TYPE_TASK          0x85
#define IA32_IDT_GATE_TYPE_INTERRUPT_16  0x86
#define IA32_IDT_GATE_TYPE_TRAP_16       0x87
#define IA32_IDT_GATE_TYPE_INTERRUPT_32  0x8E
#define IA32_IDT_GATE_TYPE_TRAP_32       0x8F

#define HEAP_SIZE 0X100000
#define HEAP_BASE 0Xa0000000 - HEAP_SIZE

// TOTAL_MEM is a  max of 4G because we start in 32-bit mode
#define TOTAL_MEM 0x100000000 
#define IDT_VECTOR_COUNT 256
#define LVMM_CS_SELECTOR 0x10

#define EVMM_DEFAULT_START_ADDR 0xa0000000 
#define LINUX_DEFAULT_LOAD_ADDRESS 0x100000

#define LOOP_FOREVER while(1);

typedef struct VMM_INPUT_PARAMS_S {
    UINT64 local_apic_id;
    UINT64 startup_struct;
    UINT64 guest_params_struct; // change name
} VMM_INPUT_PARAMS;


//  Globals

IA32_IDT_GATE_DESCRIPTOR                LvmmIdt[IDT_VECTOR_COUNT];
IA32_DESCRIPTOR                         IdtDescriptor;

static IA32_GDTR                        gdtr_32;
static IA32_GDTR                        gdtr_64;  // still in 32-bit mode
static UINT16                           cs_64= 0;
static UINT32                           p_cr4= 0;

static VMM_INPUT_PARAMS                 input_params;
static VMM_INPUT_PARAMS*                pointer_to_input_params= &input_params;
static UINT64                           evmm_reserved = 0;
static UINT32                           local_apic_id = 0;
static VMM_STARTUP_STRUCT               startup_struct;
static VMM_STARTUP_STRUCT *             p_startup_struct = &startup_struct;
static EM64T_CODE_SEGMENT_DESCRIPTOR*   p_gdt_64= NULL;
static UINT32*                          p_evmm_stack= NULL;
static EM64T_PML4 *                     pml4_table= NULL;
static EM64T_PDPE *                     pdp_table= NULL;
static EM64T_PDE_2MB *                  pd_table= NULL;

int                                     evmm_num_of_aps= 0;
UINT32                                  low_mem = 0x8000;

static INIT64_STRUCT                    init64;
static INIT64_STRUCT *                  p_init64_data = &init64;
static INIT32_STRUCT_SAFE               init32;
VMM_GUEST_STARTUP                       evmm_g0;
VMM_MEMORY_LAYOUT *                     evmm_vmem= NULL;
VMM_APPLICATION_PARAMS_STRUCT           evmm_a0;
VMM_APPLICATION_PARAMS_STRUCT*          evmm_p_a0= &evmm_a0;


// Hack!  Temporary  hacked info
// john's: tboot_printk tprintk = (tboot_printk)(0x80d660);
// tboot_printk tprintk = (tboot_printk)(0x80d660);
// john's tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;
// john's boot_params boot_params_t *my_boot_params= 0x94200
// boot_params_t *my_boot_params= (boot_params_t *)0x94200;
// john's g_mbi,  multiboot_info_t * my_mbi= 0x10000;
// multiboot_info_t * my_mbi= (multiboot_info_t *)0x10000;
typedef void (*tboot_printk)(const char *fmt, ...);
tboot_printk tprintk = (tboot_printk)(0x80d660);
tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;

// Memory layout on start32_evmm entry
uint32_t bootstrap_start= 0;    // this is the bootstrap image start address
uint32_t bootstrap_end= 0;      // this is the bootstrap image end address
uint32_t evmm_start= 0;         // location of evmm start
uint32_t evmm_end= 0;           // location of evmm image start
uint32_t linux_start= 0;        // location of linux imag start
uint32_t linux_end= 0;          // location of evmm start
uint32_t initram_start= 0;      // location of initram image start
uint32_t initram_end= 0;        // location of initram image end

// Post relocation addresses
uint32_t evmm_start_address= 0;         // this is the address of evmm after relocation (0x0e00...)
uint32_t vmm_main_entry_point= 0;       // address of vmm_main
uint32_t evmm_heap_base= 0;             // start of initial evmm heap
uint32_t evmm_heap_current= 0; 
uint32_t evmm_heap_top= 0;
uint32_t evmm_heap_size= 0;             // size of initial evmm heap

// expanded e820 table used be evmm
static unsigned int     evmm_num_e820_entries = 0;
INT15_E820_MEMORY_MAP * evmm_e820= NULL;                // address of expanded e820 table for evmm
UINT64                  evmm_start_of_e820_table= 0ULL; // same but 64 bits

uint32_t linux_start_address= 0;   // this is the address of the linux protected mode image
uint32_t initram_start_address= 0; // this is the address of the initram for linux
uint32_t linux_entry_address= 0;   // this is the address of the eip in the guest
uint32_t linux_esi_register= 0;    // this is the value of the esi register on guest entry
uint32_t linux_esp_register= 0;    // this is the value of the esp on entry to the guest linux
uint32_t linux_stack_base= 0;      // this is the base of the stack on entry to linux
uint32_t linux_stack_size= 0;      // this is the size of the stack that the linux guest has

// new boot parameters for linux guest
uint32_t linux_boot_params= 0;



void *vmm_memset(void *dest, int val, UINT32 count)
{
    asm volatile(
        "\n movl %[dest], %%edi"
        "\n\t movl %[val], %%eax"
        "\n\t movl %[count], %%ecx"
        "\n\t cld"
        "\n\t rep stosb"
    :[dest] "+g" (dest)
    :[val] "g" (val), [count] "g" (count) :);
    return dest;
}

void *vmm_memcpy(void *dest, const void* src, UINT32 count)
{
    asm volatile(
        "\n movl %[src], %%esi"
        "\n movl %[dest], %%edi"
        "\n\t movl %[count], %%ecx"
        "\n\t cld"
        "\n\t rep stosb"
    :[dest] "+g" (dest)
    :[src] "g" (src), [count] "g" (count) :);
    return dest;
}

UINT32 vmm_strlen(const char* p)
{
    UINT32 count= 0;
    if(p==NULL)
        return 0;
    while(*p!=0)
        count++;
    return count;
}


void InitializeMemoryManager(UINT32 heap_base_address, UINT32 heap_bytes)
{
    evmm_heap_current = evmm_heap_base = heap_base_address;
    evmm_heap_top = evmm_heap_base + heap_bytes;
}


void *evmm_page_alloc(UINT32 pages)
{
    UINT32 address;
    UINT32 size = pages * PAGE_SIZE;

    address = ALIGN_FORWARD(evmm_heap_current, PAGE_SIZE);
    evmm_heap_current = address + size;
    vmm_memset((void*)address, 0, size);
    return (void*)address;
}


void ExceptionHandlerReserved(UINT32 Cs, UINT32 Eip)
{
    // PrintExceptionHeader(Cs, Eip);
    tprintk("Reserved exception\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerDivideError(UINT32 Cs, UINT32 Eip)
{
    tprintk("Divide error\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerDebugBreakPoint(UINT32 Cs, UINT32 Eip)
{
    // PrintExceptionHeader(Cs, Eip);
    tprintk("Debug breakpoint\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerNmi(UINT32 Cs, UINT32 Eip)
{
    tprintk("NMI\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerBreakPoint(UINT32 Cs, UINT32 Eip)
{
    tprintk("Breakpoint\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerOverflow(UINT32 Cs, UINT32 Eip)
{
    tprintk("Overflow\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerBoundRangeExceeded(UINT32 Cs, UINT32 Eip)
{
    tprintk("Bound range exceeded\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerUndefinedOpcode(UINT32 Cs, UINT32 Eip)
{
    tprintk("Undefined opcode\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerNoMathCoprocessor(UINT32 Cs, UINT32 Eip)
{
    tprintk("No math coprocessor\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerDoubleFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    tprintk("Double fault\n");
    // No need to print error code here because it is always zero
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerInvalidTaskSegmentSelector(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    tprintk("Invalid task segment selector\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerSegmentNotPresent(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    tprintk("Segment not present\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerStackSegmentFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    tprintk("Stack segment fault\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerGeneralProtectionFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    tprintk("General protection fault\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerPageFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    UINT32 Cr2;

    asm volatile(
        "\npush %%eax"
        "\n\tmovl %%cr2, %%eax"
        "\n\tmovl %%eax, %[Cr2]"
        "\n\tpop %%eax"
    :[Cr2] "=g" (Cr2)
    ::"%eax");
    tprintk("Page fault\n");
    tprintk("Faulting address %x",Cr2);
    tprintk("\n");

    // TODO: need a specific error code print function here
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerMathFault(UINT32 Cs, UINT32 Eip)
{
    tprintk("Math fault\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerAlignmentCheck(UINT32 Cs, UINT32 Eip)
{
    tprintk("Alignment check\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerMachineCheck(UINT32 Cs, UINT32 Eip)
{
    tprintk("Machine check\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerSimdFloatingPointNumericError(UINT32 Cs, UINT32 Eip)
{
    tprintk("SIMD floating point numeric error\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerReservedSimdFloatingPointNumericError(UINT32 Cs, UINT32 Eip)
{
    tprintk("Reserved SIMD floating point numeric error\n");
    VMM_UP_BREAKPOINT();
}

void InstallExceptionHandler(UINT32 ExceptionIndex, UINT32 HandlerAddr)
{
    LvmmIdt[ExceptionIndex].OffsetLow  = HandlerAddr & 0xFFFF;
    LvmmIdt[ExceptionIndex].OffsetHigh = HandlerAddr >> 16;
}

void SetupIDT()
{
    int i;

    UINT32  pIdtDescriptor;

    tprintk("SetupIdt called\n");
    vmm_memset(&LvmmIdt, 0, sizeof(LvmmIdt));

    for (i = 0 ; i < 32 ; i++) {
        LvmmIdt[i].GateType = IA32_IDT_GATE_TYPE_INTERRUPT_32;
        LvmmIdt[i].Selector = LVMM_CS_SELECTOR;
        LvmmIdt[i].Reserved_0 = 0;
        InstallExceptionHandler(i, (UINT32)(ExceptionHandlerReserved));
    }

    InstallExceptionHandler(Ia32ExceptionVectorDivideError,
                            (UINT32)ExceptionHandlerDivideError);
    InstallExceptionHandler(Ia32ExceptionVectorDebugBreakPoint,
                            (UINT32)ExceptionHandlerDebugBreakPoint);
    InstallExceptionHandler(Ia32ExceptionVectorNmi,
                            (UINT32)ExceptionHandlerNmi);
    InstallExceptionHandler(Ia32ExceptionVectorBreakPoint,
                            (UINT32)ExceptionHandlerBreakPoint);
    InstallExceptionHandler(Ia32ExceptionVectorOverflow,
                            (UINT32)ExceptionHandlerOverflow);
    InstallExceptionHandler(Ia32ExceptionVectorBoundRangeExceeded,
                            (UINT32)ExceptionHandlerBoundRangeExceeded);
    InstallExceptionHandler(Ia32ExceptionVectorUndefinedOpcode,
                            (UINT32)ExceptionHandlerUndefinedOpcode);
    InstallExceptionHandler(Ia32ExceptionVectorNoMathCoprocessor,
                            (UINT32)ExceptionHandlerNoMathCoprocessor);
    InstallExceptionHandler(Ia32ExceptionVectorDoubleFault,
                            (UINT32)ExceptionHandlerDoubleFault);
    InstallExceptionHandler(Ia32ExceptionVectorInvalidTaskSegmentSelector,
                            (UINT32)ExceptionHandlerInvalidTaskSegmentSelector);
    InstallExceptionHandler(Ia32ExceptionVectorSegmentNotPresent,
                            (UINT32)ExceptionHandlerSegmentNotPresent);
    InstallExceptionHandler(Ia32ExceptionVectorStackSegmentFault,
                            (UINT32)ExceptionHandlerStackSegmentFault);
    InstallExceptionHandler(Ia32ExceptionVectorStackSegmentFault,
                            (UINT32)ExceptionHandlerStackSegmentFault);
    InstallExceptionHandler(Ia32ExceptionVectorGeneralProtectionFault,
                            (UINT32)ExceptionHandlerGeneralProtectionFault);
    InstallExceptionHandler(Ia32ExceptionVectorPageFault,
                            (UINT32)ExceptionHandlerPageFault);
    InstallExceptionHandler(Ia32ExceptionVectorMathFault,
                            (UINT32)ExceptionHandlerMathFault);
    InstallExceptionHandler(Ia32ExceptionVectorAlignmentCheck,
                            (UINT32)ExceptionHandlerAlignmentCheck);
    InstallExceptionHandler(Ia32ExceptionVectorMachineCheck,
                            (UINT32)ExceptionHandlerMachineCheck);
    InstallExceptionHandler(Ia32ExceptionVectorSimdFloatingPointNumericError,
                            (UINT32)ExceptionHandlerSimdFloatingPointNumericError);
    InstallExceptionHandler(Ia32ExceptionVectorReservedSimdFloatingPointNumericError,
                            (UINT32)ExceptionHandlerReservedSimdFloatingPointNumericError);

    IdtDescriptor.Base = (UINT32)(LvmmIdt);
    IdtDescriptor.Limit = sizeof(IA32_IDT_GATE_DESCRIPTOR) * 32 - 1;

    pIdtDescriptor = (UINT32)&IdtDescriptor;
    asm volatile(
        "\nmovl   %%eax, %[pIdtDescriptor]"
        "\n\tlidt  (%%edx)"
    :[pIdtDescriptor] "+g" (pIdtDescriptor)
    :: "%edx");
}


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

void  ia32_write_cr3(UINT32 value)
{
    asm volatile(
        "\n movl %[value], %%eax \n\t"
        "\n\t movl %%eax, %%cr3"
    ::[value] "m" (value)
    : "%eax", "cc");
}

UINT32  ia32_read_cr4(void)
{
    UINT32 ret;
    asm volatile(
        "\n .byte 0x0F"
        "\n\t .byte 0x20"
        "\n\t .byte 0xE0"       //mov eax, cr4
        "\n\t movl %%eax, %[ret]"
    :[ret] "=m" (ret) 
    :: "%eax");
    return ret;
}

void  ia32_write_cr4(UINT32 value)
{
    asm volatile(
        "\n movl %[value], %%eax"
        "\n\t .byte 0x0F"
        "\n\t .byte 0x22"
        "\n\t .byte 0xE0"       //mov cr4, eax
    ::[value] "m" (value)
    :"%eax");
}

void  ia32_write_msr(UINT32 msr_id, UINT64 *p_value)
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
    p_evmm_stack = (UINT32 *) p_gdt_64 + (UVMM_DEFAULT_STACK_SIZE_PAGES * PAGE_4KB_SIZE);
}

void x32_gdt64_setup(void)
{
    UINT32 last_index;
    // RNB: 1 page for code segment, and the rest for stack
    p_gdt_64 = (EM64T_CODE_SEGMENT_DESCRIPTOR *)evmm_page_alloc (1 + 
                        UVMM_DEFAULT_STACK_SIZE_PAGES);

    vmm_memset(p_gdt_64, 0, PAGE_4KB_SIZE);

    // read 32-bit GDTR
    ia32_read_gdtr(&gdtr_32);

    // clone it to the new 64-bit GDT
     vmm_memcpy(p_gdt_64, (void *) gdtr_32.base, gdtr_32.limit+1);

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
    p_gdt_64[last_index].hi.default_size= 0;  // important !!!
    p_gdt_64[last_index].hi.granularity= 1;

    // prepare GDTR
    gdtr_64.base  = (UINT32) p_gdt_64;
    // !!! TBD !!! will be extended by TSS
    gdtr_64.limit = gdtr_32.limit + sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR) * 2; 
    cs_64 = last_index * sizeof(EM64T_CODE_SEGMENT_DESCRIPTOR) ;
}

void x32_gdt64_load(void)
{
    ia32_write_gdtr(&gdtr_64);
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

//  x32_pt64_setup_paging: establish paging tables for x64 -bit mode, 
//     2MB pages while running in 32-bit mode.
//     It should scope full 32-bit space, i.e. 4G
void x32_pt64_setup_paging(UINT64 memory_size)
{
    UINT32 pdpt_entry_id;
    UINT32 pdt_entry_id;
    UINT32 address = 0;

    if (memory_size >= 0x100000000)
        memory_size = 0x100000000;

    // To cover 4G-byte addrerss space the minimum set is
    // PML4    - 1entry
    // PDPT    - 4 entries
    // PDT     - 2048 entries
    pml4_table = (EM64T_PML4 *) evmm_page_alloc(1);
    vmm_memset(pml4_table, 0, PAGE_4KB_SIZE);
    //memset(pml4_table, 0, PAGE_4KB_SIZE);

    pdp_table = (EM64T_PDPE *) evmm_page_alloc(1);
    vmm_memset(pdp_table, 0, PAGE_4KB_SIZE);

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
        vmm_memset(pd_table, 0, PAGE_4KB_SIZE);
        pdp_table[pdpt_entry_id].lo.base_address_lo = (UINT32) pd_table >> 12;

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


#ifdef JLMDEBUG
void PrintMbi(const multiboot_info_t *mbi)
{
    /* print mbi for debug */
    unsigned int i;

    tprintk("print mbi@%p ...\n", mbi);
    tprintk("\t flags: 0x%x\n", mbi->flags);
    if ( mbi->flags & MBI_MEMLIMITS )
        tprintk("\t mem_lower: %uKB, mem_upper: %uKB\n", mbi->mem_lower,
               mbi->mem_upper);
    if ( mbi->flags & MBI_BOOTDEV ) {
        tprintk("\t boot_device.bios_driver: 0x%x\n",
               mbi->boot_device.bios_driver);
        tprintk("\t boot_device.top_level_partition: 0x%x\n",
               mbi->boot_device.top_level_partition);
        tprintk("\t boot_device.sub_partition: 0x%x\n",
               mbi->boot_device.sub_partition);
        tprintk("\t boot_device.third_partition: 0x%x\n",
               mbi->boot_device.third_partition);
    }
    if ( mbi->flags & MBI_CMDLINE ) {
#define CHUNK_SIZE 72 
#if 0
        /* Break the command line up into 72 byte chunks */
        int   cmdlen = strlen((char*)mbi->cmdline);
        char *cmdptr = (char *)mbi->cmdline;
        char  chunk[CHUNK_SIZE+1];
        tprintk("\t cmdline@0x%x: ", mbi->cmdline);
        chunk[CHUNK_SIZE] = '\0';
        while (cmdlen > 0) {
            strncpy(chunk, cmdptr, CHUNK_SIZE); 
            tprintk("\n\t\"%s\"", chunk);
            cmdptr += CHUNK_SIZE;
            cmdlen -= CHUNK_SIZE;
        }
#endif
        tprintk("\n");
    }

    if ( mbi->flags & MBI_MODULES ) {
        tprintk("\t mods_count: %u, mods_addr: 0x%x\n", mbi->mods_count,
               mbi->mods_addr);
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
            tprintk("\t     %d : mod_start: 0x%x, mod_end: 0x%x\n", i,
                   p->mod_start, p->mod_end);
            tprintk("\t         string (@0x%x): \"%s\"\n", p->string,
                   (char *)p->string);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        tprintk("\t aout :: tabsize: 0x%x, strsize: 0x%x, addr: 0x%x\n",
               p->tabsize, p->strsize, p->addr);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        tprintk("\t elf :: num: %u, size: 0x%x, addr: 0x%x, shndx: 0x%x\n",
               p->num, p->size, p->addr, p->shndx);
    }
    if ( mbi->flags & MBI_MEMMAP ) {
        memory_map_t *p;
        tprintk("\t mmap_length: 0x%x, mmap_addr: 0x%x\n", mbi->mmap_length,
               mbi->mmap_addr);
        for ( p = (memory_map_t *)mbi->mmap_addr;
              (uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
              p=(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
                tprintk("\t     size: 0x%x, base_addr: 0x%04x%04x, "
                   "length: 0x%04x%04x, type: %u\n", p->size,
                   p->base_addr_high, p->base_addr_low,
                   p->length_high, p->length_low, p->type);
        }
    }
    if ( mbi->flags & MBI_DRIVES ) {
        tprintk("\t drives_length: %u, drives_addr: 0x%x\n", mbi->drives_length,
               mbi->drives_addr);
    }
    if ( mbi->flags & MBI_CONFIG ) {
        tprintk("\t config_table: 0x%x\n", mbi->config_table);
    }
    if ( mbi->flags & MBI_BTLDNAME ) {
        tprintk("\t boot_loader_name@0x%x: %s\n",
               mbi->boot_loader_name, (char *)mbi->boot_loader_name);
    }
    if ( mbi->flags & MBI_APM ) {
        tprintk("\t apm_table: 0x%x\n", mbi->apm_table);
    }
    if ( mbi->flags & MBI_VBE ) {
        tprintk("\t vbe_control_info: 0x%x\n"
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
        tprintk("Error: mbi pointer is zero.\n");
        return NULL;
    }

    if ( i >= mbi->mods_count ) {
        tprintk("invalid module #\n");
        return NULL;
    }

    return (module_t *)(mbi->mods_addr + i * sizeof(module_t));
}


static UINT64 get_e820_table(const multiboot_info_t *mbi) 
{
    uint32_t entry_offset = 0;
    int i= 0;

    evmm_e820 = (INT15_E820_MEMORY_MAP *)evmm_page_alloc(1);
    if (evmm_e820 == NULL)
        return (UINT64)-1;

    while ( entry_offset < mbi->mmap_length ) {
        memory_map_t *entry = (memory_map_t *) (mbi->mmap_addr + entry_offset);
        evmm_e820->memory_map_entry[i].basic_entry.base_address = 
                            (((UINT64)entry->base_addr_high)<< 32) + entry->base_addr_low;
        evmm_e820->memory_map_entry[i].basic_entry.length = 
                            (((UINT64)entry->length_high)<< 32) + entry->length_low;
        evmm_e820->memory_map_entry[i].basic_entry.address_range_type= entry->type;
            evmm_e820->memory_map_entry[i].extended_attributes.uint32 = 1;
        i++;
       entry_offset += entry->size + sizeof(entry->size);
    }
    evmm_num_e820_entries = i;

    evmm_e820->memory_map_size = i * sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
    evmm_start_of_e820_table = (UINT64)(UINT32)evmm_e820;

    return evmm_start_of_e820_table;
}

static void remove_region(INT15_E820_MEMORY_MAP *e820map, unsigned int *nr_map,
                          unsigned int pos)
{
    unsigned int i = 0;
    // shift (copy) everything down one entry 
    for ( i = pos; i < *nr_map - 1; i++)
        e820map[i] = e820map[i+1];
    (*nr_map)--;
}

static BOOLEAN insert_after_region(INT15_E820_MEMORY_MAP *e820map, 
                                   unsigned int *nr_map, unsigned int pos, uint64_t addr, 
                                   uint64_t size, uint32_t type)
{
    unsigned int i = 0;

    // no more room
    if ( (*nr_map + 1) > MAX_E820_ENTRIES )
        return FALSE;
    // shift (copy) everything up one entry
    for ( i = *nr_map - 1; i > pos; i--)
        e820map[i+1] = e820map[i];
    // now add our entry
    e820map->memory_map_entry[i].basic_entry.base_address = addr;
    e820map->memory_map_entry[pos+1].basic_entry.length = size;
    e820map->memory_map_entry[pos+1].basic_entry.address_range_type = type;
    e820map->memory_map_size = sizeof(e820map) - 
    sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
    (*nr_map)++;
    return TRUE;
}

BOOLEAN e820_reserve_region(INT15_E820_MEMORY_MAP *e820map, uint64_t base, 
                            uint64_t length)
{
    INT15_E820_MEMORY_MAP_ENTRY_EXT *e820entry;
    uint64_t e820_base, e820_length, e820_end;
    uint64_t end;
    unsigned int i =0;

    if (length == 0) {
        return TRUE;
    }

    end = base + length;

    for (; i < evmm_num_e820_entries; i++) {
        e820entry = &e820map->memory_map_entry[i];
        e820_base = e820map->memory_map_entry[i].basic_entry.base_address;
        e820_length = e820map->memory_map_entry[i].basic_entry.length;
        e820_end = e820_base + e820_length;

        if ( (end <= e820_base) || (base >= e820_end) )
            continue;
                
        if ( (base <= e820_base) && (e820_end <= end) ) {
            //Requested region is bigger than the current range
            e820map->memory_map_entry[i].basic_entry.address_range_type =
                                    E820_RESERVED;
        } else if ( (e820_base >= base) && (end < e820_base) &&
                                           (e820_end > end) ) {
            //Overlapping region

            //Split the current range
            if (!insert_after_region(e820map, &evmm_num_e820_entries, i-1, e820_base,
                                     (end - e820_base), E820_RESERVED) )
                return FALSE;

            i++;
            //Update the current region base and length     
            e820map->memory_map_entry[i].basic_entry.base_address = end;
            e820map->memory_map_entry[i].basic_entry.length = e820_end - end;
            break;
        } else  if ((base > e820_base) && (e820_end > base) &&
                                          (end >= e820_end) ) {
            //Overlapping region

            //Update the current region length      
            e820map->memory_map_entry[i].basic_entry.length = base - e820_base;
            //Split the current range
            if (!insert_after_region(e820map, &evmm_num_e820_entries, i, base, 
                                    (e820_end - base), E820_RESERVED) )
                return FALSE;
            i++;
        } else if ( (base > e820_base) && (e820_end > end) ) {
            //the region is within the current range

            //Update the current region length      
            e820map->memory_map_entry[i].basic_entry.length = (base - e820_base);
            //Split the current region      
            if ( !insert_after_region(e820map, &evmm_num_e820_entries, i, base, 
                                      length, E820_RESERVED) )
                return FALSE;
            //Update the rest of the range
            if ( !insert_after_region(e820map, &evmm_num_e820_entries, i, end, 
                 (e820_end - end), e820entry->basic_entry.address_range_type))
                return FALSE;
            i++;
            break;
        } else {
            //ERROR
            return FALSE;
        }
    }       

    return TRUE;
}


uint32_t entryOffset(uint32_t base)
{
    elf64_hdr* elf= (elf64_hdr*) base;
    return elf->e_entry;
}


typedef struct {
    const char *name;          // set to NULL for last item in list
    const char *def_val;
} cmdline_option_t;

#define MAX_VALUE_LEN 64


static void cmdline_parse(const char *cmdline, const cmdline_option_t *options,
                          char vals[][MAX_VALUE_LEN])
{
#if 0
    const char *p = cmdline;
    int i;

    /* copy default values to vals[] */
    for ( i = 0; options[i].name != NULL; i++ ) {
        strncpy(vals[i], options[i].def_val, MAX_VALUE_LEN-1);
        vals[i][MAX_VALUE_LEN-1] = '\0';
    }

    if ( p == NULL )
        return;

    /* parse options */
    while ( 1 )
    {
        /* skip whitespace */
        while ( isspace(*p) )
            p++;
        if ( *p == '\0' )
            break;

        /* find end of current option */
        const char *opt_start = p;
        const char *opt_end = strchr(opt_start, ' ');
        if ( opt_end == NULL )
            opt_end = opt_start + strlen(opt_start);
        p = opt_end;

        /* find value part; if no value found, use default and continue */
        const char *val_start = strchr(opt_start, '=');
        if ( val_start == NULL || val_start > opt_end )
            continue;
        val_start++;

        unsigned int opt_name_size = val_start - opt_start - 1;
        unsigned int copy_size = opt_end - val_start;
        if ( copy_size > MAX_VALUE_LEN - 1 )
            copy_size = MAX_VALUE_LEN - 1;
        if ( opt_name_size == 0 || copy_size == 0 )
            continue;

        /* value found, so copy it */
        for ( i = 0; options[i].name != NULL; i++ ) {
            if ( strncmp(options[i].name, opt_start, opt_name_size ) == 0 ) {
                strncpy(vals[i], val_start, copy_size);
                vals[i][copy_size] = '\0'; /* add '\0' to the end of string */
                break;
            }
        }
    }
#endif
}



void linux_parse_cmdline(const char *cmdline)
{
    // cmdline_parse(cmdline, g_linux_cmdline_options, g_linux_param_values);
}


int get_linux_vga(int *vid_mode)
{
#if 0
    const char *vga = get_option_val(g_linux_cmdline_options,
                                     g_linux_param_values, "vga");
    if ( vga == NULL || vid_mode == NULL )
        return false;

    if ( strcmp(vga, "normal") == 0 )
        *vid_mode = 0xFFFF;
    else if ( strcmp(vga, "ext") == 0 )
        *vid_mode = 0xFFFE;
    else if ( strcmp(vga, "ask") == 0 )
        *vid_mode = 0xFFFD;
    else
        *vid_mode = strtoul(vga, NULL, 0);
#endif
    return 0;
}


const char *skip_filename(const char *cmdline)
{
#if 0
    if ( cmdline == NULL || *cmdline == '\0' )
        return cmdline;

    /* strip leading spaces, file name, then any spaces until the next
     non-space char (e.g. "  /foo/bar   baz" -> "baz"; "/foo/bar" -> "")*/
    while ( *cmdline != '\0' && isspace(*cmdline) )
        cmdline++;
    while ( *cmdline != '\0' && !isspace(*cmdline) )
        cmdline++;
    while ( *cmdline != '\0' && isspace(*cmdline) )
        cmdline++;
#endif
    return cmdline;
}


void get_highest_sized_ram(uint64_t size, uint64_t limit,
                           uint64_t *ram_base, uint64_t *ram_size)
{
#if 0
    uint64_t last_fit_base = 0, last_fit_size = 0;
    unsigned int i;

    if ( ram_base == NULL || ram_size == NULL )
        return;

    for ( i = 0; i < g_nr_map; i++ ) {
        memory_map_t *entry = &g_copy_e820_map[i];

        if ( entry->type == E820_RAM ) {
            uint64_t base = e820_base_64(entry);
            uint64_t length = e820_length_64(entry);

            /* over 4GB so use the last region that fit */
            if ( base + length > limit )
                break;
            if ( size <= length ) {
                last_fit_base = base;
                last_fit_size = length;
            }
        }
    }

    *ram_base = last_fit_base;
    *ram_size = last_fit_size;
#endif
}


#define PAGE_UP(a) ((a+(PAGE_SIZE-1))&PAGE_MASK)


unsigned long get_bootstrap_mem_end(void)
{
    return PAGE_UP((unsigned long)&_end);
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
        /* per Grub-multiboot-Main Part2 Rev94-Structures, apm size is 20 */
        end = max(end, mbi->apm_table + 20);
    if ( mbi->flags & MBI_VBE ) {
        /* VBE2.0, VBE Function 00 return 512 bytes*/
        end = max(end, mbi->vbe_control_info + 512);
        /* VBE2.0, VBE Function 01 return 256 bytes*/
        end = max(end, mbi->vbe_mode_info + 256);
    }

    return PAGE_UP(end);
}


static inline bool plus_overflow_u32(uint32_t x, uint32_t y)
{
    return ((((uint32_t)(~0)) - x) < y);
}


// expand linux kernel with kernel image and initrd image 
int expand_linux_image( multiboot_info_t* mbi,
                        UINT32 linux_image, UINT32 linux_size,
                        UINT32 initrd_image, UINT32 initrd_size,
                        UINT32* entry_point)
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
        tprintk("Error: Linux kernel image is zero.\n");
        return 1;
    }
    if ( linux_size == 0 ) {
        tprintk("Error: Linux kernel size is zero.\n");
        return 1;
    }
    if ( linux_size < sizeof(linux_kernel_header_t) ) {
        tprintk("Error: Linux kernel size is too small.\n");
        return 1;
    }
    hdr = (linux_kernel_header_t *)(linux_image + KERNEL_HEADER_OFFSET);
    if ( hdr == NULL ) {
        tprintk("Error: Linux kernel header is zero.\n");
        return 1;
    }
    if ( entry_point == NULL ) {
        tprintk("Error: Output pointer is zero.\n");
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
        tprintk("Error: Linux setup sectors %d exceed maximum limitation 64.\n",
                hdr->setup_sects);
        return 1;
    }
    // set vid_mode
    linux_parse_cmdline((char *)mbi->cmdline);
    if ( get_linux_vga(&vid_mode) )
        hdr->vid_mode = vid_mode;

    // compare to the magic number 
    if ( hdr->header != HDRS_MAGIC ) {
        tprintk("Error: Old kernel (< 2.6.20) is not supported by tboot.\n");
        return 1;
    }
    if ( hdr->version < 0x0205 ) {
        tprintk("Error: Old kernel (<2.6.20) is not supported by tboot.\n");
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
        tprintk("not enough RAM for initrd\n");
        return 1;
    }
    if ( initrd_size > max_ram_size ) {
        tprintk("initrd_size is too large\n");
        return 1;
    }
    if ( max_ram_base > ((uint64_t)(uint32_t)(~0)) ) {
        tprintk("max_ram_base is too high\n");
        return 1;
    }
    initrd_base = (max_ram_base + max_ram_size - initrd_size) & PAGE_MASK;

    // should not exceed initrd_addr_max 
    if ( (initrd_base + initrd_size) > hdr->initrd_addr_max ) {
        if ( hdr->initrd_addr_max < initrd_size ) {
            tprintk("initrd_addr_max is too small\n");
            return 1;
        }
        initrd_base = hdr->initrd_addr_max - initrd_size;
        initrd_base = initrd_base & PAGE_MASK;
    }

    vmm_memcpy ((void *)initrd_base, (void*)initrd_image, initrd_size);
    tprintk("Initrd from 0x%lx to 0x%lx\n",
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
        tprintk("realmode data is too large\n");
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
            tprintk("protected_mode_base overflows\n");
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
            tprintk("protected_mode_base plus protected_mode_size overflows\n");
            return 1;
        }
        // Check: protected mode part cannot exceed mem_upper 
        if ( mbi->flags & MBI_MEMLIMITS )
            if ( (protected_mode_base + protected_mode_size)
                    > ((mbi->mem_upper << 10) + 0x100000) ) {
                tprintk("Error: Linux protected mode part (0x%lx ~ 0x%lx) "
                       "exceeds mem_upper (0x%lx ~ 0x%lx).\n",
                       (unsigned long)protected_mode_base,
                       (unsigned long)(protected_mode_base + protected_mode_size),
                       (unsigned long)0x100000,
                       (unsigned long)((mbi->mem_upper << 10) + 0x100000));
                return 1;
            }
    }
    else {
        tprintk("Error: Linux protected mode not loaded high\n");
        return 1;
    }

    // set cmd_line_ptr 
    hdr->cmd_line_ptr = real_mode_base + KERNEL_CMDLINE_OFFSET;

    // load protected-mode part 
    vmm_memcpy((void *)protected_mode_base, (void*)(linux_image + real_mode_size),
            protected_mode_size);
    tprintk("Kernel (protected mode) from 0x%lx to 0x%lx\n",
           (unsigned long)protected_mode_base,
           (unsigned long)(protected_mode_base + protected_mode_size));

    // load real-mode part 
    vmm_memcpy((void *)real_mode_base, (void*)linux_image, real_mode_size);
    tprintk("Kernel (real mode) from 0x%lx to 0x%lx\n",
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
    *entry_point = hdr->code32_start;
    return 0;
}


// relocate and setup variables for evmm entry

int prepare_primary_guest_args()
{

    // put arguments one page prior to guest esp (which is normally one page before evmm heap)
    if(linux_esp_register==0) {
        return 1;
    }

    linux_boot_params= (linux_esp_register-2*PAGE_SIZE);
    boot_params_t* new_boot_params= (boot_params_t*)linux_boot_params;

    // FIX: copy arguments

    // set address of copied tboot shared page 
    vmm_memcpy((void*)new_boot_params->tboot_shared_addr, (void*)&shared_page, sizeof(shared_page));

    // FIX: remove bootstrap, stack page and arguments page from linux e820

    // set esi register
    linux_esi_register= linux_boot_params;
    return 0;
}


int prepare_linux_image_for_evmm(multiboot_info_t *mbi)
{
    if ( linux_start== 0)
        return 1;

    module_t* m = (module_t *)mbi->mods_addr;
    UINT32 initrd_image = (UINT32)m->mod_start;
    UINT32 initrd_size = m->mod_end - m->mod_start;
    expand_linux_image(mbi, linux_start, linux_end-linux_start,
                       initrd_image, initrd_size, &linux_entry_address);

    // CHECK(JLM)
    linux_start_address= linux_entry_address;
    tprintk("Linux kernel @%p...\n", linux_entry_address);
    return 0;
}


// tboot jumps in here
int start32_evmm(UINT32 magic, UINT32 initial_entry, multiboot_info_t* mbi)
{
    int i;

#ifdef JLMDEBUG
    tprintk("start32_evmm entry, mbi: %08x, initial_entry: %08x, magic: %08x\n",
            mbi, initial_entry, magic);
#endif

    // We assume the standard grub layout with three modules after bootstrap: 
    //    64-bit evmm, the linux image and initram fs.
    // Everything is decompressed EXCEPT the protected mode portion of linux
    int l= mbi->mmap_length/sizeof(memory_map_t);
    if (l<3) {
        tprintk("bootstrap error: wrong number of modules\n");
        LOOP_FOREVER
    }
#ifdef JLMDEBUG
    // mbi
    tprintk("%d e820 entries\n", l);

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
#endif // JLMDEBUG

    // get initial layout information for images
    module_t* m;

    // FIX(JLM): mystart is wrong
    bootstrap_start= (UINT32)_mystart;
    bootstrap_end= (UINT32)_end;

    m= get_module(mbi, 0);
    evmm_start= (uint32_t)m->mod_start;
    evmm_end= (uint32_t)m->mod_end;

    linux_start= 0ULL;
    linux_end= 0ULL;

    m= get_module(mbi, 1);
    linux_start= (uint32_t)m->mod_start;
    linux_end= (uint32_t)m->mod_end;

    initram_start= 0ULL;
    initram_end= 0ULL;

    if(l>2) {
        m= get_module(mbi, 2);
        initram_start= (uint32_t)m->mod_start;
        initram_end= (uint32_t)m->mod_end;
    }

    // get CPU info
    uint32_t info;
    // FIX(JLM): returns hyperthreaded # what does evmm want?
    asm volatile (
        "\tmovl    $1, %%eax\n"
        "\tcpuid\n"
        "\tmovl    %%ebx, %[info]\n"
    : [info] "=m" (info)
    : 
    : "%eax", "%ebx", "%ecx", "%edx");
    evmm_num_of_aps = ((info>>16)&0xff)-1;
    if (evmm_num_of_aps < 0)
        evmm_num_of_aps = 0; 

#ifdef JLMDEBUG
    tprintk("Memory map pre relocation\n");
    tprintk("\tstart32_evmm is at %08x\n", start32_evmm);
    tprintk("\tbootstrap_start: %08x, bootstrap_end: %08x\n", bootstrap_start, bootstrap_end);
    tprintk("\tevmm_start: %08x, evmm_end: %08x\n", evmm_start, evmm_end);
    tprintk("\tlinux_start: %08x, linux_end: %08x\n", linux_start, linux_end);
    tprintk("\tinitram_start: %08x, initram_end: %08x\n", initram_start, initram_end);
    tprintk("\t%d APs, %08x\n", evmm_num_of_aps, info);
#endif
    evmm_num_of_aps = 0;  // BSP only for now
    LOOP_FOREVER

    init32.s.i32_low_memory_page = low_mem;
    init32.s.i32_num_of_aps = evmm_num_of_aps;

    // set up evmm heap
    evmm_heap_base = HEAP_BASE;
    evmm_heap_size = HEAP_SIZE;
    // NOTE: first argument was &heap_base which was wrong
    InitializeMemoryManager(evmm_heap_base, evmm_heap_size);

    SetupIDT();

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

    UINT16 p_cr3 = init64.i64_cr3;

    // Allocate stack and set rsp (esp)
    setup_evmm_stack();

    // Relocate evmm_image from evmm_start to evmm_start_address
    evmm_start_address= EVMM_DEFAULT_START_ADDR;
    vmm_memcpy((void *)evmm_start_address, (const void*) evmm_start, 
               (UINT32) (evmm_end-evmm_start));

    // FIX(JLM): linker so the next line is right
    uint32_t entry= entryOffset(evmm_start);
    vmm_main_entry_point =  (entry + evmm_start_address);
#ifdef JLMDEBUG
    tprintk("evmm relocated to %08x, entry point: %08x\n", evmm_start_address,
            vmm_main_entry_point);
#endif

    if(prepare_linux_image_for_evmm(mbi)) {
        tprintk("Cant prepare linux image\n");
        LOOP_FOREVER
    }

    // Guest state initialization for relocated inage
    evmm_g0.size_of_this_struct = sizeof(evmm_g0);
    evmm_g0.version_of_this_struct = VMM_GUEST_STARTUP_VERSION;
    evmm_g0.flags = 0;               //FIX(RNB): need to put the correct guest flags
    evmm_g0.guest_magic_number = 0;  //FIX(RNB): needs to be unique id of the guest
    evmm_g0.cpu_affinity = -1;
    evmm_g0.cpu_states_count = 1;    // CHECK(RNB): number of VMM_GUEST_STARTUP structs
    evmm_g0.devices_count = 0;       // CHECK: 0 implies guest is deviceless
    evmm_g0.image_size = linux_end - linux_start;
                
    evmm_g0.image_address= linux_start_address;
    evmm_g0.image_offset_in_guest_physical_memory = linux_start_address;
    evmm_g0.physical_memory_size = 0; 

    // FIX(RNB):  This is an array of VMM_GUEST_CPU_STARTUP_STATE and must be filled
    // FIX(RNB): fill for protected mode.  rip should be 0x100000, CS, DS, 32 bit stack.
    // FIX(RNB): set aside reserved area for input arguments to guest, this includes old
    // style 20 bit entry e820.  The GP registers should be correctly filled with 
    // input args for code32_start.  Note that the boot parameters are already
    // in the current address space so we only need to reserve memory and copy
    // them.
    evmm_g0.cpu_states_array = 0; 

    // FIX(RNB): the start address of the array of initial cpu states for guest cpus.
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
    p_startup_struct->primary_guest_startup_state = (UINT64)(UINT32)&evmm_g0;

    // FIX(RNB):  For a single guest, this is wrong.  see the initialization code.
    // vmm_memory_layout is suppose to contain the start/end/size of
    // each image that is part of evmm (e.g. evmm, linux+initrd)
    evmm_vmem = (VMM_MEMORY_LAYOUT *) evmm_page_alloc(1);
    // FIX (RNB) test for failure
    (p_startup_struct->vmm_memory_layout[0]).total_size = (evmm_end - evmm_start) + 
            evmm_heap_size + p_startup_struct->size_of_vmm_stack;
    (p_startup_struct->vmm_memory_layout[0]).image_size = (evmm_end - evmm_start);

    (p_startup_struct->vmm_memory_layout[0]).base_address = evmm_start_address;
    (p_startup_struct->vmm_memory_layout[0]).entry_point =  vmm_main_entry_point;

    // FIX(RNB): memory maps should NOT include linux or initram according to SC guys
    (p_startup_struct->vmm_memory_layout[1]).total_size = (linux_end - linux_start); //+linux's heap and stack size
    (p_startup_struct->vmm_memory_layout[1]).image_size = (linux_end - linux_start);
    (p_startup_struct->vmm_memory_layout[1]).base_address = linux_start;
    // QUESTION (JLM):  Check the line below.  It is only right if linux has a 64 bit elf header
    (p_startup_struct->vmm_memory_layout[1]).entry_point = linux_start + entryOffset(linux_start);

    (p_startup_struct->vmm_memory_layout[2]).total_size = (initram_end - initram_start);
    (p_startup_struct->vmm_memory_layout[2]).image_size = (initram_end - initram_start);
    (p_startup_struct->vmm_memory_layout[2]).base_address = initram_start;
 
    (p_startup_struct->vmm_memory_layout[2]).entry_point = initram_start + entryOffset(initram_start);

    p_startup_struct->physical_memory_layout_E820 = get_e820_table(mbi);

    // FIX(RNB): The current evmm REQUIRES a thunk area.  We need to define one.
    // application parameters
    // FIX(RNB):  This structure is not used so the setting is probably OK.
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
        tprintk("Error getting e820 table\r\n");
        LOOP_FOREVER
    }

    if ( !e820_reserve_region(evmm_e820, HEAP_BASE, (HEAP_SIZE + (evmm_end - evmm_start)))) {
        tprintk("Unable to reserve evmm region in e820 table\r\n");
        LOOP_FOREVER
    }
                
    if (!e820_reserve_region(evmm_e820, bootstrap_start, (bootstrap_end - bootstrap_start))) {
      tprintk("Unable to reserve bootstrap region in e820 table\r\n");
        LOOP_FOREVER
    } 

    // FIX(RNB):  put APs in 64 bit mode with stack.  (In ifdefed code)
    // FIX (JLM):  add reserved area for linux guest startup arguments
    // FIX (JLM):  in evmm, exclude tboot and bootstrap areas from primary space
    // FIX(JLM):  allocate  debug area for return from evmm print and print it.

    // set up evmm stack for vmm_main call and flip tp 64 bit mode
    //  vmm_main call:
    //      vmm_main(UINT32 local_apic_id, UINT64 startup_struct_u, 
    //               UINT64 application_params_struct_u, 
    //               UINT64 reserved UNUSED)
    asm volatile (
        // p_evmm_stack points to the start of the stack
        "movl %[p_evmm_stack], %%esp\n"
        // prepare arguments for 64-bit mode
        // there are 3 arguments
        // align stack and push them on 8-byte alignment
        "\txor %%eax, %%eax\n"
        "\tand $7, %%esp\n"
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
        "\tpush   %[cs_64]\n"

        // for following retf
        "\tpush 1f\n"
        "\tmovl %[vmm_main_entry_point], %%ebx\n"

        "\t movl %[p_cr3], %%eax \n"
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
        "\tbts $31, %%eax\n"
        "\tmovl %%eax, %%cr0\n"

        // at this point we are in 32-bit compatibility mode
        // LMA=1, CS.L=0, CS.D=1
        // jump from 32bit compatibility mode into 64bit mode.
        "\tretf\n"

"1:\n"
        // in 64bit this is actually pop rcx
        "\t pop %%ecx\n"
        // in 64bit this is actually pop rdx
        "\t pop %%edx\n"
        "\t .byte 0x41\n"
        // pop r8
        "\t .byte 0x58\n"
        "\t .byte 0x41\n"
        // pop r9
        "\t .byte 0x59\n"
        // in 64bit this is actually sub  0x18, %%rsp
        "\t.byte 0x48\n"
        "\t subl 0x18, %%esp\n"
        // in 64bit this is actually
        // "\t call %%ebx\n"
        "\t jmp (%[vmm_main_entry_point])\n"
        "\t ud2\n"
    : 
    : [local_apic_id] "m" (local_apic_id), [p_startup_struct] "m" (p_startup_struct), 
      [evmm_p_a0] "m" (evmm_p_a0), [evmm_reserved] "m" (evmm_reserved), 
      [vmm_main_entry_point] "m" (vmm_main_entry_point), [p_evmm_stack] "m" (p_evmm_stack), 
      [cs_64] "m" (cs_64), [p_cr3] "m" (p_cr3)
    : "%eax", "%ebx", "%ecx", "%edx");

    return 0;
}

