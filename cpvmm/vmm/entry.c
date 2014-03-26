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

// for linux primary guest
#define LINUX_BOOT_CS 0x10
#define LINUX_BOOT_DS 0x18

typedef struct {
    const char *name;          // set to NULL for last item in list
    const char *def_val;
} cmdline_option_t;

#define MAX_VALUE_LEN 64


extern uint32_t _start_bootstrap, _end_bootstrap;

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

#define EVMM_HEAP_SIZE 0X100000
#define EVMM_HEAP_BASE 0Xa0000000 - EVMM_HEAP_SIZE

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
uint32_t evmm_initial_stack= 0;         // initial evmm stack

// expanded e820 table used be evmm
static unsigned int     evmm_num_e820_entries = 0;
INT15_E820_MEMORY_MAP * evmm_e820= NULL;                // address of expanded e820 table for evmm
UINT64                  evmm_start_of_e820_table= 0ULL; // same but 64 bits

// linux guest
uint32_t linux_start_address= 0;   // this is the address of the linux protected mode image
uint32_t initram_start_address= 0; // this is the address of the initram for linux
uint32_t linux_entry_address= 0;   // this is the address of the eip in the guest
uint32_t linux_esi_register= 0;    // this is the value of the esi register on guest entry
uint32_t linux_esp_register= 0;    // this is the value of the esp on entry to the guest linux
uint32_t linux_stack_base= 0;      // this is the base of the stack on entry to linux
uint32_t linux_stack_size= 0;      // this is the size of the stack that the linux guest has

// boot parameters for linux guest
uint32_t linux_original_boot_parameters= 0;
uint32_t linux_boot_params= 0;
static const cmdline_option_t linux_cmdline_options[] = {
    { "vga", "" },
    { "mem", "" },
    { NULL, NULL }
};
static char linux_param_values[ARRAY_SIZE(linux_cmdline_options)][MAX_VALUE_LEN];


char* vmm_strncpy(char *dest, const char *src, size_t n)
{
    char* out= dest;

    while(n>0 && *src!='\0') {
        *(dest++)= *(src++);
        n--;
    }
    *dest= 0;
    return out;
}


char* vmm_strcpy(char *dest, const char *src)
{
    char* out= dest;

    while(*src!='\0') {
        *(dest++)= *(src++);
    }
    *dest= 0;
    return out;
}


char* vmm_strchr (const char * str, int character)
{
    const char* p= str;

    while(1) {
        if(*p==character)
            return (char*) p;
        if(*p=='\0')
            break;
        p++;
    }
    return NULL;
}


int vmm_strcmp (const char * str1, const char * str2)
{
    while(*str1!='\0' && *str2!='\0') {
        if(*str1>*str2)
            return 1;
        if(*str1<*str2)
            return -1;
        str1++; str2++;
    }
    return 0;
}


int vmm_strncmp (const char * str1, const char * str2, size_t n)
{

    while(n>=0 && *str1!='\0' && *str2!='\0') {
        if(*str1>*str2)
            return 1;
        if(*str1<*str2)
            return -1;
        str1++; str2++;
        n--;
    }
    return 0;
}


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


unsigned long int vmm_strtoul (const char* str, char** endptr, int base)
{
    return 0;
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
    int     i;
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
    evmm_initial_stack = (UINT32) p_gdt_64 + (UVMM_DEFAULT_STACK_SIZE_PAGES * PAGE_4KB_SIZE);
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


static EM64T_CR3 cr3_for_x64 = {0};

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
            vmm_strncpy(chunk, cmdptr, CHUNK_SIZE); 
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


// This builds the 24 byte extended 8820 table
static UINT64 evmm_get_e820_table(const multiboot_info_t *mbi) 
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


// state of primary linux guest on startup
VMM_GUEST_CPU_STARTUP_STATE linux_state;


uint32_t alloc_linux_stack(UINT32 pages)
{
    if (pages > 1)
        return 0;   // error

    UINT32 address;
    UINT32 size = pages * PAGE_SIZE;

    linux_stack_base = evmm_heap_base - PAGE_SIZE;
    linux_stack_size= size;
    address = ALIGN_FORWARD(linux_stack_base, PAGE_SIZE);
    vmm_memset((void*)address, 0, size);
    return address;
}


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
        linux_state.gp.reg[i] = (UINT64) 0;
    }
    linux_state.gp.reg[IA32_REG_RIP] = (UINT64) linux_entry_address;
    linux_state.gp.reg[IA32_REG_RSI] = (UINT64) linux_esi_register;
    linux_state.gp.reg[IA32_REG_RSP] = (UINT64) linux_esp_register;
    for (i = 0; i < IA32_REG_XMM_COUNT; i++) {
        linux_state.xmm.reg[i].uint64[0] = (UINT64)0;
        linux_state.xmm.reg[i].uint64[1] = (UINT64)0;
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
    linux_state.control.gdtr.base = (UINT64)(UINT32)&gdt_table;
    linux_state.control.gdtr.limit = (UINT64)(UINT32)gdt_table + sizeof(gdt_table) -1;

    for (i = 0; i < IA32_SEG_COUNT; i++) {
        linux_state.seg.segment[i].base = 0;
        linux_state.seg.segment[i].limit = 0;
    }
    //CHECK: got the base address from tboot, not sure about the limits of these segments/attributes.
    linux_state.seg.segment[IA32_SEG_CS].base = (UINT64) LINUX_BOOT_CS;
    linux_state.seg.segment[IA32_SEG_DS].base = (UINT64) LINUX_BOOT_DS;
    return 0;
}


uint32_t OriginalEntryAddress(uint32_t base)
{
    elf64_hdr* elf= (elf64_hdr*) base;
    return elf->e_entry;
}


#define _XA     0x00    /* extra alphabetic - not supported */
#define _XS     0x40    /* extra space */
#define _BB     0x00    /* BEL, BS, etc. - not supported */
#define _CN     0x20    /* CR, FF, HT, NL, VT */
#define _DI     0x04    /* ''-'9' */
#define _LO     0x02    /* 'a'-'z' */
#define _PU     0x10    /* punctuation */
#define _SP     0x08    /* space */
#define _UP     0x01    /* 'A'-'Z' */
#define _XD     0x80    /* ''-'9', 'A'-'F', 'a'-'f' */


const uint8_t _ctype[257] = {
    _CN,            /* 0x0      0.     */
    _CN,            /* 0x1      1.     */
    _CN,            /* 0x2      2.     */
    _CN,            /* 0x3      3.     */
    _CN,            /* 0x4      4.     */
    _CN,            /* 0x5      5.     */
    _CN,            /* 0x6      6.     */
    _CN,            /* 0x7      7.     */
    _CN,            /* 0x8      8.     */
    _CN|_SP,        /* 0x9      9.     */
    _CN|_SP,        /* 0xA     10.     */
    _CN|_SP,        /* 0xB     11.     */
    _CN|_SP,        /* 0xC     12.     */
    _CN|_SP,        /* 0xD     13.     */
    _CN,            /* 0xE     14.     */
    _CN,            /* 0xF     15.     */
    _CN,            /* 0x10    16.     */
    _CN,            /* 0x11    17.     */
    _CN,            /* 0x12    18.     */
    _CN,            /* 0x13    19.     */
    _CN,            /* 0x14    20.     */
    _CN,            /* 0x15    21.     */
    _CN,            /* 0x16    22.     */
    _CN,            /* 0x17    23.     */
    _CN,            /* 0x18    24.     */
    _CN,            /* 0x19    25.     */
    _CN,            /* 0x1A    26.     */
    _CN,            /* 0x1B    27.     */
    _CN,            /* 0x1C    28.     */
    _CN,            /* 0x1D    29.     */
    _CN,            /* 0x1E    30.     */
    _CN,            /* 0x1F    31.     */
    _XS|_SP,        /* 0x20    32. ' ' */
    _PU,            /* 0x21    33. '!' */
    _PU,            /* 0x22    34. '"' */
    _PU,            /* 0x23    35. '#' */
    _PU,            /* 0x24    36. '$' */
    _PU,            /* 0x25    37. '%' */
    _PU,            /* 0x26    38. '&' */
    _PU,            /* 0x27    39. ''' */
    _PU,            /* 0x28    40. '(' */
    _PU,            /* 0x29    41. ')' */
    _PU,            /* 0x2A    42. '*' */
    _PU,            /* 0x2B    43. '+' */
    _PU,            /* 0x2C    44. ',' */
    _PU,            /* 0x2D    45. '-' */
    _PU,            /* 0x2E    46. '.' */
    _PU,            /* 0x2F    47. '/' */
    _XD|_DI,        /* 0x30    48. '' */
    _XD|_DI,        /* 0x31    49. '1' */
    _XD|_DI,        /* 0x32    50. '2' */
    _XD|_DI,        /* 0x33    51. '3' */
    _XD|_DI,        /* 0x34    52. '4' */
    _XD|_DI,        /* 0x35    53. '5' */
    _XD|_DI,        /* 0x36    54. '6' */
    _XD|_DI,        /* 0x37    55. '7' */
    _XD|_DI,        /* 0x38    56. '8' */
    _XD|_DI,        /* 0x39    57. '9' */
    _PU,            /* 0x3A    58. ':' */
    _PU,            /* 0x3B    59. ';' */
    _PU,            /* 0x3C    60. '<' */
    _PU,            /* 0x3D    61. '=' */
    _PU,            /* 0x3E    62. '>' */
    _PU,            /* 0x3F    63. '?' */
    _PU,            /* 0x40    64. '@' */
    _XD|_UP,        /* 0x41    65. 'A' */
    _XD|_UP,        /* 0x42    66. 'B' */
    _XD|_UP,        /* 0x43    67. 'C' */
    _XD|_UP,        /* 0x44    68. 'D' */
    _XD|_UP,        /* 0x45    69. 'E' */
    _XD|_UP,        /* 0x46    70. 'F' */
    _UP,            /* 0x47    71. 'G' */
    _UP,            /* 0x48    72. 'H' */
    _UP,            /* 0x49    73. 'I' */
    _UP,            /* 0x4A    74. 'J' */
    _UP,            /* 0x4B    75. 'K' */
    _UP,            /* 0x4C    76. 'L' */
    _UP,            /* 0x4D    77. 'M' */
    _UP,            /* 0x4E    78. 'N' */
    _UP,            /* 0x4F    79. 'O' */
    _UP,            /* 0x50    80. 'P' */
    _UP,            /* 0x51    81. 'Q' */
    _UP,            /* 0x52    82. 'R' */
    _UP,            /* 0x53    83. 'S' */
    _UP,            /* 0x54    84. 'T' */
    _UP,            /* 0x55    85. 'U' */
    _UP,            /* 0x56    86. 'V' */
    _UP,            /* 0x57    87. 'W' */
    _UP,            /* 0x58    88. 'X' */
    _UP,            /* 0x59    89. 'Y' */
    _UP,            /* 0x5A    90. 'Z' */
    _PU,            /* 0x5B    91. '[' */
    _PU,            /* 0x5C    92. '\' */
    _PU,            /* 0x5D    93. ']' */
    _PU,            /* 0x5E    94. '^' */
    _PU,            /* 0x5F    95. '_' */
    _PU,            /* 0x60    96. '`' */
    _XD|_LO,        /* 0x61    97. 'a' */
    _XD|_LO,        /* 0x62    98. 'b' */
    _XD|_LO,        /* 0x63    99. 'c' */
    _XD|_LO,        /* 0x64   100. 'd' */
    _XD|_LO,        /* 0x65   101. 'e' */
    _XD|_LO,        /* 0x66   102. 'f' */
    _LO,            /* 0x67   103. 'g' */
    _LO,            /* 0x68   104. 'h' */
    _LO,            /* 0x69   105. 'i' */
    _LO,            /* 0x6A   106. 'j' */
    _LO,            /* 0x6B   107. 'k' */
    _LO,            /* 0x6C   108. 'l' */
    _LO,            /* 0x6D   109. 'm' */
    _LO,            /* 0x6E   110. 'n' */
    _LO,            /* 0x6F   111. 'o' */
    _LO,            /* 0x70   112. 'p' */
    _LO,            /* 0x71   113. 'q' */
    _LO,            /* 0x72   114. 'r' */
    _LO,            /* 0x73   115. 's' */
    _LO,            /* 0x74   116. 't' */
    _LO,            /* 0x75   117. 'u' */
    _LO,            /* 0x76   118. 'v' */
    _LO,            /* 0x77   119. 'w' */
    _LO,            /* 0x78   120. 'x' */
    _LO,            /* 0x79   121. 'y' */
    _LO,            /* 0x7A   122. 'z' */
    _PU,            /* 0x7B   123. '{' */
    _PU,            /* 0x7C   124. '|' */
    _PU,            /* 0x7D   125. '}' */
    _PU,            /* 0x7E   126. '~' */
    _CN,            /* 0x7F   127.     */

    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x80 to 0x8F    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x90 to 0x9F    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xA0 to 0xAF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xB0 to 0xBF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xC0 to 0xCF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xD0 to 0xDF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xE0 to 0xEF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 /* 0xF0 to 0x100   */
};

static  bool isdigit(int c)
{
    return (_ctype[(unsigned char)(c)] & (_DI));
}
static  bool isspace(int c)
{
    return (_ctype[(unsigned char)(c)] & (_SP));
}
static  bool isxdigit(int c)
{
    return (_ctype[(unsigned char)(c)] & (_XD));
}
static  bool isupper(int c)
{
    return (_ctype[(unsigned char)(c)] & (_UP));
}
static  bool islower(int c)
{
    return (_ctype[(unsigned char)(c)] & (_LO));
}
static  bool isprint(int c)
{
    return (_ctype[(unsigned char)(c)] & (_LO | _UP | _DI |
                                          _SP | _PU));
}
static  bool isalpha(int c)
{
    return (_ctype[(unsigned char)(c)] & (_LO | _UP));
}

static const char* get_option_val(const cmdline_option_t *options,
                              char vals[][MAX_VALUE_LEN], const char *opt_name)
{
    int i;
    for (i = 0; options[i].name != NULL; i++ ) {
        if ( vmm_strcmp(options[i].name, opt_name) == 0 )
            return vals[i];
    }
    tprintk("requested unknown option: %s\n", opt_name);
    return NULL;
}

static void cmdline_parse(const char *cmdline, const cmdline_option_t *options,
                          char vals[][MAX_VALUE_LEN])
{
    const char *p = cmdline;
    int i;

    /* copy default values to vals[] */
    for ( i = 0; options[i].name != NULL; i++ ) {
        vmm_strncpy(vals[i], options[i].def_val, MAX_VALUE_LEN-1);
        vals[i][MAX_VALUE_LEN-1] = '\0';
    }

    if ( p == NULL )
        return;

    /* parse options */
    while ( 1 ) {
        /* skip whitespace */
        while ( isspace(*p) )
            p++;
        if ( *p == '\0' )
            break;

        /* find end of current option */
        const char *opt_start = p;
        const char *opt_end = (const char*)vmm_strchr(opt_start, ' ');
        if ( opt_end == NULL )
            opt_end = opt_start + vmm_strlen(opt_start);
        p = opt_end;

        /* find value part; if no value found, use default and continue */
        const char *val_start = vmm_strchr(opt_start, '=');
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
            if ( vmm_strncmp(options[i].name, opt_start, opt_name_size ) == 0 ) {
                vmm_strncpy(vals[i], val_start, copy_size);
                vals[i][copy_size] = '\0'; /* add '\0' to the end of string */
                break;
            }
        }
    }
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


const char *skip_filename(const char *cmdline)
{
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
    return cmdline;
}


#define PAGE_UP(a) ((a+(PAGE_SIZE-1))&PAGE_MASK)


unsigned long get_bootstrap_mem_end(void)
{
    return PAGE_UP(bootstrap_end);
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
    linux_original_boot_parameters= (uint32_t) boot_params;
    *entry_point = hdr->code32_start;
    return 0;
}


#ifndef false
#define false 0
#define true 1
#endif


// relocate and setup variables for evmm entry

int prepare_primary_guest_args(multiboot_info_t *mbi)
{
    // put arguments one page prior to guest esp (which is normally one page before evmm heap)
    if(linux_esp_register==0) {
        return 1;
    }

    linux_boot_params= (linux_esp_register-2*PAGE_SIZE);
    boot_params_t* new_boot_params= (boot_params_t*)linux_boot_params;

    vmm_memcpy((void*)linux_boot_params, (void*)linux_original_boot_parameters, sizeof(boot_params_t));

    uint32_t linux_e820_table= linux_boot_params+ sizeof(boot_params_t);
    set_e820_copy_location(linux_e820_table, E820MAX);

    // set address of copied tboot shared page 
    vmm_memcpy((void*)new_boot_params->tboot_shared_addr, (void*)&shared_page, sizeof(shared_page));

    // Remove bootstrap, stack page and arguments page from linux e820
    if(copy_e820_map(mbi)==false) {
        return 1;
    }

    // arguments (maybe it's ok to leave these)
    if(e820_reserve_ram(linux_boot_params, 3*PAGE_SIZE)==false) {
        return 1;
    }

    // bootstrap
    if(e820_reserve_ram(bootstrap_start, bootstrap_end-bootstrap_start)==false) {
        return 1;
    }

    // set number of e820 entries
    new_boot_params->e820_entries= get_num_e820_ents();

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
    if(prepare_primary_guest_args(mbi)!=0) {
        return 1;
    }

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
    bootstrap_start= _start_bootstrap;
    bootstrap_end= _end_bootstrap;

    m= get_module(mbi, 0);
    evmm_start= (uint32_t)m->mod_start;
    evmm_end= (uint32_t)m->mod_end;

    linux_start= 0ULL;
    linux_end= 0ULL;

    m= get_module(mbi, 1);
    linux_start= (uint32_t)m->mod_start;
    linux_end= (uint32_t)m->mod_end;

    initram_start= 0ULL;
    

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
    evmm_heap_base = EVMM_HEAP_BASE;
    evmm_heap_size = EVMM_HEAP_SIZE;
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
    // FIX(JLM): the correct address is 
    //  vmm_main_entry_point= (original entry point -original text start)+location of new test
    uint32_t entry= OriginalEntryAddress(evmm_start);
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
    // FIX(RNB): our guest has ALL the devices.  How can it be deviceless?
    evmm_g0.devices_count = 0;       // CHECK: 0 implies guest is deviceless
    evmm_g0.image_size = linux_end - linux_start;
    //FIX(RNB): is this the start of the PROTECTED mode portion of linux            
    evmm_g0.image_address= linux_start_address;
    evmm_g0.image_offset_in_guest_physical_memory = linux_start_address;
    evmm_g0.physical_memory_size = 0; 

    // This is an array of VMM_GUEST_CPU_STARTUP_STATE and must be filled
    // fill for protected mode.  rip should be 0x100000, CS, DS, 32 bit stack.
    // The GP registers should be correctly filled with 
    // input args for code32_start. 
    linux_setup();          // setups gdt table, GPRs and CS/DS for guest(linux)
    evmm_g0.cpu_states_array = (UINT32)&linux_state;

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
    // FIX(RNB): I think the memory layout is not needed for the primary
    // Also, note that the image size includes the heap.  Should the base_address
    // be the start of the evmm image or the evmm heap?
    evmm_vmem = (VMM_MEMORY_LAYOUT *) evmm_page_alloc(1);
    // FIX (RNB) test for failure
    (p_startup_struct->vmm_memory_layout[0]).total_size = (evmm_end - evmm_start) + 
            evmm_heap_size + p_startup_struct->size_of_vmm_stack;
    (p_startup_struct->vmm_memory_layout[0]).image_size = (evmm_end - evmm_start);
    (p_startup_struct->vmm_memory_layout[0]).base_address = evmm_start_address;
    (p_startup_struct->vmm_memory_layout[0]).entry_point =  vmm_main_entry_point;

#if 0
    // FIX(RNB): memory maps should NOT include linux or initram according to SC guys
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
    // CHECK(RNB):  This structure is not used so the setting is probably OK.
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

    // I don't think this is necessary
#if 0
    if (!e820_reserve_region(evmm_e820, evmm_heap_base, (evmm_heap_size+(evmm_end-evmm_start)))) {
        tprintk("Unable to reserve evmm region in e820 table\r\n");
        LOOP_FOREVER
    }
    if(!e820_reserve_region(evmm_e820, bootstrap_start, (bootstrap_end - bootstrap_start))) {
      tprintk("Unable to reserve bootstrap region in e820 table\r\n");
        LOOP_FOREVER
    } 
#endif

    // FIX(RNB):  put APs in 64 bit mode with stack.  (In ifdefed code)
    // FIX (JLM):  In evmm, exclude tboot and bootstrap areas from primary space
    // FIX(JLM):  allocate  debug area for return from evmm print and print it.

    // set up evmm stack for vmm_main call and flip tp 64 bit mode
    //  vmm_main call:
    //      vmm_main(UINT32 local_apic_id, UINT64 startup_struct_u, 
    //               UINT64 application_params_struct_u, 
    //               UINT64 reserved UNUSED)
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
    : 
    : [local_apic_id] "m" (local_apic_id), [p_startup_struct] "m" (p_startup_struct), 
      [evmm_p_a0] "m" (evmm_p_a0), [evmm_reserved] "m" (evmm_reserved), 
      [vmm_main_entry_point] "m" (vmm_main_entry_point), [evmm_initial_stack] "m" (evmm_initial_stack), 
      [cs_64] "m" (cs_64), [p_cr3] "m" (p_cr3)
    : "%eax", "%ebx", "%ecx", "%edx");

    return 0;
}

