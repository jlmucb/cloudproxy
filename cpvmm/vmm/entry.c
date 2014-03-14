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
#include "tboot.h"
#include "e820.h"
#include "linux_defns.h"

#include "em64t_defs.h"
#include "ia32_defs.h"
#include "ia32_low_level.h"
#include "x32_init64.h"
#include "vmm_startup.h"

#define PSE_BIT     0x10
#define PAE_BIT     0x20

#define PAGE_SIZE (1024 * 4) 
#define MAX_E820_ENTRIES 3 //CHECK: 1 for each tboot, evmm, and primary guest

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

#if 0
typedef struct {
    UINT32 struct_size;
    UINT32 version;
    UINT32 size_in_sectors;
    UINT32 umbr_size;
    UINT32 evmm_mem_in_mb;
    UINT32 guest_count;
    UINT32 evmml_start;
    UINT32 evmml_count;
    UINT32 starter_start;
    UINT32 starter_count;
    UINT32 evmmh_start;
    UINT32 evmmh_count;
    UINT32 startap_start;
    UINT32 startap_count;
    UINT32 evmm_start;
    UINT32 evmm_count;
    UINT32 startup_start;
    UINT32 startup_count;
    UINT32 guest1_start;
    UINT32 guest1_count;
} EVMM_DESC;

static EVMM_DESC          ed;
    // read 64-bit evm header
    //assumption: sector_size = 512; size = size of bootstrap + evmm
    ed.version = 0x00002000; //RNB-CHECK: version info from the loader start script
    ed.size_in_sectors = 1;   
                //FIX: size of what?  Where is get_size() defined?
    ed.umbr_size = 0;   // CHECK: not sure what it is
    ed.evmm_mem_in_mb = ((evmm_end - evmm_start) + (1024 * 1024) - 1)/(1024 *1024);
    ed.guest_count = 1; // RNB-CHECK: Evmm loader code says 0 for this, even though they set the guest1_start
    ed.evmml_start = 0; // CHECK: this is loader start address
    ed.evmml_count= 0;  // CHECK: this is size of the loader
    ed.starter_start = 0; // CHECK: this is startap start address
    ed.starter_count= 0;  // CHECK: size of the startap code 
    ed.evmmh_start = evmm_start; // start address of evmm header
    ed.evmmh_count= (sizeOfHdr() + 511)/512; // CHECK
    ed.evmm_start= evmm_start; 
    ed.evmm_count= ((evmm_end - evmm_start) + 511) /512; //number of sectors in evmm
    ed.startup_start = 0; //RNB-CHECK: not using startup code, so don't need this.
    ed.startup_count= 0; //RNB-CHECK: not using startup code, so don't need this.
    ed.guest1_start = linux_start;   //RNB-FIX: This is the start value passed as the command line.  Therefore, it is the start of the linux (not the relocated/uncompressed value)
#endif

// Ring 0 Interrupt Descriptor Table - Gate Types
#define IA32_IDT_GATE_TYPE_TASK          0x85
#define IA32_IDT_GATE_TYPE_INTERRUPT_16  0x86
#define IA32_IDT_GATE_TYPE_TRAP_16       0x87
#define IA32_IDT_GATE_TYPE_INTERRUPT_32  0x8E
#define IA32_IDT_GATE_TYPE_TRAP_32       0x8F

#define EVMM_START_ADDR 0xa0000000 

#define HEAP_SIZE 0X100000
#define HEAP_BASE 0Xa0000000 - HEAP_SIZE

// TOTAL_MEM is a  max of 4G because we start in 32-bit mode
#define TOTAL_MEM 0x100000000 
#define IDT_VECTOR_COUNT 256
#define LVMM_CS_SELECTOR 0x10

#define LINUX_DEFAULT_LOAD_ADDRESS 0xC0000000


UINT32  heap_base; 
UINT32  heap_current; 
UINT32  heap_tops;
UINT32  heap_size;
UINT32  evmm_start_address;
INT15_E820_MEMORY_MAP *e820;
UINT64 *start_of_e820_table;

typedef struct VMM_INPUT_PARAMS_S {
    UINT64 local_apic_id;
    UINT64 startup_struct;
    UINT64 guest_params_struct; // change name
} VMM_INPUT_PARAMS;

//  Globals
IA32_IDT_GATE_DESCRIPTOR LvmmIdt[IDT_VECTOR_COUNT];
IA32_DESCRIPTOR IdtDescriptor;

static IA32_GDTR        gdtr_32;
static IA32_GDTR        gdtr_64;  // still in 32-bit mode
static UINT16           cs_64;
static UINT32           p_cr4;

static VMM_INPUT_PARAMS  input_params;
static VMM_INPUT_PARAMS  *pointer_to_input_params= &input_params;
static UINT32           reserved = 0;
static UINT32           local_apic_id = 0;
static VMM_STARTUP_STRUCT startup_struct;
static VMM_STARTUP_STRUCT *p_startup_struct = &startup_struct;
static EM64T_CODE_SEGMENT_DESCRIPTOR *p_gdt_64;
static UINT32 *p_evmm_stack;
static EM64T_PML4 *pml4_table;
static EM64T_PDPE *pdp_table;
static EM64T_PDE_2MB *pd_table;

static INIT64_STRUCT    init64;
static INIT64_STRUCT *  p_init64_data = &init64;
static INIT32_STRUCT_SAFE init32;
int                     info[4] = {0, 0, 0, 0};
int                     num_of_aps= 0;
void*                   p_low_mem = (void *)0x8000;
VMM_GUEST_STARTUP       g0;
VMM_GUEST_STARTUP *     p_g0 = &g0;
VMM_MEMORY_LAYOUT      *vmem;

void *                  vmm_main_entry_point;      // address of vmm_main
multiboot_info_t *      g_mbi= NULL;

typedef void (*tboot_printk)(const char *fmt, ...);
tboot_printk tprintk = (tboot_printk)(0x80d660);

void *vmm_memset(void *dest, int val, UINT32 count)
{
    asm volatile(
        "\n movl %[dest], %%edi"
        "\n\t movl %[val], %%eax"
        "\n\t movl %[count], %%ecx"
        "\n\t cld"
        "\n\t rep stosb"
        :[dest] "+g" (dest)
        :[val] "g" (val), [count] "g" (count)
        :);
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
        :[src] "g" (src), [count] "g" (count)
        :);
    return dest;
}

void ZeroMem(void *Address, UINT32  Size)
{
  UINT8* Source;

  Source = (UINT8*)Address;
  while (Size--) {
    *Source++ = 0;
  }
}//end ZeroMem

void* AllocateMemory(UINT32 size_request)
{
  UINT32 Address;

  if (heap_current + size_request > heap_tops) {
      tprintk("Allocation request exceeds heap's size\r\n");
      tprintk("Heap current = %X", heap_current);
      tprintk("Requested size = %X", size_request);
      tprintk("Heap tops = %X", heap_tops);
      return NULL;
  }
  Address = heap_current;
  heap_current+=size_request;
  ZeroMem((void*)Address, size_request);
  return (void*)Address;
}//end AllocateMemory

void InitializeMemoryManager(UINT64 *HeapBaseAddress, UINT64 *HeapBytes)
{
    heap_current = heap_base = *(UINT32*)HeapBaseAddress;
    heap_tops = heap_base + *(UINT32*)HeapBytes;
}

void CopyMem(void *Dest, void *Source, UINT32 Size)
{
    UINT8 *d = (UINT8*)Dest;
    UINT8 *s = (UINT8*)Source;

    while (Size--) {
        *d++ = *s++;
    }
}

BOOLEAN CompareMem(void *Source1, void *Source2, UINT32 Size)
{
    UINT8 *s1 = (UINT8*)Source1;
    UINT8 *s2 = (UINT8*)Source2;

    while (Size--) {
        if (*s1++ != *s2++) {
        tprintk("Compare mem failed\n");
        return FALSE;
        }
    }
    return TRUE;
}

void *evmm_page_alloc(UINT32 pages)
{
    UINT32 address;
    UINT32 size = pages * PAGE_SIZE;

    address = ALIGN_FORWARD(heap_current, PAGE_SIZE);
    heap_current = address + size;
    ZeroMem((void*)address, size);
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
    // PrintExceptionHeader(Cs, Eip);
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
    //PrintExceptionHeader(Cs, Eip);
    tprintk("NMI\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerBreakPoint(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Breakpoint\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerOverflow(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Overflow\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerBoundRangeExceeded(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Bound range exceeded\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerUndefinedOpcode(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Undefined opcode\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerNoMathCoprocessor(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("No math coprocessor\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerDoubleFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Double fault\n");

    // No need to print error code here because it is always zero
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerInvalidTaskSegmentSelector(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Invalid task segment selector\n");
    //PrintErrorCodeGeneric(ErrorCode);
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerSegmentNotPresent(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Segment not present\n");
    //PrintErrorCodeGeneric(ErrorCode);
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerStackSegmentFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Stack segment fault\n");
    //PrintErrorCodeGeneric(ErrorCode);
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerGeneralProtectionFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("General protection fault\n");
    //PrintErrorCodeGeneric(ErrorCode);
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
        //PrintExceptionHeader(Cs, Eip);
    tprintk("Page fault\n");
    tprintk("Faulting address %x",Cr2);
    tprintk("\n");

    // TODO: need a specific error code print function here
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerMathFault(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Math fault\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerAlignmentCheck(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Alignment check\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerMachineCheck(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("Machine check\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerSimdFloatingPointNumericError(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
    tprintk("SIMD floating point numeric error\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerReservedSimdFloatingPointNumericError(UINT32 Cs, UINT32 Eip)
{
    //PrintExceptionHeader(Cs, Eip);
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
    ZeroMem(&LvmmIdt, sizeof(LvmmIdt));

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
} // end SetupIDT

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

/*
 *  x32_pt64_setup_paging: establish paging tables for x64 -bit mode, 
 *     2MB pages while running in 32-bit mode.
 *     It should scope full 32-bit space, i.e. 4G
 */
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
    //memset(pdp_table, 0, PAGE_4KB_SIZE);

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
        //memset(pd_table, 0, PAGE_4KB_SIZE);
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
#define CHUNK_SIZE 72 
#if 0
        /* Break the command line up into 72 byte chunks */
        int   cmdlen = strlen((char*)mbi->cmdline);
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
#endif
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

#include "elf64.h"

static UINT64 *get_e820_table(const multiboot_info_t *mbi) 
{
    uint32_t entry_offset = 0;
    int i= 0;

    e820 = (INT15_E820_MEMORY_MAP *)evmm_page_alloc(1);
    if (e820 ==NULL)
        return -1;

    while ( entry_offset < mbi->mmap_length ) {
        memory_map_t *entry = (memory_map_t *) (mbi->mmap_addr + entry_offset);
        e820->memory_map_entry[i].basic_entry.base_address = 
                            (entry->base_addr_high << 32) + entry->base_addr_low;
        e820->memory_map_entry[i].basic_entry.length = 
                            (entry->length_high << 32) + entry->length_low;
        e820->memory_map_entry[i].basic_entry.address_range_type= entry->type;
            e820->memory_map_entry[i].extended_attributes.uint32 = 1;
        i++;
       entry_offset += entry->size + sizeof(entry->size);
    }
    e820->memory_map_size = i * sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
    start_of_e820_table = (UINT64)(UINT32)e820;

    return start_of_e820_table;
}

#if 0

static void remove_region(INT15_E820_MEMORY_MAP *e820map, unsigned int *nr_map,
                          unsigned int pos)
{
    unsigned int i = 0;
    /* shift (copy) everything down one entry */
    for ( i = pos; i < *nr_map - 1; i++)
        e820map[i] = e820map[i+1];

    (*nr_map)--;
}

static BOOLEAN insert_after_region(INT15_E820_MEMORY_MAP *e820map, 
                unsigned int pos, uint64_t addr, uint64_t size, uint32_t type)
{
    unsigned int i = 0;

    // no more room
    if ( *nr_map + 1 > MAX_E820_ENTRIES )
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

static BOOLEAN protect_region(INT15_E820_MEMORY_MAP *e820map, unsigned int *nr_map,
                           uint64_t new_addr, uint64_t new_size, uint32_t new_type)
{
    uint64_t addr, tmp_addr, size, tmp_size;
    uint32_t type;
    unsigned int i;

    if ( new_size == 0 )
        return TRUE;
    // check for wrap
    if ( new_addr + new_size < new_addr )
        return FALSE;

    /* find where our region belongs in the table and insert it */
    for ( i = 0; i < *nr_map; i++ ) {
        addr = e820map->memory_map_entry[i].basic_entry.base_address;
        size = e820map->memory_map_entry[i].basic_entry.length;
        type = e820map->memory_map_entry[i].basic_entry.length;
        /* is our region at the beginning of the current map region? */
        if ( new_addr == addr ) {
            if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                      new_type) )
                return FALSE;
            break;
        }
        /* are we w/in the current map region? */
        else if ( new_addr > addr && new_addr < (addr + size) ) {
            if ( !insert_after_region(e820map, nr_map, i, new_addr, new_size,
                                      new_type) )
                return FALSE;
            /* fixup current region */
            tmp_addr = e820map->memory_map_entry[i].basic_entry.base_address;
            i++;   /* adjust to always be that of our region */
            /* insert a copy of current region (before adj) after us so */
            /* that rest of code can be common with previous case */
            if ( !insert_after_region(e820map, nr_map, i, addr, size, type) )
                return FALSE;
            break;
        }
        /* is our region in a gap in the map? */
        else if ( addr > new_addr ) {
            if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                      new_type) )
                return FALSE;
            break;
        }
    }
    /* if we reached the end of the map without finding an overlapping */
    /* region, insert us at the end (note that this test won't trigger */
    /* for the second case above because the insert() will have incremented */
    /* nr_map and so i++ will still be less) */
    if ( i == *nr_map ) {
        if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                  new_type) )
            return FALSE;
        return TRUE;
    }

    i++;     /* move to entry after our inserted one (we're not at end yet) */

    tmp_addr = e820map->memory_map_entry[i].basic_entry.base_address;
    tmp_size = e820map->memory_map_entry[i].basic_entry.length;

    /* did we split the (formerly) previous region? */
    if ((new_addr >= tmp_addr) &&
         ((new_addr + new_size) < (tmp_addr + tmp_size)) ) {
        /* then adjust the current region (adj size first) */
        e820map->memory_map_entry[i].basic_entry.length = 
            (tmp_addr + tmp_size) - (new_addr + new_size);
        e820map->memory_map_entry[i].basic_entry.base_address = 
            (new_addr + new_size);
        return TRUE;
    }

    /* if our region completely covers any existing regions, delete them */
    while ( (i < *nr_map) && ((new_addr + new_size) >=
                              (tmp_addr + tmp_size)) ) {
        remove_region(e820map, nr_map, i);
        tmp_addr = e820map->memory_map_entry[i].basic_entry.base_address;
        tmp_size = e820map->memory_map_entry[i].basic_entry.length;
    }

    /* finally, if our region partially overlaps an existing region, */
    /* then truncate the existing region */
    if ( i < *nr_map ) {
        tmp_addr = e820map->memory_map_entry[i].basic_entry.base_address;
        tmp_size = e820map->memory_map_entry[i].basic_entry.length;
        if ( (new_addr + new_size) > tmp_addr ) {
            e820map->memory_map_entry[i].basic_entry.length = 
                                    (tmp_addr + tmp_size) - (new_addr + new_size);
            e820map->memory_map_entry[i].basic_entry.base_address = 
                                            (new_addr + new_size);
        }
    }

    return TRUE;
}
#endif


int getuuid(char* uuid_str, uint8_t* uuid)
{
    return 1;
}


// TODO(tmroeder): this should be the real base, but I want it to compile.
//uint64_t tboot_shared_page = 0;

uint32_t entryOffset(uint32_t base)
{
    elf64_hdr* elf= (elf64_hdr*) base;
    return elf->e_entry;
}


#define JLMDEBUG

// tboot jumps in here
int main(int an, char** av) 
{
    int i;

    // john's tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;
    tboot_shared_t *shared_page = (tboot_shared_t *)0x829000;

    // john's g_mbi,  multiboot_info_t * my_mbi= 0x10000;
    multiboot_info_t * my_mbi= (multiboot_info_t *)0x10000;

    // john's boot_params boot_params_t *my_boot_params= 0x94200
    boot_params_t *my_boot_params= (boot_params_t *)0x94200;

    // We assume the standard grub layout with three modules
    // after bootstrap: 64-bit evmm, the linux image
    // and initram fs.
    // Everything is decompressed EXCEPT the protected mode portion of
    // linux
    module_t* m;
    int l= my_mbi->mmap_length/sizeof(memory_map_t);

    if (l<3) {
        tprintk("bootstrap error: wrong number of modules\n");
    }
#ifdef JLMDEBUG
    // toms: tboot_printk tprintk = (tboot_printk)(0x80d7f0);
    // john's: tboot_printk tprintk = (tboot_printk)(0x80d660);
    //tboot_printk tprintk = (tboot_printk)(0x80d660);
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
    tprintk("bootstap main is at %08x\n", main);

    tprintk("%d mbi modules\n", my_mbi->mods_count);
    tprintk("\tmod_start  mod_end   string\n");
    for(i=0; i<my_mbi->mods_count; i++) {
        m= get_module(my_mbi, (unsigned int) i);
        tprintk("\t%08x %08x %s\n", m->mod_start, 
                m->mod_end, m->string);
    }

    tprintk("\t_start: %08x, _end: %08x\n", _mystart, _end);
#endif

    uint32_t bootstrap_start= _mystart;
    uint32_t bootstrap_end= _end;

    uint32_t evmm_start= 0ULL;
    uint32_t evmm_end= 0ULL;

    m= get_module(my_mbi, 0);
    evmm_start= (uint32_t)m->mod_start;
    evmm_end= (uint32_t)m->mod_end;
    elf64_hdr* evmm_elf= (elf64_hdr*)evmm_start;

    uint32_t linux_start= 0ULL;
    uint32_t linux_end= 0ULL;

    m= get_module(my_mbi, 1);
    linux_start= (uint32_t)m->mod_start;
    linux_end= (uint32_t)m->mod_end;
    // char* uuid_string= m->string;

    uint32_t initram_start= 0ULL;
    uint32_t initram_end= 0ULL;

    if(l>2) {
        m= get_module(my_mbi, 2);
        initram_start= (uint32_t)m->mod_start;
        initram_end= (uint32_t)m->mod_end;
    }


    // TODO(tmroeder): remove this debugging while loop later
    while(1) ;

    // get CPU info
    __cpuid(info,1);
    num_of_aps = ((info[1] >> 16) & 0xff) - 1;
    if (num_of_aps < 0)
        num_of_aps = 0; // CHECK: this should be 0 until we have AP's, right?

    init32.s.i32_low_memory_page = (UINT32)p_low_mem;
    init32.s.i32_num_of_aps = num_of_aps;

    // set up evmm heap
    heap_base = HEAP_BASE;
    heap_size = HEAP_SIZE;
    InitializeMemoryManager((UINT64 *)&heap_base, (UINT64 *)&heap_size);

    SetupIDT();

    // setup gdt for 64-bit
    x32_gdt64_setup();
    x32_gdt64_get_gdtr(&init64.i64_gdtr);
    ia32_write_gdtr(&init64.i64_gdtr);

    // setup paging, control registers and flags
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

    // get vmm_main entry point
    uint32_t entry= entryOffset(evmm_start);

    // Relocate evmm_image from evmm_start to evmm_start_address
    evmm_start_address= EVMM_START_ADDR;
    vmm_memcpy((void *)evmm_start_address, (const void*) evmm_start, (UINT32) (evmm_end-evmm_start));
    // QUESTION: This was wrong, you had entry+evmm_start 
    vmm_main_entry_point = (void *) (entry + evmm_start_address);

    // Allocate stack and set rsp (esp)
    setup_evmm_stack();

    // JLM:  string hardcoded for now but it's defined above
    //    Remove this definition when Rekha figures out what uuid should be
    char* uuid_string= "a1edf4f7-94e1-4c47-8573-0e3f54821ed3";
    // QUESTION:  This doesn't seem right.  See my mail.
    UINT32 uuid =0;

    // Guest state initialization
    g0.size_of_this_struct = sizeof(g0);
    g0.version_of_this_struct = VMM_GUEST_STARTUP_VERSION;
    g0.flags = 0;               //FIX: need to put the correct guest flags
    g0.guest_magic_number = 0;  //FIX: needs to be unique id of the guest
    g0.cpu_affinity = -1;
    g0.cpu_states_count = 1;    // CHECK: number of VMM_GUEST_STARTUP structs
    g0.devices_count = 0;       // CHECK: 0 implies guest is devices less
    g0.image_size = linux_end - linux_start;
                
    // FIX: This is the start address,  the offset from the
    // compressed linux.  Currently, evmm_main does't understand elf
    // (uncompressed or otherwise).
    g0.image_address= linux_start;
    g0.image_offset_in_guest_physical_memory = LINUX_DEFAULT_LOAD_ADDRESS;
    g0.physical_memory_size = 0; //CHECK: notes inside evmm say it should be 0 for primary. 
    g0.cpu_states_array = NULL; 

    // FIX: the start address of the array of initial cpu states for guest cpus.
    //     This pointer makes sense only if the devices_count > 0
    g0.devices_array = NULL;

    // Startup struct initialization
    p_startup_struct->version_of_this_struct = VMM_STARTUP_STRUCT_VERSION;
    p_startup_struct->number_of_processors_at_install_time = 1;     // only BSP for now
    p_startup_struct->number_of_processors_at_boot_time = 1;        // only BSP for now
    p_startup_struct->number_of_secondary_guests = 0; 
    p_startup_struct->size_of_vmm_stack = UVMM_DEFAULT_STACK_SIZE_PAGES; 
    p_startup_struct->unsupported_vendor_id = 0; 
    p_startup_struct->unsupported_device_id = 0; 
    p_startup_struct->flags = 0; 
    // QUESTION:  I'm pretty sure the line below is wrong since the uuid is NOT a 32 
    // bit nunber please correct.  You can use getuuid(uuid_string, uuid)
    p_startup_struct->default_device_owner= uuid;
    p_startup_struct->acpi_owner= uuid; 
    p_startup_struct->nmi_owner= uuid; 
    p_startup_struct->primary_guest_startup_state = (UINT64)&g0;

    // FIX: vmm_memory_layout is suppose to contain the start/end/size of
    // each image that is part of evmm (e.g. evmm, linux+initrd
    vmem = (VMM_MEMORY_LAYOUT *) evmm_page_alloc(1);
    (p_startup_struct->vmm_memory_layout[0]).total_size = (evmm_end - evmm_start) + 
            heap_size + p_startup_struct->size_of_vmm_stack;
    (p_startup_struct->vmm_memory_layout[0]).image_size = (evmm_end - evmm_start);

    (p_startup_struct->vmm_memory_layout[0]).base_address = evmm_start_address;
    (p_startup_struct->vmm_memory_layout[0]).entry_point =  vmm_main_entry_point;

    (p_startup_struct->vmm_memory_layout[1]).total_size = (linux_end - linux_start); //+linux's heap and stack size
    (p_startup_struct->vmm_memory_layout[1]).image_size = (linux_end - linux_start);
    (p_startup_struct->vmm_memory_layout[1]).base_address = linux_start;
    // QUESTION:  Check the line below.  It is only right if linux has a 64 bit elf header
    (p_startup_struct->vmm_memory_layout[1]).entry_point = linux_start + entryOffset(linux_start);

    (p_startup_struct->vmm_memory_layout[2]).total_size = (initram_end - initram_start);
    (p_startup_struct->vmm_memory_layout[2]).image_size = (initram_end - initram_start);
    (p_startup_struct->vmm_memory_layout[2]).base_address = initram_start;
    // FIX:  This is wrong, intiram does not have an entry point
    (p_startup_struct->vmm_memory_layout[2]).entry_point = initram_start + entryOffset(initram_start);

    // QUESTION: where is get_e820_layout defined?
    p_startup_struct->physical_memory_layout_E820 = get_e820_layout();

    // set up evmm stack for vmm_main call and flip tp 64 bit mode
    //  vmm_main call:
    //      vmm_main(UINT32 local_apic_id, UINT64 startup_struct_u, 
    //               UINT64 application_params_struct_u, 
    //               UINT64 reserved UNUSED)
    asm volatile (
        "movl %[p_evmm_stack], %%esp\n"
        // prepare arguments for 64-bit mode
        // there are 3 arguments
        // align stack and push them on 8-byte alignment
        "\txor %%eax, %%eax\n"
        "\tand $7, %%esp\n"
        "\tpush %%eax\n"
        "\tpush %[reserved]\n"
        "\tpush %%eax\n"
        "\tpush %[p_g0]\n"
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
        : [local_apic_id] "m" (local_apic_id), 
          [p_startup_struct] "m" (p_startup_struct), 
          [p_g0] "m" (p_g0), [reserved] "m" (reserved), 
          [vmm_main_entry_point] "m" (vmm_main_entry_point), 
          [p_evmm_stack] "m" (p_evmm_stack), 
          [cs_64] "m" (cs_64), [p_cr3] "m" (p_cr3)
        : "%eax", "%ebx", "%ecx", "%edx");

    // CHECK: what happens when evmm returns?
    return 0;
}

