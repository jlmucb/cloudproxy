/*
 * File: bootstrap_idt.c
 * Description: idt support for bootstrap
 * Author: John Manferdelli and Rekha Bachwani
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "bootstrap_types.h"
#include "bootstrap_print.h"
#include "e820.h"
#include "multiboot.h"

#include "bootstrap_ia.h"
#include "vmm_defs.h"
#include "ia32_defs.h"
#include "ia32_low_level.h"
#include "x32_init64.h"


#define JLMDEBUG


typedef struct {
    INIT32_STRUCT s;
    uint32_t data[32];
} INIT32_STRUCT_SAFE;


#define IDT_VECTOR_COUNT 256
IA32_IDT_GATE_DESCRIPTOR                LvmmIdt[IDT_VECTOR_COUNT];
IA32_DESCRIPTOR                         IdtDescriptor;


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

// TOTAL_MEM is a  max of 4G because we start in 32-bit mode
#define TOTAL_MEM 0x100000000 
#define IDT_VECTOR_COUNT 256
#define LVMM_CS_SELECTOR 0x10


//  Globals

IA32_IDT_GATE_DESCRIPTOR                LvmmIdt[IDT_VECTOR_COUNT];
IA32_DESCRIPTOR                         IdtDescriptor;


void ExceptionHandlerReserved(uint32_t Cs, uint32_t Eip)
{
    // PrintExceptionHeader(Cs, Eip);
    bprint("Reserved exception\n");
    LOOP_FOREVER
}

void ExceptionHandlerDivideError(uint32_t Cs, uint32_t Eip)
{
    bprint("Divide error\n");
    LOOP_FOREVER
}

void ExceptionHandlerDebugBreakPoint(uint32_t Cs, uint32_t Eip)
{
    // PrintExceptionHeader(Cs, Eip);
    bprint("Debug breakpoint\n");
    LOOP_FOREVER
}

void ExceptionHandlerNmi(uint32_t Cs, uint32_t Eip)
{
    bprint("NMI\n");
    LOOP_FOREVER
}

void ExceptionHandlerBreakPoint(uint32_t Cs, uint32_t Eip)
{
    bprint("Breakpoint\n");
    LOOP_FOREVER
}

void ExceptionHandlerOverflow(uint32_t Cs, uint32_t Eip)
{
    bprint("Overflow\n");
    LOOP_FOREVER
}

void ExceptionHandlerBoundRangeExceeded(uint32_t Cs, uint32_t Eip)
{
    bprint("Bound range exceeded\n");
    LOOP_FOREVER
}

void ExceptionHandlerUndefinedOpcode(uint32_t Cs, uint32_t Eip)
{
    bprint("Undefined opcode\n");
    LOOP_FOREVER
}

void ExceptionHandlerNoMathCoprocessor(uint32_t Cs, uint32_t Eip)
{
    bprint("No math coprocessor\n");
    LOOP_FOREVER
}

void ExceptionHandlerDoubleFault(uint32_t Cs, uint32_t Eip, uint32_t ErrorCode)
{
    bprint("Double fault\n");
    // No need to print error code here because it is always zero
    LOOP_FOREVER
}

void ExceptionHandlerInvalidTaskSegmentSelector(uint32_t Cs, uint32_t Eip, uint32_t ErrorCode)
{
    bprint("Invalid task segment selector\n");
    LOOP_FOREVER
}

void ExceptionHandlerSegmentNotPresent(uint32_t Cs, uint32_t Eip, uint32_t ErrorCode)
{
    bprint("Segment not present\n");
    LOOP_FOREVER
}

void ExceptionHandlerStackSegmentFault(uint32_t Cs, uint32_t Eip, uint32_t ErrorCode)
{
    bprint("Stack segment fault\n");
    LOOP_FOREVER
}

void ExceptionHandlerGeneralProtectionFault(uint32_t Cs, uint32_t Eip, uint32_t ErrorCode)
{
    bprint("General protection fault\n");
    LOOP_FOREVER
}

void ExceptionHandlerPageFault(uint32_t Cs, uint32_t Eip, uint32_t ErrorCode)
{
    uint32_t Cr2;

    asm volatile(
        "\npush %%eax"
        "\n\tmovl %%cr2, %%eax"
        "\n\tmovl %%eax, %[Cr2]"
        "\n\tpop %%eax"
    :[Cr2] "=g" (Cr2)
    ::"%eax");
    bprint("Page fault\n");
    bprint("Faulting address %x",Cr2);
    bprint("\n");

    // TODO: need a specific error code print function here
    LOOP_FOREVER
}

void ExceptionHandlerMathFault(uint32_t Cs, uint32_t Eip)
{
    bprint("Math fault\n");
    LOOP_FOREVER
}

void ExceptionHandlerAlignmentCheck(uint32_t Cs, uint32_t Eip)
{
    bprint("Alignment check\n");
    LOOP_FOREVER
}

void ExceptionHandlerMachineCheck(uint32_t Cs, uint32_t Eip)
{
    bprint("Machine check\n");
    LOOP_FOREVER
}

void ExceptionHandlerSimdFloatingPointNumericError(uint32_t Cs, uint32_t Eip)
{
    bprint("SIMD floating point numeric error\n");
    LOOP_FOREVER
}

void ExceptionHandlerReservedSimdFloatingPointNumericError(uint32_t Cs, uint32_t Eip)
{
    bprint("Reserved SIMD floating point numeric error\n");
    LOOP_FOREVER
}

void InstallExceptionHandler(uint32_t ExceptionIndex, uint32_t HandlerAddr)
{
    LvmmIdt[ExceptionIndex].OffsetLow  = HandlerAddr & 0xFFFF;
    LvmmIdt[ExceptionIndex].OffsetHigh = HandlerAddr >> 16;
}

void SetupIDT()
{
    int     i;
    uint32_t  pIdtDescriptor;

    bprint("SetupIdt called\n");
    vmm_memset(&LvmmIdt, 0, sizeof(LvmmIdt));

    for (i = 0 ; i < 32 ; i++) {
        LvmmIdt[i].GateType = IA32_IDT_GATE_TYPE_INTERRUPT_32;
        LvmmIdt[i].Selector = LVMM_CS_SELECTOR;
        LvmmIdt[i].Reserved_0 = 0;
        InstallExceptionHandler(i, (uint32_t)(ExceptionHandlerReserved));
    }

    InstallExceptionHandler(Ia32ExceptionVectorDivideError,
                            (uint32_t)ExceptionHandlerDivideError);
    InstallExceptionHandler(Ia32ExceptionVectorDebugBreakPoint,
                            (uint32_t)ExceptionHandlerDebugBreakPoint);
    InstallExceptionHandler(Ia32ExceptionVectorNmi,
                            (uint32_t)ExceptionHandlerNmi);
    InstallExceptionHandler(Ia32ExceptionVectorBreakPoint,
                            (uint32_t)ExceptionHandlerBreakPoint);
    InstallExceptionHandler(Ia32ExceptionVectorOverflow,
                            (uint32_t)ExceptionHandlerOverflow);
    InstallExceptionHandler(Ia32ExceptionVectorBoundRangeExceeded,
                            (uint32_t)ExceptionHandlerBoundRangeExceeded);
    InstallExceptionHandler(Ia32ExceptionVectorUndefinedOpcode,
                            (uint32_t)ExceptionHandlerUndefinedOpcode);
    InstallExceptionHandler(Ia32ExceptionVectorNoMathCoprocessor,
                            (uint32_t)ExceptionHandlerNoMathCoprocessor);
    InstallExceptionHandler(Ia32ExceptionVectorDoubleFault,
                            (uint32_t)ExceptionHandlerDoubleFault);
    InstallExceptionHandler(Ia32ExceptionVectorInvalidTaskSegmentSelector,
                            (uint32_t)ExceptionHandlerInvalidTaskSegmentSelector);
    InstallExceptionHandler(Ia32ExceptionVectorSegmentNotPresent,
                            (uint32_t)ExceptionHandlerSegmentNotPresent);
    InstallExceptionHandler(Ia32ExceptionVectorStackSegmentFault,
                            (uint32_t)ExceptionHandlerStackSegmentFault);
    InstallExceptionHandler(Ia32ExceptionVectorStackSegmentFault,
                            (uint32_t)ExceptionHandlerStackSegmentFault);
    InstallExceptionHandler(Ia32ExceptionVectorGeneralProtectionFault,
                            (uint32_t)ExceptionHandlerGeneralProtectionFault);
    InstallExceptionHandler(Ia32ExceptionVectorPageFault,
                            (uint32_t)ExceptionHandlerPageFault);
    InstallExceptionHandler(Ia32ExceptionVectorMathFault,
                            (uint32_t)ExceptionHandlerMathFault);
    InstallExceptionHandler(Ia32ExceptionVectorAlignmentCheck,
                            (uint32_t)ExceptionHandlerAlignmentCheck);
    InstallExceptionHandler(Ia32ExceptionVectorMachineCheck,
                            (uint32_t)ExceptionHandlerMachineCheck);
    InstallExceptionHandler(Ia32ExceptionVectorSimdFloatingPointNumericError,
                            (uint32_t)ExceptionHandlerSimdFloatingPointNumericError);
    InstallExceptionHandler(Ia32ExceptionVectorReservedSimdFloatingPointNumericError,
                            (uint32_t)ExceptionHandlerReservedSimdFloatingPointNumericError);

    IdtDescriptor.Base = (uint32_t)(LvmmIdt);
    IdtDescriptor.Limit = sizeof(IA32_IDT_GATE_DESCRIPTOR) * 32 - 1;

    pIdtDescriptor = (uint32_t)&IdtDescriptor;
    asm volatile(
        "\nmovl   %%eax, %[pIdtDescriptor]"
        "\n\tlidt  (%%edx)"
    :[pIdtDescriptor] "+g" (pIdtDescriptor)
    :: "%edx");
}


