/****************************************************************************
* Copyright (c) 2013 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
****************************************************************************/

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/
//
// IA-32 Exception Bitmap
//

#include <vmm_defs.h>
#include <vmm_arch_defs.h>
#include <uvmmh.h>
#include <memory.h>

#pragma pack (1)

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

//
// IA-32 Interrupt Descriptor Table - Gate Descriptor
//
typedef struct {
  UINT32  OffsetLow:16;   // Offset bits 15..0
  UINT32  Selector:16;    // Selector
  UINT32  Reserved_0:8;   // Reserved
  UINT32  GateType:8;     // Gate Type.  See #defines above
  UINT32  OffsetHigh:16;  // Offset bits 31..16
} IA32_IDT_GATE_DESCRIPTOR;

//
// Descriptor for the Global Descriptor Table(GDT) and Interrupt Descriptor Table(IDT)
//
typedef struct {
  UINT16  Limit;
  UINT32  Base;
} IA32_DESCRIPTOR;

//
// Ring 0 Interrupt Descriptor Table - Gate Types
//
#define IA32_IDT_GATE_TYPE_TASK          0x85
#define IA32_IDT_GATE_TYPE_INTERRUPT_16  0x86
#define IA32_IDT_GATE_TYPE_TRAP_16       0x87
#define IA32_IDT_GATE_TYPE_INTERRUPT_32  0x8E
#define IA32_IDT_GATE_TYPE_TRAP_32       0x8F


#define IDT_VECTOR_COUNT 256
#define LVMM_CS_SELECTOR 0x10

#define ERROR_CODE_EXT_BIT 0x1
#define ERROR_CODE_IN_IDT  0x2
#define ERROR_CODE_TI      0x4

IA32_IDT_GATE_DESCRIPTOR LvmmIdt[IDT_VECTOR_COUNT];
IA32_DESCRIPTOR IdtDescriptor;


void PrintExceptionHeader(UINT32 Cs, UINT32 Eip)
{
//    ClearScreen();
    PRINT_STRING("*******************************************************************************\n");
    PRINT_STRING("*                                                                             *\n");
    PRINT_STRING("*             Intel Lightweight Virtual Machine Monitor (TM)                  *\n");
    PRINT_STRING("*                                                                             *\n");
    PRINT_STRING("*******************************************************************************\n");
    PRINT_STRING("\nFatal error has occured at 0x");
    PRINT_VALUE(Cs);
    PRINT_STRING(":0x");
    PRINT_VALUE(Eip);
    PRINT_STRING("\n");

    PRINT_STRING("Error type: ");
}

void PrintErrorCodeGeneric(UINT32 ErrorCode)
{
    PRINT_STRING("Error code: 0x");
    PRINT_VALUE(ErrorCode);
    PRINT_STRING(", index 0x");
    PRINT_VALUE(ErrorCode >> 3);
    PRINT_STRING("\n");

    if ((ErrorCode & ERROR_CODE_EXT_BIT) != 0)
    {
        PRINT_STRING("External event\n");
    }
    else
    {
        PRINT_STRING("Internal event\n");
    }

    if ((ErrorCode & ERROR_CODE_IN_IDT) != 0)
    {
        PRINT_STRING("Index is in IDT\n");
    }
    else if ((ErrorCode & ERROR_CODE_TI) != 0)
    {
        PRINT_STRING("Index is in LDT\n");
    }
    else
    {
        PRINT_STRING("Index is in GDT\n");
    }
}

void ExceptionHandlerReserved(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Reserved exception\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerDivideError(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Divide error\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerDebugBreakPoint(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Debug breakpoint\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerNmi(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("NMI\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerBreakPoint(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Breakpoint\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerOverflow(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Overflow\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerBoundRangeExceeded(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Bound range exceeded\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerUndefinedOpcode(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Undefined opcode\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerNoMathCoprocessor(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("No math coprocessor\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerDoubleFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Double fault\n");

    //
    // No need to print error code here because it is always zero
    //

    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerInvalidTaskSegmentSelector(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Invalid task segment selector\n");
    PrintErrorCodeGeneric(ErrorCode);
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerSegmentNotPresent(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Segment not present\n");
    PrintErrorCodeGeneric(ErrorCode);
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerStackSegmentFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Stack segment fault\n");
    PrintErrorCodeGeneric(ErrorCode);
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerGeneralProtectionFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("General protection fault\n");
    PrintErrorCodeGeneric(ErrorCode);
    VMM_UP_BREAKPOINT();
}

  //
  // The next pragma is to avoid compiler warning when debug prints are disabled
  //
#pragma warning (disable:4101)
void ExceptionHandlerPageFault(UINT32 Cs, UINT32 Eip, UINT32 ErrorCode)
{
    UINT32 Cr2;

    __asm
    {
      push eax
      mov eax, cr2
      mov Cr2, eax
      pop eax
    }
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Page fault\n");
    PRINT_STRING("Faulting address 0x");
    PRINT_VALUE(Cr2);
    PRINT_STRING("\n");

    // TODO: need a specific error code print function here
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerMathFault(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Math fault\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerAlignmentCheck(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Alignment check\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerMachineCheck(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Machine check\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerSimdFloatingPointNumericError(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("SIMD floating point numeric error\n");
    VMM_UP_BREAKPOINT();
}

void ExceptionHandlerReservedSimdFloatingPointNumericError(UINT32 Cs, UINT32 Eip)
{
    PrintExceptionHeader(Cs, Eip);
    PRINT_STRING("Reserved SIMD floating point numeric error\n");
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

    PRINT_STRING("SetupIdt called\n");

    ZeroMem(&LvmmIdt, sizeof(LvmmIdt));

    for (i = 0 ; i < 32 ; i++)
    {
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
    __asm
    {
      mov   edx, pIdtDescriptor
      lidt  fword ptr [edx]
    }
}
