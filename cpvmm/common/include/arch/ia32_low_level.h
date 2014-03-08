/*
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
 */

#ifndef _IA32_LOW_LEVEL_H_
#define _IA32_LOW_LEVEL_H_

#include "ia32_defs.h"

UINT32 CDECL ia32_read_cr0(void);
void   CDECL ia32_write_cr0(UINT32 value);
UINT32 CDECL ia32_read_cr2(void);
UINT32 CDECL ia32_read_cr3(void);
void   CDECL ia32_write_cr3(UINT32 value);
UINT32 CDECL ia32_read_cr4(void);
void   CDECL ia32_write_cr4(UINT32 value);
void   CDECL ia32_write_gdtr(IA32_GDTR *p_descriptor);
void   CDECL ia32_read_gdtr(IA32_GDTR *p_descriptor);
void   CDECL ia32_read_idtr(IA32_IDTR *p_descriptor);
void   CDECL ia32_write_idtr(IA32_IDTR *p_descriptor);
UINT16 CDECL ia32_read_ldtr(void);
UINT16 CDECL ia32_read_tr(void);
void   CDECL ia32_read_msr(UINT32 msr_id, UINT64 *p_value);
void   CDECL ia32_write_msr(UINT32 msr_id, UINT64 *p_value);
UINT32 CDECL ia32_read_eflags(void);
UINT16 CDECL ia32_read_cs(void);
UINT16 CDECL ia32_read_ds(void);
UINT16 CDECL ia32_read_es(void);
UINT16 CDECL ia32_read_fs(void);
UINT16 CDECL ia32_read_gs(void);
UINT16 CDECL ia32_read_ss(void);

// CPUID

extern void __cpuid(int CPUInfo[4], int InfoType);  // compiler intrinsic
#define CPUID_EAX 0
#define CPUID_EBX 1
#define CPUID_ECX 2
#define CPUID_EDX 3
#define ia32_cpuid  __cpuid

void CDECL ia32_cpu_id(int CPUInfo[4], int InfoType);
               // This function is for use when the compiler intrinsic
               // is not available

#endif // _IA32_LOW_LEVEL_H_

