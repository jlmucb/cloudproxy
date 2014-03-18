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

#include "vmm_defs.h"
#include "ia32_defs.h"
#include "ia32_low_level.h"

/*
 *
 * Register usage
 *
 * Caller-saved and scratch:
 *    eax
 *    edx
 *    ecx
 *
 * Callee-saved
 *    ebp
 *    ebx
 *    esi
 *    edi
 *    esp
 */


UINT32 CDECL ia32_read_cr0(void)
{
    __asm   mov  eax, cr0
}

void CDECL ia32_write_cr0(UINT32 value)
{
    __asm
    {
        mov   eax, value
        mov   cr0, eax
    }
}

UINT32 CDECL ia32_read_cr2(void)
{
	__asm	mov  eax, cr2
}

UINT32 CDECL ia32_read_cr3(void)
{
	__asm	mov  eax, cr3
}

void CDECL ia32_write_cr3(UINT32 value)
{
	__asm
	{
		mov   eax, value
		mov   cr3, eax
	}
}

UINT32 CDECL ia32_read_cr4(void)
{
	__asm
	{
		_emit 0x0F
		_emit 0x20
		_emit 0xE0	;; mov eax, cr4
	}
}

void CDECL ia32_write_cr4(UINT32 value)
{
	__asm
	{
		mov eax, value
		_emit 0x0F
		_emit 0x22
		_emit 0xE0	;; mov cr4, eax
	}
}


void CDECL ia32_read_gdtr(IA32_GDTR *p_descriptor)
{
	__asm
	{
		mov   edx, p_descriptor
		sgdt  [edx]
	}
}

void CDECL ia32_write_gdtr(IA32_GDTR *p_descriptor)
{
	__asm
	{
		mov   edx, p_descriptor
		lgdt  fword ptr [edx]
	}
}

void CDECL ia32_read_idtr(IA32_IDTR *p_descriptor)
{
	__asm
	{
		mov   edx, p_descriptor
		sidt  [edx]
	}
}

void CDECL ia32_write_idtr(IA32_IDTR *p_descriptor)
{
	__asm
	{
		mov   edx, p_descriptor
		lidt  fword ptr [edx]
	}
}

UINT16 CDECL ia32_read_ldtr(void)
{
	__asm
	{
		sldt  ax
	}
}

UINT16 CDECL ia32_read_tr(void)
{
	__asm
	{
		str  ax
	}
}

void CDECL ia32_read_msr(UINT32 msr_id, UINT64 *p_value)
{
    __asm
    {
    mov     ecx, msr_id
    rdmsr       ;; read MSR[ecx] into EDX:EAX
    mov     ecx, p_value
    mov     dword ptr [ecx], eax
    mov     dword ptr [ecx + 4], edx
    }
}

void CDECL ia32_write_msr(UINT32 msr_id, UINT64 *p_value)
{
    __asm
    {
    mov     ecx, p_value
    mov     eax, dword ptr [ecx]
    mov     edx, dword ptr [ecx + 4]
    mov     ecx, msr_id
    wrmsr       ;; write from EDX:EAX into MSR[ECX]
    }
}

UINT32 CDECL ia32_read_eflags(void)
{
    __asm
    {
    pushfd
    pop eax
    }
}

UINT16 CDECL ia32_read_cs(void)
{
	__asm
	{
		mov  ax, cs
	}
}

UINT16 CDECL ia32_read_ds(void)
{
	__asm
	{
		mov  ax, ds
	}
}

UINT16 CDECL ia32_read_es(void)
{
	__asm
	{
		mov  ax, es
	}
}

UINT16 CDECL ia32_read_fs(void)
{
	__asm
	{
		mov  ax, fs
	}
}

UINT16 CDECL ia32_read_gs(void)
{
	__asm
	{
		mov  ax, gs
	}
}

UINT16 CDECL ia32_read_ss(void)
{
	__asm
	{
		mov  ax, ss
	}
}

void CDECL ia32_cpu_id(int CPUInfo[4], int InfoType)
{
    __asm
    {
        push ebx
        push edi

        mov  eax, InfoType
        cpuid

        mov  edi, CPUInfo
        mov  dword ptr [edi][CPUID_EAX * 4], eax
        mov  dword ptr [edi][CPUID_EBX * 4], ebx
        mov  dword ptr [edi][CPUID_ECX * 4], ecx
        mov  dword ptr [edi][CPUID_EDX * 4], edx

        pop  edi
        pop  ebx
    }
}

