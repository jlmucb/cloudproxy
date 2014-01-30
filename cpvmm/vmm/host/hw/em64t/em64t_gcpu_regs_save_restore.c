/*
 * 
 *  Copyright (c) 2013 Intel Corporation
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

//RNB: Adding header for GUEST_CPU_SAVE_AREA and hw_cpu_id().
#include "guest_cpu_internal.h"
#include "vmm_defs.h"

// Assumption - hw_cpu_id() uses RAX only and returns host cpu id in ax

// pointer to the array of pointers to the GUEST_CPU_SAVE_AREA_PREFIX
extern GUEST_CPU_SAVE_AREA** g_guest_regs_save_area;

// include       ia32_registers.equ

// Define initial part of GUEST_CPU_SAVE_AREA structure
typedef struct {
    VMM_GP_REGISTERS gp; 
    VMM_XMM_REGISTERS xmm;
} PACKED GUEST_CPU_SAVE_AREA_PREFIX; 

/*
* This functions are part of the GUEST_CPU class.  They are called by
* assembler-lever VmExit/VmResume functions to save all registers that are not
* saved in VMCS but may be used immediately by C-language VMM code.
# The following registers are NOT saved here
#
#   RIP            part of VMCS RSP            part of VMCS RFLAGS         part
#   of VMCS segment regs   part of VMCS control regs   saved in C-code later
#   debug regs     saved in C-code later FP/MMX regs    saved in C-code later
#
# Assumptions: No free registers except of RSP/RFLAGS FS contains host CPU id
# (should be calculated)
#
#   RNB: Why FS should have CPU id, and how do those functions ensure.  AFAI
#   can tell the cpu id is %rax register
#
#
# Assumption - no free registers on entry, all are saved on exit
#
*/
void gcpu_save_registers(void) 
{
    UINT64                  cpuid= 0;
    UINT64                  oldrbx = 0ULL;
    GUEST_CPU_SAVE_AREA*    save_area= NULL;

    cpuid = hw_cpu_id();
    save_area= g_guest_regs_save_area[cpuid];

    asm volatile (
        "movq   %%rbx, %[oldrbx] \n\t"
        "movq   %[save_area], %%rbx\n\t"
        "movq   %%rax, (%%rbx) \n\t"
        "movq   %[oldrbx], %%rax \n\t"
        "movq   %%rax, 8(%%rbx) \n\t"
        "movq   %%rcx, 16(%%rbx) \n\t"
        "movq   %%rdx, 24(%%rbx) \n\t"
        "movq   %%rdi, 32(%%rbx) \n\t"
        "movq   %%rsi, 40(%%rbx) \n\t"
        "movq   %%rbp, 48(%%rbx) \n\t"
        "movq   %%r8, 64(%%rbx) \n\t"
        "movq   %%r9, 72(%%rbx) \n\t"
        "movq   %%r10, 80(%%rbx) \n\t"
        "movq   %%r11, 88(%%rbx) \n\t"
        "movq   %%r12, 96(%%rbx) \n\t"
        "movq   %%r13, 104(%%rbx) \n\t"
        "movq   %%r14, 112(%%rbx) \n\t"
        "movq   %%r15, 120(%%rbx) \n\t"
        //RNB: used 144...182 as offset instead of IA32_REG_GP_COUNT*8
        // JLM: how does %rsp get set?
        "movaps %%xmm0, 144(%%rbx) \n\t"
        "movaps %%xmm1, 152(%%rbx) \n\t"
        "movaps %%xmm2, 160(%%rbx) \n\t"
        "movaps %%xmm3, 168(%%rbx) \n\t"
        "movaps %%xmm4, 176(%%rbx) \n\t"
        "movaps %%xmm5, 182(%%rbx) \n\t"
        "movq   (%%rbx), %%rax \n\t"
        "movq %[oldrbx], %%rbx \n"
    : [oldrbx] "=m" (oldrbx)
    : [cpuid] "m" (cpuid), [save_area] "p" (save_area)
    :);

    return;
}


/*
 * Assumption - all free registers on entry, no free registers on exit
*/
void gcpu_restore_registers(void) 
{
    UINT64                  cpuid= 0;
    GUEST_CPU_SAVE_AREA*    save_area= NULL;

    cpuid = hw_cpu_id();
    save_area= g_guest_regs_save_area[cpuid];

    // restore all XMM first
    asm(
        "movq   %[save_area], %%rbx\n\t"
        "movaps 144(%%rbx), %%xmm0\n\t"
        "movaps 152(%%rbx), %%xmm1 \n\t"
        "movaps 160(%%rbx), %%xmm2 \n\t"
        "movaps 168(%%rbx), %%xmm3 \n\t"
        "movaps 176(%%rbx), %%xmm4 \n\t"
        "movaps 182(%%rbx), %%xmm5 \n\t"
        // RNB: rbx is restored at the end
        "movq   16(%%rbx), %%rcx \n\t"
        "movq   24(%%rbx), %%rdx \n\t"
        "movq   32(%%rbx), %%rdi \n\t"
        "movq   40(%%rbx),%%rsi \n\t"
        // RNB: rsp is not restored
        "movq   64(%%rbx), %%r8 \n\t"
        "movq   72(%%rbx), %%r9 \n\t"
        "movq   80(%%rbx), %%r10 \n\t"
        "movq   88(%%rbx), %%r11 \n\t"
        "movq   96(%%rbx), %%r12 \n\t"
        "movq   104(%%rbx), %%r13 \n\t"
        "movq   112(%%rbx), %%r14 \n\t"
        "movq   120(%%rbx), %%r15 \n\t"
        "movq   (%%rbx), %%rax \n\t"
        "movq   48(%%rbx), %%rbp \n\t"
        "movq   8(%%rbx), %%rbx \n"
    : 
    : [save_area] "p" (save_area)
    :);

   return;
}



