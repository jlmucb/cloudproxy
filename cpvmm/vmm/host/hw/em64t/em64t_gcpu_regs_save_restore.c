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
#include "../../../guest/guest_cpu/guest_cpu_internal.h"

// Assumption - hw_cpu_id() uses RAX only and returns host cpu id in ax

// pointer to the array of pointers to the GUEST_CPU_SAVE_AREA_PREFIX
extern GUEST_CPU_SAVE_AREA** g_guest_regs_save_area;

// include       ia32_registers.equ

// Define initial part of GUEST_CPU_SAVE_AREA structure
typedef struct {
    VMM_GP_REGISTERS gp; 
    VMM_XMM_REGISTERS xmm;
} GUEST_CPU_SAVE_AREA_PREFIX; 

/*
* Load pointer to the active GUEST_CPU_SAVE_AREA_PREFIX into rbx
* No other registers are modified
*/
void load_save_area_into_rbx(void) {

        int cpuid;
    // save RAX temporary
    // calculate host cpu id and put it into the rax (ax)
    cpuid = hw_cpu_id();
        asm("push %rax \n\t"
            //RNB: mov rax is probably not required, as the rax (cpuid) should do the trick.
            //      "mov %rax, %0 \n\t"
            // put pointer to the array of GUEST_CPU_SAVE_AREA_PREFIX* to RBX
            "mov  %rbx, g_guest_regs_save_area \n\t"
            "mov  %rbx, (%rbx) \n\t"
            // put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
            "mov  %rbx, (%rbx + sizeof qword * %rax) \n\t"
            // restore RAX
            "pop %rax"
            //RNB: this function has no output, but the below line is to satisfy the compiler
        :"=g" (cpuid)
        :"rax" (cpuid)
        :"rax", "rbx");
/*
    // put pointer to the array of GUEST_CPU_SAVE_AREA_PREFIX* to RBX
    asm("mov  %rbx, g_guest_regs_save_area");
    asm("mov  %rbx, (%rbx)");
    // put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
    asm("mov  %rbx, (%rbx + sizeof qword * %rax)");
    // restore RAX
    asm("pop %rax");
*/
    return;
}


/*
* This functions are part of the GUEST_CPU class.
* They are called by assembler-lever VmExit/VmResume functions
* to save all registers that are not saved in VMCS but may be used immediately
* by C-language VMM code.
# The following registers are NOT saved here
#
#   RIP            part of VMCS
#   RSP            part of VMCS
#   RFLAGS         part of VMCS
#   segment regs   part of VMCS
#   control regs   saved in C-code later
#   debug regs     saved in C-code later
#   FP/MMX regs    saved in C-code later
#
# Assumptions:
#   No free registers except of RSP/RFLAGS
#   FS contains host CPU id (should be calculated)
#
#

#
# Assumption - no free registers on entry, all are saved on exit
#
*/
void gcpu_save_registers(void) {
    // save RAX and RBX temporary on a stack
                GUEST_CPU_SAVE_AREA_PREFIX *gsap;
//              int gp_count = IA32_REG_GP_COUNT;
//              int xmm_count = IA32_REG_XMM_REGISTERS;
    asm("push %rbx");
    // put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
    load_save_area_into_rbx();
    // now save rax and rbx first
                
                asm("mov %0, %rbx \n\t" // this moves %rbx to gsap
                                "mov [%rbx], %rax \n\t"
                                "pop %rax \n\t" // this is %rbx
                                "mov 8[%rbx], %rax \n\t"
                                "mov 16[%rbx], %rcx \n\t"
                                "mov 24[%rbx], %rdx \n\t"
                                "mov 32[%rbx], %rdi \n\t"
                                "mov 40[%rbx], %rsi \n\t"
                                "mov 48[%rbx], %rbp \n\t"
                                "mov 64[%rbx], %r8 \n\t"
                                "mov 72[%rbx], %r9 \n\t"
                                "mov 80[%rbx], %r10 \n\t"
                                "mov 88[%rbx], %r11 \n\t"
                                "mov 96[%rbx], %r12 \n\t"
                                "mov 104[%rbx], %r13 \n\t"
                                "mov 112[%rbx], %r14 \n\t"
                                "mov 120[%rbx], %r15 \n\t"
        /* now save XMM registers
         * Depending on the compiler used, not all XMMs are needed to save/restore
         * Before any release, use dumpbin.exe to examine asm code and remove
         * the unused XMMs.
        */
//RNB: instead of using 144...182 as offset, it should be IA32_REG_GP_COUNT*8
                                "movaps 144[%rbx], %%xmm0 \n\t"
                                "movaps 152[%rbx], %%xmm1 \n\t"
                                "movaps 160[%rbx], %%xmm2 \n\t"
                                "movaps 168[%rbx], %%xmm3 \n\t"
                                "movaps 176[%rbx], %%xmm4 \n\t"
                                "movaps 182[%rbx], %%xmm5 \n\t"
//RNB: in the next two  lines (gsap) is to satisfy gcc
                                :"=r" (gsap)
                                :"r" (gsap)
                                :
                );

        /*
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RAX], %rax");
    asm("pop  %rax"); //   # this is rbx
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RBX], %rax");
    // now save all other GP registers except of RIP,RSP,RFLAGS
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RCX], %rcx");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RDX], %rdx");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RDI], %rdi");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RSI], %rsi");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RBP], %rbp");
    // skip RSP
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R8], %r8");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R9], %r9");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R10], %r10");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R11], %r11");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R12], %r12");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R13], %r13");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R14], %r14");
    asm("mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R15], %r15");
    // skip RIP
    // skip RFLAGS
*/     

        /* now save XMM registers
         * Depending on the compiler used, not all XMMs are needed to save/restore
         * Before any release, use dumpbin.exe to examine asm code and remove
         * the unused XMMs.
        */
                
/*
    asm("movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM0], %xmm0");
    asm("movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM1], %xmm1");
    asm("movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM2], %xmm2");
    asm("movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM3], %xmm3");
    asm("movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM4], %xmm4");
    asm("movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM5], %xmm5");
        */
    
    // done
    return;
}


/*
 * Assumption - all free registers on entry, no free registers on exit
*/
void gcpu_restore_registers(void) { 
    // put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
                int dummy;
    load_save_area_into_rbx();
    // restore all XMM first
                asm("movaps %%xmm0, 144[%rbx] \n\t"
                                "movaps %%xmm1, 152[%rbx] \n\t"
                                "movaps %%xmm2, 160[%rbx] \n\t"
                                "movaps %%xmm3, 168[%rbx] \n\t"
                                "movaps %%xmm4, 176[%rbx] \n\t"
                                "movaps %%xmm5, 182[%rbx] \n\t"
                                "mov [%rbx], %rax \n\t"
                                // RNB: rbx is restored at the end
                                "mov 16[%rbx], %rcx \n\t"
                                "mov 24[%rbx], %rdx \n\t"
                                "mov 32[%rbx], %rdi \n\t"
                                "mov 40[%rbx], %rsi \n\t"
                                "mov 48[%rbx], %rbp \n\t"
                                // RNB: rsp is not restored
                                "mov 64[%rbx], %r8 \n\t"
                                "mov 72[%rbx], %r9 \n\t"
                                "mov 80[%rbx], %r10 \n\t"
                                "mov 88[%rbx], %r11 \n\t"
                                "mov 96[%rbx], %r12 \n\t"
                                "mov 104[%rbx], %r13 \n\t"
                                "mov 112[%rbx], %r14 \n\t"
                                "mov 120[%rbx], %r15 \n\t"
                                "mov 8[%rbx], %rbx"
                                :"=r" (dummy)
                                :"r" (dummy)
                                :
                );
/*
    asm("movaps %xmm0, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM0]");
    asm("movaps %xmm1, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM1]");
    asm("movaps %xmm2, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM2]");
    asm("movaps %xmm3, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM3]");
    asm("movaps %xmm4, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM4]");
    asm("movaps %xmm5, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).xmm.reg[IA32_REG_XMM5]");
*/
        /*
    // restore all GP except of RBX
    // now save all other GP registers except of RIP,RSP,RFLAGS
    asm("mov  %rax, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RAX]");
    // RBX restore later
    asm("mov  %rcx, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RCX]");
    asm("mov  %rdx, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RDX]");
    asm("mov  %rdi, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RDI]");
    asm("mov  %rsi, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RSI]");
    asm("mov  %rbp, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RBP]");
    // skip RSP
    asm("mov  %r8,  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R8]");
    asm("mov  %r9,  (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R9]");
    asm("mov  %r10, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R10]");
    asm("mov  %r11, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R11]");
    asm("mov  %r12, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R12]");
    asm("mov  %r13, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R13]");
    asm("mov  %r14, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R14]");
    asm("mov  %r15, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_R15]");
    // skip RIP
    // skip RFLAGS
    // restore RBX
    asm("mov  %rbx, (GUEST_CPU_SAVE_AREA_PREFIX ptr [%rbx]).gp.reg[IA32_REG_RBX]");
*/
    // done
    return;
}
