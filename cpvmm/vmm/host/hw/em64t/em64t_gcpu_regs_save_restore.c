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
			// put pointer to the array of GUEST_CPU_SAVE_AREA_PREFIX* to RBX
			"movq  g_guest_regs_save_area, %%rbx \n\t"
			"movq  (%%rbx), %%rbx \n\t"
			// put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
//			"movq  (%%rbx + sizeof qword * %%rax), %%rbx \n\t"
			"movq  %%rbx (%%rax, sizeof qword), %%rbx \n\t"
            // restore RAX
			"pop %%rax"
			//RNB: this function has no output, but the below line is 
			//to satisfy the compiler
        :"=g" (cpuid)
        :"g" (cpuid)
        :"%rax", "%rbx"
	);
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
    asm volatile("push %%rbx"
			:::"rbx");
    // put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
    load_save_area_into_rbx();
    // now save rax and rbx first
                
		asm volatile(
			"movq %%rbx, %0 \n\t" // this moves %rbx to gsap
			"movq (%%rbx), %%rax \n\t"
			"pop %%rax \n\t" // this is %rbx
			"movq %%rax, 8(%%rbx) \n\t"
			"movq %%rcx, 16(%%rbx) \n\t"
			"movq %%rdx, 24(%%rbx) \n\t"
			"movq %%rdi, 32(%%rbx) \n\t"
			"movq %%rsi, 40(%%rbx) \n\t"
			"movq %%rbp, 48(%%rbx) \n\t"
			"movq %%r8, 64(%%rbx) \n\t"
			"movq %%r9, 72(%%rbx) \n\t"
			"movq %%r10, 80(%%rbx) \n\t"
			"movq %%r11, 88(%%rbx) \n\t"
			"movq %%r12, 96(%%rbx) \n\t"
			"movq %%r13, 104(%%rbx) \n\t"
			"movq %%r14, 112(%%rbx) \n\t"
			"movq %%r15, 120(%%rbx) \n\t"
      /* now save XMM registers
        * Depending on the compiler used, not all XMMs are needed to save/restore
        * Before any release, use dumpbin.exe to examine asm code and remove
        * the unused XMMs.
        */
//RNB: instead of using 144...182 as offset, it should be IA32_REG_GP_COUNT*8
			"movaps %%xmm0, 144(%%rbx) \n\t"
			"movaps %%xmm1, 152(%%rbx) \n\t"
			"movaps %%xmm2, 160(%%rbx) \n\t"
			"movaps %%xmm3, 168(%%rbx) \n\t"
			"movaps %%xmm4, 176(%%rbx) \n\t"
			"movaps %%xmm5, 182(%%rbx) \n\t"
//RNB: in the next two  lines (gsap) is to satisfy gcc
			:"=g" (gsap)
			:"g" (gsap)
			:
		);

    return;
}


/*
 * Assumption - all free registers on entry, no free registers on exit
*/
void gcpu_restore_registers(void) { 
    // put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
  load_save_area_into_rbx();
    // restore all XMM first
	asm("movaps 144(%%rbx), %%xmm0\n\t"
			"movaps 152(%%rbx), %%xmm1 \n\t"
			"movaps 160(%%rbx), %%xmm2 \n\t"
      "movaps 168(%%rbx), %%xmm3 \n\t"
      "movaps 176(%%rbx), %%xmm4 \n\t"
      "movaps 182(%%rbx), %%xmm5 \n\t"
      "mov %%rax, (%%rbx) \n\t"
      // RNB: rbx is restored at the end
      "movq %%rcx, 16(%%rbx) \n\t"
      "movq %%rdx, 24(%%rbx) \n\t"
      "movq %%rdi, 32(%%rbx) \n\t"
      "movq %%rsi, 40(%%rbx) \n\t"
      "movq %%rbp, 48(%%rbx) \n\t"
      // RNB: rsp is not restored
      "movq %%r8, 64(%%rbx) \n\t"
      "movq %%r9, 72(%%rbx) \n\t"
      "movq %%r10, 80(%%rbx) \n\t"
      "movq %%r11, 88(%%rbx) \n\t"
      "movq %%r12, 96(%%rbx) \n\t"
      "movq %%r13, 104(%%rbx) \n\t"
      "movq %%r14, 112(%%rbx) \n\t"
      "movq %%r15, 120(%%rbx) \n\t"
      "movq %%rbx, 8(%%rbx) "
     :::
   );
   return;
}
