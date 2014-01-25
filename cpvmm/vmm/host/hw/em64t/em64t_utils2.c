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


/*
 * Register usage
	*
	* Caller-saved and scratch:
	*        RAX, RCX, RDX, R8, R9, R10, R11
	*
	* Callee-saved
	*        RBX, RBP, RDI, RSI, R12, R13, R14, and R15
	*
	*  void __stdcall
	*  hw_lgdt (
	*          void * gdtr
	*  );
	*
	*  Load GDTR (from buffer pointed by RCX)
	.set    ARG1_U8, %cl
	.set    ARG1_U16, % cx
	.set    ARG1_U32, %ecx
	.set    ARG1_U64, %rcx
	.set    ARG2_U8, %dl
	.set    ARG2_U16, %dx
	.set    ARG2_U32, %edx
	.set    ARG2_U64, %rdx
	.set    ARG3_U32, %r8d
	.set    ARG3_U64, %r8
*/

#include "hw_utils.h"
#include "vmm_defs.h"

typedef struct {
    unsigned long P_RAX;
    unsigned long P_RBX;
    unsigned long P_RCX;
    unsigned long P_RDX;
    unsigned long P_RSI;
    unsigned long P_RDI;
    unsigned long P_RFLAGS;
} SMI_PORT_PARAMS;  

SMI_PORT_PARAMS spp;

/*
typedef struct {
    unsigned long M_RAX;
    unsigned long M_RBX;
    unsigned long M_RCX;
    unsigned long M_RDX;
} CPUID_PARAMS;
*/
CPUID_PARAMS cp;

void  hw_lgdt (void *gdtr) {

	 asm volatile("lgdt (%0)\n"
		:
		:"rcx" (gdtr)
	  :"rcx"
	);
	return;
}

void hw_sgdt (void * gdtr) {
//  Store GDTR (to buffer pointed by RCX)
	 asm volatile("sgdt (%0)"
		:
		:"rcx" (gdtr)
		:"rcx"
	);
	return;
}

/*  Read Command Segment Selector
 *  Stack offsets on entry:
 *  ax register will contain result
*/
UINT16 hw_read_cs () {
		
	UINT16 ret = 0;
	 asm volatile("xor %%rax, %%rax \n\t"
       "movw %%ax, %%cs \n\t"
			:"=rm" (ret)
			:"rm" (ret)
			:"cc", "memory");
	return ret;
}

//RNB: I am not 100% sure about "jumping to a label" part.
void hw_write_cs (UINT16 i) { 
        // push segment selector
		asm volatile("xor %%rax, %%rax \n\t"
        "movw %0, %%ax \n\t"
        "shlq $32, %%rax \n\t"
        "lea L_CONT_WITH_NEW_CS, %%rdx \n\t"
        "add %%rdx, %%rax \n\t"
        "push %%rax \n\t"
        "lret \n\t" //brings IP to CONT_WITH_NEW_CS
				"L_CONT_WITH_NEW_CS: \n\t"
        "ret"
				:"=g" (i)
				:"g" (i)
				:"rax", "rdx"
		);
}

/*  UINT16 __stdcall
 *  hw_read_ds (
 *          void
 *  );
 *
 *  Read Data Segment Selector
 *
 *  Stack offsets on entry:
 *
 *  ax register will contain result
 */
UINT16 hw_read_ds () {
	UINT16 ret = 0;
	 asm volatile("xor %%rax, %%rax \n\t"
			"mov %%ds, %%ax \n\t"
			"mov %%ax, %0 \n\t"
			:
			:"rm"(ret)
			:"cc", "memory"
	);
	return;
}

//
//  void __stdcall
//  hw_write_ds (
//          UINT16
//  );
//
//  Write to Data Segment Selector
void hw_write_ds(UINT16 i) {
	 asm volatile("mov %0, %%ds \n\t"
			://"=r" (i)
			:"g" (i)
			:
	);
	return;
}

//
//  UINT16 __stdcall
//  hw_read_es (
//          void
//  );
//
//  Read ES Segment Selector
//
//  Stack offsets on entry:
//
//  ax register will contain result
//
UINT16 hw_read_es() {

	 asm volatile("xor %%rax, %%rax \n\t"
			"mov %%es, %%ax \n\t"
			:::
	);
	return;
}

//
//  void __stdcall
//  hw_write_es (
//          UINT16
//  );
//
//  Write to ES Segment Selector
//
void hw_write_es (UINT16 i) { 
	 asm volatile("mov %0, %%es"
			:
			:"r" (i)
			:
	);
	return;
}
//
//  UINT16 __stdcall
//  hw_read_ss (
//          void
//  );
//
//  Read Stack Segment Selector
//
//  ax register will contain result
//
UINT16 hw_read_ss() {
	UINT16 ret;
	 asm volatile("xor %%rax, %%rax \n\t"
      "mov %%es, %%ax \n\t"
      "mov %%ax, %0 \n\t"
			::"rm"(ret)
			:"cc", "memory"
	);
	return;
}

//
//  void __stdcall
//  hw_write_ss (
//          UINT16
//  );
//
//  Write to Stack Segment Selector
//
void hw_write_ss (UINT16 i) { 
	 asm volatile("mov %0, %%ss"
			:
			:"r" (i)
			:
	);
	return;
}
//
//  UINT16 __stdcall
//  hw_read_fs (
//          void
//  );
//
//  Read FS
//
//  ax register will contain result
//
UINT16 hw_read_fs() {
	 asm volatile("xor %%rax, %%rax \n\t"
      "mov %%fs, %%ax \n\t"
			:::
	);
	return;
}

//
//  void __stdcall
//  hw_write_fs (
//          UINT16
//  );
//
//  Write to FS
//
void hw_write_fs (UINT16 i) { 
	 asm volatile("mov %0, %%fs"
			:
			:"r" (i)
			:
	);
	return;
}
//
//  UINT16 __stdcall
//  hw_read_gs (
//          void
//  );
//
//  Read GS
//
//  ax register will contain result
//
UINT16 hw_read_gs() {
	 asm volatile("xor %%rax, %%rax \n\t"
      "mov %%gs, %%ax \n\t"
			:::
	);
	return;
}

//
//  void __stdcall
//  hw_write_gs (
//          UINT16
//  );
//
//  Write to GS
//
void hw_write_gs (UINT16 i) { 
	 asm volatile("mov %0, %%gs"
			:
			:"r" (i)
			:
	);
	return;
}
/* 
 *  UINT64 __stdcall
 *  hw_read_rsp (void);
*/
UINT64 hw_read_rsp () {
		
	UINT64 ret = 0;
		 asm volatile("movq %%rsp, %%rax \n\t"
        "add %%rax, 8 \n\t"
				"movq %%rax, %0 \n\t"
		::"rm"(ret) 
		: "cc", "memory"
		);
	return ret;

}
//RNB: TODO the args/offsets need to be double-checked
void hw_write_to_smi_port(
    UINT64 * p_rax,     // rcx
    UINT64 * p_rbx,     // rdx
    UINT64 * p_rcx,     // r8
    UINT64 * p_rdx,     // r9
    UINT64 * p_rsi,     // on the stack
    UINT64 * p_rdi,     // on the stack
    UINT64 * p_rflags) // on the stack
{
        // save callee saved registers
	 asm volatile("push %%rbp \n\t"
			"mov %%rbp, %%rsp \n\t" //setup stack frame pointer
			"push %%rbx \n\t"
			"push %%rdi \n\t"
			"push %%rsi \n\t"
			"push %%r12 \n\t"
			"push %%r13 \n\t"
			"push %%r14 \n\t"
			"push %%r15 \n\t"
			"lea 16(%%rbp), %%r15 \n\t"//set r15 to point to SMI_PORT_PARAMS struct
			// normalize stack \n\t"
			"mov %%rcx, (%%r15) \n\t"
			"mov %%rdx, 8(%%r15) \n\t"
			"mov %%r8, 16(%%r15) \n\t"
			"mov %%r9, 24(%%r15) \n\t"
			//copy emulator registers into CPU
			/* RNB: this code can be shortened to just 1 mov for each register
		   * mov (%%r15), %%rax, mov 8(%%r15), %%rbx, and so on
			 */
			"mov (%%r15), %%r8 \n\t"
			"mov (%%r8), %%rax\n\t"
			"mov 8(%%r15), %%r8 \n\t"
			"mov (%%r8), %%rbx \n\t"
			"mov 16(%%r15), %%r8\n\t"
			"mov (%%r8), %%rcx \n\t"
			"mov 24(%%r15), %%r8\n\t"
			"mov (%%r8), %%rdx\n\t"
			"mov 32(%%r15), %%r8 \n\t"
			"mov (%%r8), %%rsi \n\t"
			"mov 40(%%r15), %%r8 \n\t"
			"mov (%%r8), %%rdi \n\t"
			"mov 48(%%r15), %%r8 \n\t"
			"push (%%r8) \n\t"
			"popfq \n\t" //rflags = *p_rflags

			//we assume that sp will not change after SMI

			"push %%rbp \n\t"
			"push %%r15 \n\t"
//			"out %%dx, %%al \n\t"
			"out %%al, %%dx \n\t"
			"pop %%r15 \n\t"
			"pop %%rbp \n\t"
			//fill emulator registers from CPU
			"mov (%%r15), %%r8 \n\t"
			"mov %%rax, (%%r8) \n\t"
			"mov 8(%%r15), %%r8 \n\t"
			"mov %%rbx, (%%r8) \n\t"
			"mov 16(%%r15), %%r8\n\t"
			"mov %%rcx, (%%r8) \n\t"
			"mov 24(%%r15), %%r8 \n\t"
			"mov %%rdx, (%%r8) \n\t"
			"mov 32(%%r15), %%r8\n\t"
			"mov %%rsi, (%%r8) \n\t"
			"mov 40(%%r15), %%r8 \n\t"
			"mov %%rdi, (%%r8) \n\t"
			"mov 48(%%r15), %%r8 \n\t"
			"pushfq \n\t"
			"pop (%%r8) \n\t" // *p_rflags = rflags
			//restore callee saved registers
			"pop %%r15 \n\t"
			"pop %%r14 \n\t"
			"pop %%r13 \n\t"
			"pop %%r12 \n\t"
			"pop %%rsi \n\t"
			"pop %%rdi \n\t"
			"pop %%rbx \n\t"
			"pop %%rbp \n\t"
//			"ret \n\t"
			:::
	);
	return;
}

/*
 *  void __stdcall
 *  hw_enable_interrupts (void);
 */

void hw_enable_interrupts () {
	asm volatile("sti");
	return;
}

/*
 *  void __stdcall
 *  hw_disable_interrupts (void);
 */
void hw_disable_interrupts () {
	asm volatile("cli");
	return;
}

/*
 *  void __stdcall
 *  hw_fxsave (void* buffer);
 */
void hw_fxsave (void *buffer) {
	asm volatile("fxsave %0"
		:"=m" (buffer)
		:"m" (buffer)
		:
	);
	return;
}

/*
 *  void __stdcall
 *  hw_fxrestore (void* buffer);
 */
void hw_fxrestore (void *buffer) {
	asm volatile("fxrstor %0"
		:"=m" (buffer)
		:"m" (buffer)
		:
	);
	return;
}

/*
 *  void __stdcall
 *  hw_write_cr2 (UINT64 value);
 */
void hw_write_cr2 (UINT64 value) {
	asm volatile("mov %%cr2, %0"
		:"=rm" (value)
		:"rm" (value)
		:"cc", "memory"
	);
		
	return;
}
/*
 * UINT16 __stdcall
 * hw_cpu_id (
 *	void
 *  );
 *
 *  Read TR and calculate cpu_id
 *
 *  ax register will contain result
 *
 *  IMPORTANT NOTE: only RAX regsiter may be used here !!!!
 *                  This assumption is used in gcpu_regs_save_restore.asm
 */
#define CPU_LOCATOR_GDT_ENTRY_OFFSET 32
#define TSS_ENTRY_SIZE_SHIFT 4
UINT16 hw_cpu_id () {
	UINT16 ret = 0;

	asm volatile("xor %%rax, %%rax \n\t"
        			"str %%ax \n\t"
        			"sub $32 , %%ax \n\t" // CPU_LOCATOR_GDT_ENTRY_OFFSET is 48
        			"shrw $4, %%ax \n\t" //TSS_ENTRY_SIZE_SHIFT is 4
							:"=rax" (ret)
							:"rax" (ret)
							:"rax"
	);
	return ret;
}
/*
 * UINT16 __stdcall
 * hw_read_tr (
 *          void
 *  );
 *
 *  Read Task Register
 *
 *  ax register will contain result
 */
UINT16 hw_read_tr() {
	UINT16 ret = 0;
//RNB: Added the movw instruction to move the return value into 'ret'
	asm volatile("str %%ax \n\t"
							"movw %%ax, %0 \n\t"
							:"=r" (ret)
							:"r" (ret)
							:
	);
	return ret;
}
/*
 *  void __stdcall
 *  hw_write_tr (
 *          UINT16
 *  );
 *  Write Task Register
 *
 */
void hw_write_tr (UINT16 i) {
	asm volatile("ltr %0"
							:"=r" (i)
							:"r" (i)
							:
	);
	return;
}

/*
 *  UINT16 __stdcall
 *  hw_read_ldtr (
 *          void
 *  );
 *
 *  Read LDT Register
 *
 *  ax register will contain result
 */
UINT16 hw_read_ldtr () {
	UINT16 ret = 0;
//RNB: Added the movw instruction to move the return value into 'ret'
	asm volatile("sldt %%ax \n\t"
							:"=rax" (ret)
							:"rax" (ret)
							:"rax"
	);
	return ret;
}
/*
 *  void __stdcall
 *  hw_write_ldtr (
 *          UINT16
 *  );
 *
 *  Write LDT Register
 */
void hw_write_ldtr (UINT16 i) {
	asm volatile("lldt %0"
							:"=r" (i)
							:"r" (i)
							:
	);
	return;
}

/*
 *  void __stdcall
 *  hw_cpuid (CPUID_PARAMS *)
 *
 *  Execute cpuid instruction
*/
void hw_cpuid (CPUID_PARAMS *cp) {

	 asm volatile("mov %%rcx, %%r8 \n\t" //RNB: address of struct is assumed to be in %%rcx
			"mov %%rbx, %%r9 \n\t" //    # save RBX
        //# fill regs for cpuid
			"mov (%%r8), %%rax \n\t"
			"mov 8(%%r8), %%rbx \n\t"
			"mov 16(%%r8), %%rcx \n\t"
			"mov 24(%%r8), %%rdx \n\t"
			"cpuid \n\t"
			"mov %%rax, (%%r8) \n\t"
			"mov %%rbx, 8(%%r8) \n\t"
			"mov %%rcx, 16(%%r8) \n\t"
			"mov %%rdx, 24(%%r8) \n\t"
			"mov %%r9, %%rbx \n\t"
			"mov %%r8, %%rcx \n\t"
			:::
	);

	return;
}

/*
 *  void __stdcall
 *  hw_leave_64bit_mode ();
 *  Arguments:   UINT32 compatibility_segment  CX
 *               UINT16 port_id                DX
 *               UINT16 value                  R8
 *               UINT32 cr3_value              R9
 */
/*
void hw_leave_64bit_mode (unsigned int compatibility_segment, 
													unsigned short int port_id,
													unsigned short int value,
													unsigned int cr3_value) 
{

        jmp $

        shl rcx, 32             ;; prepare segment:offset pair for retf by shifting
                                ;; compatibility segment in high address
        lea rax, compat_code    ;; and
        add rcx, rax            ;; placing offset into low address
        push rcx                ;; push ret address onto stack
        mov  rsi, rdx           ;; rdx will be used during EFER access
        mov  rdi, r8            ;; r8 will be unaccessible, so use rsi instead
        mov  rbx, r9            ;; save CR3 in RBX. this function is the last called, so we have not to save rbx
        retf                    ;; jump to compatibility mode
compat_code:                    ;; compatibility mode starts right here

        mov rax, cr0            ;; only 32-bit are relevant
        btc eax, 31             ;; disable IA32e paging (64-bits)
        mov cr0, rax            ;;

        ;; now in protected mode
        mov ecx, 0C0000080h     ;; EFER MSR register
        rdmsr                   ;; read EFER into EAX
        btc eax, 8              ;; clear EFER.LME
        wrmsr                   ;; write EFER back

;        mov cr3, rbx            ;; load CR3 for 32-bit mode
;
;        mov rax, cr0            ;; use Rxx notation for compiler, only 32-bit are valuable
;        bts eax, 31             ;; enable IA32 paging (32-bits)
;        mov cr0, rax            ;;
;        jmp @f

;; now in 32-bit paging mode
        mov rdx, rsi
        mov rax, rdi
        out dx, ax              ;; write to PM register
        ret                     ;; should never get here
} //hw_leave_64bit_mode
*/


/*------------------------------------------------------------------------------
;  void
;  hw_perform_asm_iret(void);
;------------------------------------------------------------------------------
; Transforms stack from entry to reglar procedure: 
;
; [       RIP        ] <= RSP
;
; To stack  to perform iret instruction:
; 
; [       SS         ]
; [       RSP        ]
; [      RFLAGS      ]
; [       CS         ]
; [       RIP        ] <= RSP should point prior iret
*/

void hw_perform_asm_iret () {
	asm volatile(
			"sub $0x20, %%rsp \n\t" //prepare space for "interrupt stack"
			"push %%rax \n\t" //save scratch registers
			"push %%rbx \n\t"
			"push %%rcx \n\t"
			"push %%rdx \n\t"
			"addq $0x40, %%rsp \n\t" // get rsp back to RIP
			"pop %%rax \n\t" //RIP -> RAX
			"movq %%cs, %%rbx \n\t" //; CS  -> RBX
			"movq %%rsp, %%rcx \n\t" // good RSP -> RCX
			"movq %%ss, %%rdx \n\t" //; CS  -> RDX
			"push %%rdx \n\t" //[       SS         ]
			"push %%rcx \n\t" //[       RSP        ]
			"pushfq \n\t"  //[      RFLAGS      ]
			"push %%rbx \n\t" //[       CS         ]
			"push %%rax \n\t"  //[       RIP        ]

			"subq $0x20, %%rsp \n\t" //restore scratch registers
			"pop %%rdx \n\t"
			"pop %%rcx \n\t"
			"pop %%rbx \n\t"
			"pop %%rax \n\t" // now RSP is in right position 
			"iretq " //                   ; perform IRET
		:::
	);
} //hw_perform_asm_iret ENDP
void hw_set_stack_pointer (HVA new_stack_pointer, 
													main_continue_fn func, void *params) {
	asm volatile("L1: \n\t"
							"movq %0, %%rsp \n\t"
							"movq %2, %0 \n\t"
							"subq $32, %%rsp \n\t" // allocate home space for 4 input params
							"call %1 \n\t" 
							"jmp L1"
							:
							:"r"(new_stack_pointer),"r"(func), "r"(params)
							:"cc"
	);
	return;
}
