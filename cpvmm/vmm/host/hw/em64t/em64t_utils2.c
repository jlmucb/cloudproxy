/*
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

typedef struct {
    unsigned long M_RAX;
    unsigned long M_RBX;
    unsigned long M_RCX;
    unsigned long M_RDX;
} CPUID_PARAMS;

CPUID_PARAMS cp;

void  hw_lgdt (void *gdtr) {

	asm("lgdt (%0)\n"
		:
		:"rcx" (gdtr)
	  :"rcx"
	);
	return;
}

void hw_sgdt (void * gdtr) {
//  Store GDTR (to buffer pointed by RCX)
	asm("sgdt (%0)"
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
int hw_read_cs () {
		
	int ret = 0;
	asm("xor %%rax, %%rax \n\t"
       "mov %%ax, %%cs \n\t"
			:"=ax" (ret)
			::"rax");
	return ret;
}


//  UINT16 __stdcall
//  hw_read_ds (
//          void
//  );
//
//  Read Data Segment Selector
//
//  Stack offsets on entry:
//
//  ax register will contain result
//
void hw_read_ds () {
	asm("xor %%rax, %%rax \n\t"
			"mov %%ds, %%ax \n\t"
			:::
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
/*
void hw_write_ds(int i) {
	asm("mov %0, %%ds \n\t"
			:::
	);
	return;
}
*/

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
void hw_read_es() {

	asm("xor %%rax, %%rax \n\t"
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
/*
void hw_write_es (short int i) { 
	asm("mov %%0, %%es"
			:::
	);
	return;
}
*/
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
void hw_read_ss() {
	asm("xor %%rax, %%rax \n\t"
      "mov %%es, %%ax \n\t"
			:::
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
/*
void hw_write_ss (short int i) { 
	asm("mov %%0, %%ss"
			:::
	);
	return;
}
*/
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
void hw_read_fs() {
	asm("xor %%rax, %%rax \n\t"
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
/*
void hw_write_fs (short int i) { 
	asm("mov %%0, %%fs"
			:::
	);
	return;
}
*/
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
void hw_read_gs() {
	asm("xor %%rax, %%rax \n\t"
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
/*
void hw_write_gs (short int i) { 
	asm("mov %%0, %%gs"
			:::
	);
	return;
}
*/
/* 
 *  UINT64 __stdcall
 *  hw_read_rsp (void);
*/
void hw_read_rsp () {
		
		asm("mov %%rsp, %%rax \n\t"
        "add %%rax, 8 \n\t"
		:::
		);
	return;

}
void hw_write_to_smi_port() {
        // save callee saved registers
	asm("push %%rbp \n\t"
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
 *  hw_cpuid (CPUID_PARAMS *)
 *
 *  Execute cpuid instruction
*/
void hw_cpuid (CPUID_PARAMS *cp) {

	asm("mov %%rcx, %%r8 \n\t" //RNB: address of struct is assumed to be in %%rcx
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
