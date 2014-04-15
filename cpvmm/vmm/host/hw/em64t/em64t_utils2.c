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
} PACKED SMI_PORT_PARAMS;  

SMI_PORT_PARAMS spp;

CPUID_PARAMS cp;

void  hw_lgdt (void *gdtr) {
     asm volatile(
        "lgdt (%[gdtr])\n"
     : :[gdtr] "p" (gdtr)
     :);
    return;
}

void hw_sgdt (void * gdtr) {
    //  Store GDTR (to buffer pointed by RCX)
    asm volatile(
        "\tsgdt (%[gdtr])\n"
    : :[gdtr] "p" (gdtr)
    :);
        return;
}

/*  
 *  Read Command Segment Selector
 *  Stack offsets on entry:
 *  ax register will contain result
 */
UINT16 hw_read_cs () {
                
    UINT16 ret = 0;

    asm volatile(
        "\txor %%rax, %%rax\n"
        "\tmovw %%cs, %%ax\n"
        "\tmovw %%ax, %[ret]\n"
    :"=rm" (ret)
    :[ret] "rm" (ret)
    :"cc", "rax", "memory");
    return ret;
}

//RNB: I am not 100% sure about "jumping to a label" part.
void hw_write_cs (UINT16 i) { 
    // push segment selector
    asm volatile (
        "\txor %%rax, %%rax\n"
        "\tmovw %[i], %%ax\n"
        "\tshlq $32, %%rax\n"
        "\tlea L_CONT_WITH_NEW_CS, %%rdx\n"
        "\tadd %%rdx, %%rax\n"
        "\tpush %%rax\n"
        "\tlret\n" //brings IP to CONT_WITH_NEW_CS
        "\tL_CONT_WITH_NEW_CS:\n"
        "\tret\n"
    : :[i] "m" (i)
    :"rax", "rdx");
}

/*  
 *  UINT16 hw_read_ds ( void);
 *  Read Data Segment Selector
 *  Stack offsets on entry:
 *  ax register will contain result
 */
UINT16 hw_read_ds () {
    UINT16 ret = 0;

    asm volatile(
        "\txor %%rax, %%rax\n"
        "\tmovw %%ds, %%ax\n"
        "\tmovw %%ax, %[ret]\n"
    :[ret] "=g" (ret)
    : :"cc", "memory");
    return ret;
}

//
//  void hw_write_ds ( UINT16);
//  Write to Data Segment Selector
void hw_write_ds(UINT16 i) {
    asm volatile(
        "\tmovw %[i], %%ds\n"
    :
    :[i] "g" (i) :);
    return;
}

//
//  UINT16 hw_read_es ( void);
//  Read ES Segment Selector
//  Stack offsets on entry:
//  ax register will contain result
UINT16 hw_read_es() {

    UINT16 ret = 0;

     asm volatile(
        "\txor %%rax, %%rax\n"
        "\tmovw %%es, %%ax\n"
        "\tmovw %%ax, %[ret]\n"
    :[ret] "=g" (ret)
    ::);
    return ret;
}

//
//  void hw_write_es ( UINT16);
//  Write to ES Segment Selector
void hw_write_es (UINT16 i) { 
    asm volatile(
        "\tmovw %[i], %%es\n"
    :
    :[i] "g" (i)
    :);
    return;
}
//
//  UINT16 hw_read_ss ( void);
//  Read Stack Segment Selector
//  ax register will contain result
UINT16 hw_read_ss() {
    UINT16 ret = 0;

    asm volatile(
        "\txor %%rax, %%rax\n"
        "\tmovw %%es, %%ax\n"
        "\tmovw %%ax, %[ret]\n"
    :[ret] "=g" (ret)
    ::);
    return ret;
}

//
//  void hw_write_ss ( UINT16);
//  Write to Stack Segment Selector
void hw_write_ss (UINT16 i) { 
    asm volatile(
        "\tmovw %[i], %%ss\n"
    : :[i] "g" (i)
    :);
    return;
}


//
//  UINT16 hw_read_fs ( void);
//  Read FS
//  ax register will contain result
UINT16 hw_read_fs() {
    UINT16 ret = 0;

    asm volatile(
        "\txor %%rax, %%rax\n"
        "\tmovw %%fs, %%ax\n"
        "\tmovw %%ax, %[ret]\n"
    :[ret] "=g" (ret)
    :
    :"rax");
    return ret;
}

//
//  void hw_write_fs ( UINT16);
//  Write to FS
void hw_write_fs (UINT16 i) { 
    asm volatile(
        "\tmovw %[i], %%fs\n"
    :
    :[i] "r" (i)
    :);
    return;
}


//  UINT16 hw_read_gs ( void);
//  Read GS
//  ax register will contain result
UINT16 hw_read_gs() {
    UINT16 ret = 0;

    asm volatile(
        "\txor %%rax, %%rax\n"
        "\tmovw %%gs, %%ax\n"
        "\tmovw %%ax, %[ret]\n"
    :[ret] "=rm" (ret) 
    ::"rax");
    return ret;
}


//  void hw_write_gs ( UINT16);
//  Write to GS
void hw_write_gs (UINT16 i) { 
    asm volatile(
        "\tmovw %[i], %%gs\n"
    :
    :[i] "r" (i)
    :);
    return;
}


//  UINT64 hw_read_rsp (void);
UINT64 hw_read_rsp () {
    UINT64 ret = 0;
    asm volatile(
        "\tmovq %%rsp, %%rax\n"
        "\tadd $8,%%rax\n"
        "\tmovq %%rax, %[ret]\n"
    :[ret] "=rm"(ret) 
    :: "cc", "memory");
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
     asm volatile(
        "\tpush %%rbp\n"
        "\tmovq %%rbp, %%rsp\n" //setup stack frame pointer
        "\tpush %%rbx\n"
        "\tpush %%rdi\n"
        "\tpush %%rsi\n"
        "\tpush %%r12\n"
        "\tpush %%r13\n"
        "\tpush %%r14\n"
        "\tpush %%r15\n"
        "\tlea 16(%%rbp), %%r15\n"//set r15 to point to SMI_PORT_PARAMS struct
        // normalize stack\n"\t
        "\tmovq %%rcx, (%%r15)\n"
        "\tmovq %%rdx, 8(%%r15)\n"
        "\tmovq %%r8, 16(%%r15)\n"
        "\tmovq %%r9, 24(%%r15)\n"
        //copy emulator registers into CPU
        "\tmovq (%%r15), %%r8\n"
        "\tmovq (%%r8), %%rax\n"
        "\tmovq 8(%%r15), %%r8\n"
        "\tmovq (%%r8), %%rbx\n"
        "\tmovq 16(%%r15), %%r8\n"
        "\tmovq (%%r8), %%rcx\n"
        "\tmovq 24(%%r15), %%r8\n"
        "\tmovq (%%r8), %%rdx\n"
        "\tmovq 32(%%r15), %%r8\n"
        "\tmovq (%%r8), %%rsi\n"
        "\tmovq 40(%%r15), %%r8\n"
        "\tmovq (%%r8), %%rdi\n"
        "\tmovq 48(%%r15), %%r8\n"
        "\tpush (%%r8)\n"
        "\tpopfq\n" //rflags = *p_rflags

        //we assume that sp will not change after SMI

        "\tpush %%rbp\n"
        "\tpush %%r15\n"
        //  "\tout %%dx, %%al\n"
        "\tout %%al, %%dx\n"
        "\tpop %%r15\n"
        "\tpop %%rbp\n"
        //fill emulator registers from CPU
        "\tmovq (%%r15), %%r8\n"
        "\tmovq %%rax, (%%r8)\n"
        "\tmovq 8(%%r15), %%r8\n"
        "\tmovq %%rbx, (%%r8)\n"
        "\tmovq 16(%%r15), %%r8\n"
        "\tmovq %%rcx, (%%r8)\n"
        "\tmovq 24(%%r15), %%r8\n"
        "\tmovq %%rdx, (%%r8)\n"
        "\tmovq 32(%%r15), %%r8\n"
        "\tmovq %%rsi, (%%r8)\n"
        "\tmovq 40(%%r15), %%r8\n"
        "\tmovq %%rdi, (%%r8)\n"
        "\tmovq 48(%%r15), %%r8\n"
        "\tpushfq\n"
        "\tpop (%%r8)\n" // *p_rflags = rflags
        //restore callee saved registers
        "\tpop %%r15\n"
        "\tpop %%r14\n"
        "\tpop %%r13\n"
        "\tpop %%r12\n"
        "\tpop %%rsi\n"
        "\tpop %%rdi\n"
        "\tpop %%rbx\n"
        "\tpop %%rbp\n"
    :::);
    return;
}

//  void 
//  hw_enable_interrupts (void);
void hw_enable_interrupts () {
    asm volatile("\tsti\n");
    return;
}

//  void 
//  hw_disable_interrupts (void);
void hw_disable_interrupts () {
    asm volatile("\tcli\n");
    return;
}

//  void 
//  hw_fxsave (void* buffer);
void hw_fxsave (void *buffer) {
    asm volatile(
        "\tfxsave %[buffer]\n"
    :[buffer] "=m" (buffer)
    : :);
    return;
}


//  void 
//  hw_fxrestore (void* buffer);
void hw_fxrestore (void *buffer) {
    asm volatile(
        "\tfxrstor %[buffer]\n"
    :
    :[buffer] "m" (buffer)
    :);
    return;
}


//  void 
//  hw_write_cr2 (UINT64 value);
void hw_write_cr2 (UINT64 value) {
    asm volatile(
        "\tmovq %%cr2, %[value]\n"
    :[value] "=g" (value)
    : :"cc", "memory");
    return;
}


// UINT16 * hw_cpu_id ( void * );
//  Read TR and calculate cpu_id
//  ax register will contain result
//  IMPORTANT NOTE: only RAX regsiter may be used here !!!!
//  This assumption is used in gcpu_regs_save_restore.asm
#define CPU_LOCATOR_GDT_ENTRY_OFFSET 32
#define TSS_ENTRY_SIZE_SHIFT 4

asm(
".globl hw_cpu_id\n"
".type hw_cpu_id,@function\n"
"hw_cpu_id:\n"
	"\txor %rax, %rax\n"
	"\tstr %ax\n"
	"\tsubw $32, %ax\n" // CPU_LOCATOR_GDT_ENTRY_OFFSET == 32
	"\tshrw $4, %ax\n" // TSS_ENTRY_SIZE_SHIFT == 4
	"\tret\n"
);

// See asm definition above. This function has highly specialized assumptions,
// and it's better to write it in pure assembly rather than depending on the
// compiler to get it right.
#if 0
UINT16 hw_cpu_id () {
    UINT16 ret = 0;

    asm volatile(
        "\txor %%rax, %%rax\n"
        "\tstr %%ax\n"
        "\tsubw $32 , %%ax\n" // CPU_LOCATOR_GDT_ENTRY_OFFSET is 32
        "\tshrw $4, %%ax\n" //TSS_ENTRY_SIZE_SHIFT is 4
        "\tmovw %%ax, %[ret]\n"
    :[ret] "=g" (ret)
    : :"%rax");
    return ret;
}
#endif


// UINT16 hw_read_tr ( void);
//  Read Task Register
//  ax register will contain result
UINT16 hw_read_tr() {
    UINT16 ret = 0;

    //RNB: Added the movw instruction to move the return value into 'ret'
   asm volatile(
        "\tstr %%ax\n"
        "\tmovw %%ax, %[ret]\n"
    :[ret] "=g" (ret)
    : :"%rax");
    return ret;
}


//  void hw_write_tr ( UINT16);
//  Write Task Register
void hw_write_tr (UINT16 i) {
    asm volatile(
        "\tltr %[i]\n"
    :
    :[i] "g" (i)
    :);
    return;
}


//  UINT16 hw_read_ldtr ( void);
//  Read LDT Register
//  ax register will contain result
UINT16 hw_read_ldtr () {
    UINT16 ret = 0;
    asm volatile (
        "\tsldt %[ret]\n"
    :[ret] "=g" (ret)
    : :);
    return ret;
}


//  void hw_write_ldtr ( UINT16);
//  Write LDT Register
void hw_write_ldtr (UINT16 i) {
    asm volatile(
        "\tlldt %[i]\n"
    :
    :[i] "r" (i) :);
    return;
}


//  void hw_cpuid (CPUID_PARAMS *)
//  Execute cpuid instruction
void hw_cpuid (CPUID_PARAMS *cp) {

    asm volatile(
        "\tmovq %[cp], %%r8\n" 
        //# fill regs for cpuid
        "\tmovq (%%r8), %%rax\n"
        "\tmovq 8(%%r8), %%rbx\n"
        "\tmovq 16(%%r8), %%rcx\n"
        "\tmovq 24(%%r8), %%rdx\n"
        "\tcpuid\n"
        "\tmovq %%rax, (%%r8)\n"
        "\tmovq %%rbx, 8(%%r8)\n"
        "\tmovq %%rcx, 16(%%r8)\n"
        "\tmovq %%rdx, 24(%%r8)\n"
        :
        :[cp] "g" (cp)
        :"%r8", "%rax", "%rbx", "%rcx", "%rdx", "memory");

        return;
}


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


/*
 *  void
 *  hw_perform_asm_iret(void);
 * Transforms stack from entry to regular procedure: 
 *
 * [       RIP        ] <= RSP
 *
 * To stack  to perform iret instruction:
 * 
 * [       SS         ]
 * [       RSP        ]
 * [      RFLAGS      ]
 * [       CS         ]
 * [       RIP        ] <= RSP should point prior iret
 */
void hw_perform_asm_iret () {
    asm volatile(
        "\tsubq $0x20, %%rsp\n"     //prepare space for "interrupt stack"
        "\tpush %%rax\n"                               //save scratch registers
        "\tpush %%rbx\n"
        "\tpush %%rcx\n"
        "\tpush %%rdx\n"
        "\taddq $0x40, %%rsp\n"   // get rsp back to RIP
        "\tpop %%rax\n"          //RIP -> RAX
        "\tmovq %%cs, %%rbx\n"   //CS  -> RBX
        "\tmovq %%rsp, %%rcx\n"  //good RSP -> RCX
        "\tmovq %%ss, %%rdx\n"   //CS  -> RDX
        "\tpush %%rdx\n"         //[       SS         ]
        "\tpush %%rcx\n"         //[       RSP        ]
        "\tpushfq\n"             //[      RFLAGS      ]
        "\tpush %%rbx\n"         //[       CS         ]
        "\tpush %%rax\n"         //[       RIP        ]

        "\tsubq $0x20, %%rsp\n"   //restore scratch registers
        "\tpop %%rdx\n"
        "\tpop %%rcx\n"
        "\tpop %%rbx\n"
        "\tpop %%rax\n"          // now RSP is in right position 
        "\tiretq "                  //perform IRET
    :::);
} 


// CHECK(JLM)
void hw_set_stack_pointer (HVA new_stack_pointer, main_continue_fn func, void *params) 
{
    asm volatile(
        "L1:\n"
        "\tmovq %[new_stack_pointer], %%rsp\n"
        "\tmovq %[params], %[new_stack_pointer]\n"
        "\tsubq $32, %%rsp\n" // allocate home space for 4 input params
        "\tcall %[func]\n" 
        "\tjmp L1\n"
    :
    :[new_stack_pointer] "g"(new_stack_pointer),
     [func] "g" (func), [params] "p"(params)
    :"cc");
    return;
}
