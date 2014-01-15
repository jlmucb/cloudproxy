#
# Copyright (c) 2013 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

.intel_syntax
.text

#
#
# Calling conventions
#
# Floating : First 4 parameters – XMM0 through XMM3. Others passed on stack.
#
# Integer  : First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
#
# Aggregates (8, 16, 32, or 64 bits) and __m64:
#              First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
#
# Aggregates (other):
#            By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
#
# __m128   : By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
#
#
#
# Return values that can fit into 64-bits are returned through RAX 
# (including __m64 types), except for __m128, __m128i, __m128d, floats, 
# and doubles, which are returned in XMM0.  If the return value does not 
# fit within 64 bits, then the caller assumes the responsibility
# of allocating and passing a pointer for the return value as the first 
# argument. Subsequent arguments are then shifted one argument to the right. 
# That same pointer must be returned by the callee in RAX. User defined 
# types to be returned must be 1, 2, 4, 8, 16, 32, or 64 bits in length.
#

.set    ARG1_U8, %cl
.set    ARG1_U16, % cx
.set    ARG1_U32, %ecx
.set    ARG1_U64, %rcx
.set    ARG2_U8, %dl
.set    ARG2_U16, %dx
.set    ARG2_U32, %edx
.set    ARG2_U64, %rdx
.set    ARG3_U32, %r8l
.set    ARG3_U64, %r8

#
# Register usage
#
# Caller-saved and scratch:
#        RAX, RCX, RDX, R8, R9, R10, R11
#
# Callee-saved
#        RBX, RBP, RDI, RSI, R12, R13, R14, and R15
#
#  void __stdcall
#  hw_lgdt (
#          void * gdtr
#  );
#
#  Load GDTR (from buffer pointed by RCX)
#
.globl  hw_lgdt 
hw_lgdt:
        lgdt  fword ptr [ARG1_U64]
        ret

#
#  void __stdcall
#  hw_sgdt (
#          void * gdtr
#  );
#
#  Store GDTR (to buffer pointed by RCX)
#
.globl  hw_sgdt 
hw_sgdt:
        sgdt  fword ptr [ARG1_U64]
        ret

#
#  UINT16 __stdcall
#  hw_read_cs (
#          void
#  );
#  Read Command Segment Selector
#  Stack offsets on entry:
#  ax register will contain result
#
.globl  hw_read_cs 
hw_read_cs:
        xor     %rax, %rax
        mov     %ax, %cs
        ret

#
#  void __stdcall
#  hw_write_cs (
#          UINT16
#  );
#
#  Write to Command Segment Selector
#
#
.globl  hw_write_cs 
hw_write_cs:
        #; push segment selector
        xor     %rax, %rax
        mov     %ax, ARG1_U16
        shl     %rax, 32
        lea     %rdx, CONT_WITH_NEW_CS
        add     %rax, %rdx
        push    %rax
        retf                            # brings IP to CONT_WITH_NEW_CS
CONT_WITH_NEW_CS:
        ret


#
#  UINT16 __stdcall
#  hw_read_ds (
#          void
#  );
#
#  Read Data Segment Selector
#
#  Stack offsets on entry:
#
#  ax register will contain result
#
.globl  hw_read_ds 
hw_read_ds:
        xor     %rax, %rax
        mov     %ax, %ds
        ret

#
#  void __stdcall
#  hw_write_ds (
#          UINT16
#  );
#
#  Write to Data Segment Selector
#
.globl  hw_write_ds 
hw_write_ds:
        mov     %ds, ARG1_U16
        ret


#
#  UINT16 __stdcall
#  hw_read_es (
#          void
#  );
#
#  Read ES Segment Selector
#
#  Stack offsets on entry:
#
#  ax register will contain result
#
.globl  hw_read_es 
hw_read_es:
        xor     %rax, %rax
        mov     %ax, %es
        ret


#
#  void __stdcall
#  hw_write_es (
#          UINT16
#  );
#
#  Write to ES Segment Selector
#
#
.globl  hw_write_es 
hw_write_es:
        mov     %es, ARG1_U16
        ret


#
#  UINT16 __stdcall
#  hw_read_ss (
#          void
#  );
#
#  Read Stack Segment Selector
#
#  ax register will contain result
#
.globl  hw_read_ss 
hw_read_ss:
        xor     %rax, %rax
        mov     %ax, %ss
        ret


#
#  void __stdcall
#  hw_write_ss (
#          UINT16
#  );
#
#  Write to Stack Segment Selector
#
#
.globl  hw_write_ss 
hw_write_ss:
        mov     %ss, ARG1_U16
        ret


#
#  UINT16 __stdcall
#  hw_read_fs (
#          void
#  );
#
#  Read FS
#
#  ax register will contain result
#
.globl  hw_read_fs 
hw_read_fs:
        xor     %rax, %rax
        mov     %ax, %fs
        ret


#
#  void __stdcall
#  hw_write_fs (
#          UINT16
#  );
#
#  Write to FS
#
#
.global hw_write_fs 
hw_write_fs:
        mov     %fs, ARG1_U16
        ret

#
#  UINT16 __stdcall
#  hw_read_gs (
#          void
#  );
#
#  Read GS
#
#  ax register will contain result
#
.globl hw_read_gs 
hw_read_gs:
        xor     %rax, %rax
        mov     %ax, %gs
        ret


#
#  void __stdcall
#  hw_write_gs (
#          UINT16
#  );
#
#  Write to GS
#
#
.globl  hw_write_gs 
hw_write_gs:
        mov     %gs, ARG1_U16
        ret


#
#  void __stdcall
#  hw_set_stack_pointer (
#          HVA new_stack_pointer,
#          main_continue_fn func,
#          void* params
#  );
#
#
#
.globl  hw_set_stack_pointer 
hw_set_stack_pointer:
        mov     rsp,    ARG1_U64
                mov     ARG1_U64, ARG3_U64
                sub     %rsp, $32     # allocate home space for 4 input params
                call    ARG2_U64
                jmp     $
        ret


#
#  UINT64 __stdcall
#  hw_read_rsp (void);
#
#
#
.globl  hw_read_rsp 
hw_read_rsp:
        mov     %rax, %rsp
        add     %rax, $8
        ret

#
#  void __stdcall
#  hw_write_to_smi_port(
#               UINT64 * p_rax,     // rcx
#               UINT64 * p_rbx,     // rdx
#               UINT64 * p_rcx,     // r8
#               UINT64 * p_rdx,     // r9
#               UINT64 * p_rsi,     // on the stack
#               UINT64 * p_rdi,     // on the stack
#               UINT64 * p_rflags   // on the stack
#               );
#
#  Fill HW regs from emulator context before writing to the port,
#  and fill emulator context registers from HW after the write.
#
#
UINT64  typedef qword
SMI_PORT_PARAMS   struc
    P_RAX       UINT64  ?
    P_RBX       UINT64  ?
    P_RCX       UINT64  ?
    P_RDX       UINT64  ?
    P_RSI       UINT64  ?
    P_RDI       UINT64  ?
    P_RFLAGS    UINT64  ?
SMI_PORT_PARAMS   ends

.globl  hw_write_to_smi_port 
hw_write_to_smi_port:

        #; save callee saved registers
        push    %rbp
        mov     %rbp, %rsp                #; setup stack frame pointer

        push    %rbx
        push    %rdi
        push    %rsi
        push    %r12
        push    %r13
        push    %r14
        push    %r15

        lea     %r15,[%rbp + $0x10]     #; set r15 to point to SMI_PORT_PARAMS struct

        #; normalize stack
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RAX, %rcx
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RBX, %rdx
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RCX, %r8
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RDX, %r9

        #; copy emulator registers into CPU
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RAX
        mov     %rax, [%r8]
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RBX
        mov     %rbx, [%r8]
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RCX
        mov     %rcx, [%r8]
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RDX
        mov     %rdx, [%r8]
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RSI
        mov     %rsi, [%r8]
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RDI
        mov     %rdi, [%r8]
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RFLAGS
        push    qword ptr [%r8]
        popfq                           #; rflags = *p_rflags

        #; we assume that sp will not change after SMI
        push    %rbp
        push    %r15
        out     %dx, %al
        pop     %r15
        pop     %rbp

        #; fill emulator registers from CPU
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RAX
        mov     [%r8], rax
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RBX
        mov     [%r8], %rbx
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RCX
        mov     [%r8], %rcx
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RDX
        mov     [%r8], %rdx
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RSI
        mov     [%r8], %rsi
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RDI
        mov     [%r8], %rdi
        mov     %r8, (SMI_PORT_PARAMS ptr [%r15]).P_RFLAGS
        pushfq                          #;
        pop     [%r8]                    #; *p_rflags = rflags

        #; restore callee saved registers
        pop     %r15
        pop     %r14
        pop     %r13
        pop     %r12
        pop     %rsi
        pop     %rdi
        pop     %rbx
        pop     %rbp
        ret


#
#  void __stdcall
#  hw_enable_interrupts (void);
#
#
#
.globl  hw_enable_interrupts 
hw_enable_interrupts:
        sti
        ret

#
#  void __stdcall
#  hw_disable_interrupts (void);
#
#
#
.globl hw_disable_interrupts 
hw_disable_interrupts:
        cli
        ret

#
#  void __stdcall
#  hw_fxsave (void* buffer);
#
#
#
.globl  hw_fxsave 
hw_fxsave:
        fxsave [ARG1_U64]
        ret

#
#  void __stdcall
#  hw_fxrestore (void* buffer);
#
#
#
.globl  hw_fxrestore 
hw_fxrestore:
        fxrstor [ARG1_U64]
        ret

#
#  void __stdcall
#  hw_write_cr2 (UINT64 value);
#
#
#
.globl  hw_write_cr2 
hw_write_cr2:
        mov %cr2, ARG1_U64
        ret

#
#  UINT16 __stdcall
#  hw_cpu_id (
#          void
#  );
#
#  Read TR and calculate cpu_id
#
#  ax register will contain result
#
#  IMPORTANT NOTE: only RAX regsiter may be used here !!!!
#                  This assumption is used in gcpu_regs_save_restore.asm
#
.set    CPU_LOCATOR_GDT_ENTRY_OFFSET, 48
.set    CPU_LOCATOR_GDT_ENTRY_OFFSET, 32
.set    TSS_ENTRY_SIZE_SHIFT, 4

.globl  hw_cpu_id 
hw_cpu_id:
        xor     %rax, %rax
        str     %ax
        sub     %ax, CPU_LOCATOR_GDT_ENTRY_OFFSET
        shr     %ax, TSS_ENTRY_SIZE_SHIFT
        ret

#
#  UINT16 __stdcall
#  hw_read_tr (
#          void
#  );
#
#  Read Task Register
#
#  ax register will contain result
#
.globl  hw_read_tr 
hw_read_tr:
        str     %ax
        ret

#
#  void __stdcall
#  hw_write_tr (
#          UINT16
#  );
#
#  Write Task Register
#
#
.globl  hw_write_tr 
hw_write_tr:
        ltr     ARG1_U16
        ret

#
#  UINT16 __stdcall
#  hw_read_ldtr (
#          void
#  );
#
#  Read LDT Register
#
#  ax register will contain result
#
.globl  hw_read_ldtr 
hw_read_ldtr:
        sldt   %ax
        ret

#
#  void __stdcall
#  hw_write_ldtr (
#          UINT16
#  );
#
#  Write LDT Register
#
#
.globl  hw_write_ldtr 
hw_write_ldtr:
        lldt   ARG1_U16
        ret


CPUID_PARAMS   struc
    M_RAX       UINT64  ?
    M_RBX       UINT64  ?
    M_RCX       UINT64  ?
    M_RDX       UINT64  ?
CPUID_PARAMS ends

#
#  void __stdcall
#  hw_cpuid (
#       CPUID_PARAMS *
#  );
#
#  Execute cpuid instruction
#
#
.globl  hw_cpuid
hw_cpuid:
        mov r8, %rcx     # address of struct
        mov r9, %rbx     # save RBX
        # fill regs for cpuid
        mov     %rax, (CPUID_PARAMS ptr [r8]).M_RAX
        mov     %rbx, (CPUID_PARAMS ptr [r8]).M_RBX
        mov     %rcx, (CPUID_PARAMS ptr [r8]).M_RCX
        mov     %rdx, (CPUID_PARAMS ptr [r8]).M_RDX
        cpuid
        mov     (CPUID_PARAMS ptr [r8]).M_RAX, %rax
        mov     (CPUID_PARAMS ptr [r8]).M_RBX, %rbx
        mov     (CPUID_PARAMS ptr [r8]).M_RCX, %rcx
        mov     (CPUID_PARAMS ptr [r8]).M_RDX, %rdx
        mov     %rbx, %r9
        mov     %rcx, %r8
        ret


#
#  void __stdcall
#  hw_leave_64bit_mode ();
#  Arguments:   UINT32 compatibility_segment  CX
#               UINT16 port_id                DX
#               UINT16 value                  R8
#               UINT32 cr3_value              R9
#
.globl  hw_leave_64bit_mode
hw_leave_64bit_mode:
        jmp $
        shl %rcx, $32             #; prepare segment:offset pair for retf by shifting
                                #; compatibility segment in high address
        lea %rax, compat_code    #; and
        add %rcx, %rax            #; placing offset into low address
        push %rcx                #; push ret address onto stack
        mov  %rsi, %rdx           #; rdx will be used during EFER access
        mov  %rdi, %r8            #; r8 will be unaccessible, so use rsi instead
        mov  %rbx, %r9            #; save CR3 in RBX. this function is the last called, so we have not to save rbx
        retf                    #; jump to compatibility mode
compat_code:                    #; compatibility mode starts right here

        mov %rax, %cr0            #; only 32-bit are relevant
        btc %eax, $31             #; disable IA32e paging (64-bits)
        mov %cr0, %rax            #;

        #; now in protected mode
#RNB: The original constant was 0C0000080h
        mov %ecx, $0xC0000080h     #; EFER MSR register
        rdmsr                   #; read EFER into EAX
        btc %eax, $8              #; clear EFER.LME
        wrmsr                   #; write EFER back

#        mov cr3, rbx            ;; load CR3 for 32-bit mode
#
#        mov rax, cr0            ;; use Rxx notation for compiler, only 32-bit are valuable
#        bts eax, 31             ;; enable IA32 paging (32-bits)
#        mov cr0, rax            ;;
#        jmp @f

#; now in 32-bit paging mode
        mov %rdx, %rsi
        mov %rax, %rdi
        out %dx, %ax              #; write to PM register
        ret                     #; should never get here


#
#  void
#  hw_perform_asm_iret(void);
#
# Transforms stack from entry to reglar procedure: 
#
# [       RIP        ] <= RSP
#
# To stack  to perform iret instruction:
# 
# [       SS         ]
# [       RSP        ]
# [      RFLAGS      ]
# [       CS         ]
# [       RIP        ] <= RSP should point prior iret
#
.globl  hw_perform_asm_iret
hw_perform_asm_iret:
        sub     %rsp, $0x020h       # prepare space for "interrupt stack"
        push    %rax             # save scratch registers
        push    %rbx
        push    %rcx
        push    %rdx
        add     %rsp, $0x040       # get rsp back to RIP
        pop     %rax             # RIP -> RAX
        mov     %rbx, %cs         # CS  -> RBX
        mov     %rcx, %rsp        # good RSP -> RCX
        mov     %rdx, %ss         # CS  -> RDX

        push    %rdx             # [       SS         ]
        push    %rcx             # [       RSP        ]
        pushfq                  # [      RFLAGS      ]
        push    %rbx             # [       CS         ]
        push    %rax             # [       RIP        ]

        sub     %rsp, $0x020       # restore scratch registers
        pop     %rdx
        pop     %rcx
        pop     %rbx
        pop     %rax             # now RSP is in right position

        iretq                   # perform IRET


