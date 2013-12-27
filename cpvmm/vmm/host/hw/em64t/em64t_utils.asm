      TITLE   em64t_utils.asm: Assembly code for the IA-32e ISR

;****************************************************************************
; Copyright (c) 2013 Intel Corporation
;
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
;     http://www.apache.org/licenses/LICENSE-2.0

; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.
;***************************************************************************/

;****************************************************************************
; INTEL CONFIDENTIAL
; Copyright 2001-2013 Intel Corporation All Rights Reserved.
;
; The source code contained or described herein and all documents related to
; the source code ("Material") are owned by Intel Corporation or its
; suppliers or licensors.  Title to the Material remains with Intel
; Corporation or its suppliers and licensors.  The Material contains trade
; secrets and proprietary and confidential information of Intel or its
; suppliers and licensors.  The Material is protected by worldwide copyright
; and trade secret laws and treaty provisions.  No part of the Material may
; be used, copied, reproduced, modified, published, uploaded, posted,
; transmitted, distributed, or disclosed in any way without Intel's prior
; express written permission.
;
; No license under any patent, copyright, trade secret or other intellectual
; property right is granted to or conferred upon you by disclosure or
; delivery of the Materials, either expressly, by implication, inducement,
; estoppel or otherwise.  Any license under such intellectual property rights
; must be express and approved by Intel in writing.
;***************************************************************************/

.CODE

;****************************************************************************
;*
;* Calling conventions
;*
;* Floating : First 4 parameters – XMM0 through XMM3. Others passed on stack.
;*
;* Integer  : First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
;*
;* Aggregates (8, 16, 32, or 64 bits) and __m64:
;*              First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
;*
;* Aggregates (other):
;*            By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
;*
;* __m128   : By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
;*
;*
;*
;* Return values that can fit into 64-bits are returned through RAX (including __m64 types),
;* except for __m128, __m128i, __m128d, floats, and doubles, which are returned in XMM0.
;* If the return value does not fit within 64 bits, then the caller assumes the responsibility
;* of allocating and passing a pointer for the return value as the first argument. Subsequent
;* arguments are then shifted one argument to the right. That same pointer must be returned
;* by the callee in RAX. User defined types to be returned must be 1, 2, 4, 8, 16, 32, or 64
;* bits in length.
;*
;****************************************************************************

ARG1_U8  equ cl
ARG1_U16 equ cx
ARG1_U32 equ ecx
ARG1_U64 equ rcx

ARG2_U8  equ dl
ARG2_U16 equ dx
ARG2_U32 equ edx
ARG2_U64 equ rdx

ARG3_U32 equ r8l
ARG3_U64 equ r8

;****************************************************************************
;*
;* Register usage
;*
;* Caller-saved and scratch:
;*        RAX, RCX, RDX, R8, R9, R10, R11
;*
;* Callee-saved
;*        RBX, RBP, RDI, RSI, R12, R13, R14, and R15
;*
;****************************************************************************

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_lgdt (
;          void * gdtr
;  );
;
;  Load GDTR (from buffer pointed by RCX)
;------------------------------------------------------------------------------
hw_lgdt PROC
        lgdt  fword ptr [ARG1_U64]
        ret
hw_lgdt ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_sgdt (
;          void * gdtr
;  );
;
;  Store GDTR (to buffer pointed by RCX)
;------------------------------------------------------------------------------
hw_sgdt PROC
        sgdt  fword ptr [ARG1_U64]
        ret
hw_sgdt ENDP


;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_cs (
;          void
;  );
;
;  Read Command Segment Selector
;
;  Stack offsets on entry:
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_cs PROC
        xor     rax, rax
        mov     ax, cs
        ret
hw_read_cs ENDP

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_cs (
;          UINT16
;  );
;
;  Write to Command Segment Selector
;
;------------------------------------------------------------------------------
hw_write_cs PROC
        ;; push segment selector
        xor     rax, rax
        mov     ax, ARG1_U16
        shl     rax, 32
        lea     rdx, CONT_WITH_NEW_CS
        add     rax, rdx
        push    rax
        retf                            ; brings IP to CONT_WITH_NEW_CS
CONT_WITH_NEW_CS:
        ret
hw_write_cs ENDP


;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_ds (
;          void
;  );
;
;  Read Data Segment Selector
;
;  Stack offsets on entry:
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_ds PROC
        xor     rax, rax
        mov     ax, ds
        ret
hw_read_ds ENDP

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_ds (
;          UINT16
;  );
;
;  Write to Data Segment Selector
;
;------------------------------------------------------------------------------
hw_write_ds PROC
        mov     ds, ARG1_U16
        ret
hw_write_ds ENDP


;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_es (
;          void
;  );
;
;  Read ES Segment Selector
;
;  Stack offsets on entry:
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_es PROC
        xor     rax, rax
        mov     ax, es
        ret
hw_read_es ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_es (
;          UINT16
;  );
;
;  Write to ES Segment Selector
;
;------------------------------------------------------------------------------
hw_write_es PROC
        mov     es, ARG1_U16
        ret
hw_write_es ENDP



;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_ss (
;          void
;  );
;
;  Read Stack Segment Selector
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_ss PROC
        xor     rax, rax
        mov     ax, ss
        ret
hw_read_ss ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_ss (
;          UINT16
;  );
;
;  Write to Stack Segment Selector
;
;------------------------------------------------------------------------------
hw_write_ss PROC
        mov     ss, ARG1_U16
        ret
hw_write_ss ENDP


;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_fs (
;          void
;  );
;
;  Read FS
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_fs PROC
        xor     rax, rax
        mov     ax, fs
        ret
hw_read_fs ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_fs (
;          UINT16
;  );
;
;  Write to FS
;
;------------------------------------------------------------------------------
hw_write_fs PROC
        mov     fs, ARG1_U16
        ret
hw_write_fs ENDP

;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_gs (
;          void
;  );
;
;  Read GS
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_gs PROC
        xor     rax, rax
        mov     ax, gs
        ret
hw_read_gs ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_gs (
;          UINT16
;  );
;
;  Write to GS
;
;------------------------------------------------------------------------------
hw_write_gs PROC
        mov     gs, ARG1_U16
        ret
hw_write_gs ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_set_stack_pointer (
;          HVA new_stack_pointer,
;          main_continue_fn func,
;          void* params
;  );
;
;
;------------------------------------------------------------------------------
hw_set_stack_pointer PROC
        mov     rsp,	  ARG1_U64
		mov     ARG1_U64, ARG3_U64
		sub		rsp,	  32       ; allocate home space for 4 input params
		call    ARG2_U64
		jmp     $
        ret
hw_set_stack_pointer ENDP

;------------------------------------------------------------------------------
;  UINT64 __stdcall
;  hw_read_rsp (void);
;
;
;------------------------------------------------------------------------------
hw_read_rsp PROC
        mov     rax, rsp
		add     rax, 8
        ret
hw_read_rsp ENDP



;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_to_smi_port(
;               UINT64 * p_rax,     // rcx
;               UINT64 * p_rbx,     // rdx
;               UINT64 * p_rcx,     // r8
;               UINT64 * p_rdx,     // r9
;               UINT64 * p_rsi,     // on the stack
;               UINT64 * p_rdi,     // on the stack
;               UINT64 * p_rflags   // on the stack
;               );
;
;  Fill HW regs from emulator context before writing to the port,
;  and fill emulator context registers from HW after the write.
;
;------------------------------------------------------------------------------
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

hw_write_to_smi_port PROC

        ;; save callee saved registers
        push    rbp
        mov     rbp, rsp                ;; setup stack frame pointer

        push    rbx
        push    rdi
        push    rsi
        push    r12
        push    r13
        push    r14
        push    r15

        lea     r15,[rbp + 10h]          ;; set r15 to point to SMI_PORT_PARAMS struct

        ;; normalize stack
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RAX, rcx
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RBX, rdx
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RCX, r8
        mov     (SMI_PORT_PARAMS ptr [r15]).P_RDX, r9

        ;; copy emulator registers into CPU
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RAX
        mov     rax, [r8]
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RBX
        mov     rbx, [r8]
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RCX
        mov     rcx, [r8]
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RDX
        mov     rdx, [r8]
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RSI
        mov     rsi, [r8]
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RDI
        mov     rdi, [r8]
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RFLAGS
        push    qword ptr [r8]
        popfq                           ;; rflags = *p_rflags

        ;; we assume that sp will not change after SMI
        push    rbp
        push    r15
        out     dx, al
        pop     r15
        pop     rbp

        ;; fill emulator registers from CPU
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RAX
        mov     [r8], rax
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RBX
        mov     [r8], rbx
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RCX
        mov     [r8], rcx
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RDX
        mov     [r8], rdx
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RSI
        mov     [r8], rsi
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RDI
        mov     [r8], rdi
        mov     r8, (SMI_PORT_PARAMS ptr [r15]).P_RFLAGS
        pushfq                          ;;
        pop     [r8]                    ;; *p_rflags = rflags

        ;; restore callee saved registers
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rsi
        pop     rdi
        pop     rbx
        pop     rbp
        ret
hw_write_to_smi_port ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_enable_interrupts (void);
;
;
;------------------------------------------------------------------------------
hw_enable_interrupts PROC
        sti
        ret
hw_enable_interrupts ENDP

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_disable_interrupts (void);
;
;
;------------------------------------------------------------------------------
hw_disable_interrupts PROC
        cli
        ret
hw_disable_interrupts ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_fxsave (void* buffer);
;
;
;------------------------------------------------------------------------------
hw_fxsave PROC
        fxsave [ARG1_U64]
        ret
hw_fxsave ENDP

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_fxrestore (void* buffer);
;
;
;------------------------------------------------------------------------------
hw_fxrestore PROC
        fxrstor [ARG1_U64]
        ret
hw_fxrestore ENDP

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_cr2 (UINT64 value);
;
;
;------------------------------------------------------------------------------
hw_write_cr2 PROC
        mov cr2, ARG1_U64
        ret
hw_write_cr2 ENDP

;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_cpu_id (
;          void
;  );
;
;  Read TR and calculate cpu_id
;
;  ax register will contain result
;
;  IMPORTANT NOTE: only RAX regsiter may be used here !!!!
;                  This assumption is used in gcpu_regs_save_restore.asm
;------------------------------------------------------------------------------
;CPU_LOCATOR_GDT_ENTRY_OFFSET equ 48
CPU_LOCATOR_GDT_ENTRY_OFFSET equ 32
TSS_ENTRY_SIZE_SHIFT         equ 4

hw_cpu_id PROC
        xor     rax, rax
        str     ax
        sub     ax, CPU_LOCATOR_GDT_ENTRY_OFFSET
        shr     ax, TSS_ENTRY_SIZE_SHIFT
        ret
hw_cpu_id ENDP

;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_tr (
;          void
;  );
;
;  Read Task Register
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_tr PROC
        str     ax
        ret
hw_read_tr ENDP

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_tr (
;          UINT16
;  );
;
;  Write Task Register
;
;------------------------------------------------------------------------------
hw_write_tr PROC
        ltr     ARG1_U16
        ret
hw_write_tr ENDP

;------------------------------------------------------------------------------
;  UINT16 __stdcall
;  hw_read_ldtr (
;          void
;  );
;
;  Read LDT Register
;
;  ax register will contain result
;------------------------------------------------------------------------------
hw_read_ldtr PROC
        sldt   ax
        ret
hw_read_ldtr ENDP

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_write_ldtr (
;          UINT16
;  );
;
;  Write LDT Register
;
;------------------------------------------------------------------------------
hw_write_ldtr PROC
        lldt   ARG1_U16
        ret
hw_write_ldtr ENDP


CPUID_PARAMS   struc
    M_RAX       UINT64  ?
    M_RBX       UINT64  ?
    M_RCX       UINT64  ?
    M_RDX       UINT64  ?
CPUID_PARAMS ends

;------------------------------------------------------------------------------
;  void __stdcall
;  hw_cpuid (
;       CPUID_PARAMS *
;  );
;
;  Execute cpuid instruction
;
;------------------------------------------------------------------------------
hw_cpuid PROC
        mov r8, rcx     ; address of struct
        mov r9, rbx     ; save RBX
        ; fill regs for cpuid
        mov     rax, (CPUID_PARAMS ptr [r8]).M_RAX
        mov     rbx, (CPUID_PARAMS ptr [r8]).M_RBX
        mov     rcx, (CPUID_PARAMS ptr [r8]).M_RCX
        mov     rdx, (CPUID_PARAMS ptr [r8]).M_RDX
        cpuid
        mov     (CPUID_PARAMS ptr [r8]).M_RAX, rax
        mov     (CPUID_PARAMS ptr [r8]).M_RBX, rbx
        mov     (CPUID_PARAMS ptr [r8]).M_RCX, rcx
        mov     (CPUID_PARAMS ptr [r8]).M_RDX, rdx
        mov     rbx, r9
        mov     rcx, r8
        ret
hw_cpuid ENDP


;------------------------------------------------------------------------------
;  void __stdcall
;  hw_leave_64bit_mode ();
;  Arguments:   UINT32 compatibility_segment  CX
;               UINT16 port_id                DX
;               UINT16 value                  R8
;               UINT32 cr3_value              R9
;------------------------------------------------------------------------------
hw_leave_64bit_mode PROC

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
hw_leave_64bit_mode ENDP


;------------------------------------------------------------------------------
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
;------------------------------------------------------------------------------

hw_perform_asm_iret PROC
        sub     rsp, 020h       ; prepare space for "interrupt stack"

        push    rax             ; save scratch registers
        push    rbx
        push    rcx
        push    rdx

        add     rsp, 040h       ; get rsp back to RIP
        pop     rax             ; RIP -> RAX
        mov     rbx, cs         ; CS  -> RBX
        mov     rcx, rsp        ; good RSP -> RCX
        mov     rdx, ss         ; CS  -> RDX

        push    rdx             ; [       SS         ]
        push    rcx             ; [       RSP        ]
        pushfq                  ; [      RFLAGS      ]
        push    rbx             ; [       CS         ]
        push    rax             ; [       RIP        ]

        sub     rsp, 020h       ; restore scratch registers
        pop     rdx
        pop     rcx
        pop     rbx
        pop     rax             ; now RSP is in right position

        iretq                   ; perform IRET
hw_perform_asm_iret ENDP

END

