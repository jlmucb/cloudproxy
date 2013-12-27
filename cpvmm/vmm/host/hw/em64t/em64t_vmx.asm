      TITLE   vmx_utils.asm: Assembly code for the IA-32e

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


extrn gcpu_save_registers       :NEAR 
extrn gcpu_restore_registers    :NEAR
extrn vmexit_common_handler     :NEAR
extrn vmentry_failure_function  :NEAR

ifdef ENABLE_TMSL_PROFILING
extern profiling_vmexit        :NEAR
extern g_tmsl_profiling_vmexit :NEAR
; Assumption - hw_cpu_id() uses RAX only and returns host cpu id in ax
extrn hw_cpu_id:NEAR

; Define PROF_VMEXIT_TIME structure
PROF_VMEXIT_TIME struc
    last_vmexit     qword  00h;
    last_vmentry    qword  00h;
    last_reason    qword  00h;
    last_cpu_id    qword  00h;
    this_vmexit     qword  00h;
    this_vmentry    qword  00h;
    this_reason    qword  00h;
    this_cpu_id    qword  00h;
PROF_VMEXIT_TIME ends;
endif



;------------------------------------------------------------------------------
;  Function:    Restore space on the stack for calling C-function
;
;  Arguments:   RCX - contains the number of arguments, passed to C-function
;------------------------------------------------------------------------------
RESTORE_C_STACK        MACRO
        cmp     rcx, 4
        ja      @F                      ;; goto parameters are normalized
        mov     rcx, 4                  ;; at least 4 arguments must be allocated
@@:                                     ;; parameters are normalized
        shl     rcx, 3
        add     rsp, rcx
ENDM


;------------------------------------------------------------------------------
;  Function:    Allocates space on the stack for calling C-function
;
;  Arguments:   RCX - contains the number of arguments, passed to C-function
;------------------------------------------------------------------------------
ALLOCATE_C_STACK        MACRO
        cmp     rcx, 4
        ja      @F                      ;; goto parameters are normalized
        mov     rcx, 4                  ;; at least 4 arguments must be allocated
@@:                                     ;; parameters are normalized
        shl     rcx, 3
        sub     rsp, rcx
ENDM

ifdef ENABLE_TMSL_PROFILING
profiling_serialize PROC
    ; serialize
    mov     rax, cr0
    mov     cr0, rax

    ret
profiling_serialize ENDP

profiling_save_vmexit_time PROC
    ; save registers. rax must be saved, else will hang.
    push rax
    push rbx
    push r8

    ; calculate host cpu id and put it into the rax (ax)
    call hw_cpu_id
    mov r8, rax

    ; put pointer to the array of GUEST_CPU_SAVE_AREA_PREFIX* to RBX
    mov  rbx, g_tmsl_profiling_vmexit
    shl  rax, 6 ;size of PROF_VMEXIT_TIME = 64 * rax
    add  rbx, rax

    ; save last vmexit/vmentry time
    mov  rax, (PROF_VMEXIT_TIME ptr [rbx]).this_vmexit
    mov  (PROF_VMEXIT_TIME ptr [rbx]).last_vmexit,  rax
    mov  rax, (PROF_VMEXIT_TIME ptr [rbx]).this_vmentry
    mov  (PROF_VMEXIT_TIME ptr [rbx]).last_vmentry,  rax
    mov  rax, (PROF_VMEXIT_TIME ptr [rbx]).this_reason
    mov  (PROF_VMEXIT_TIME ptr [rbx]).last_reason,  rax
    mov  rax, (PROF_VMEXIT_TIME ptr [rbx]).this_cpu_id
    mov  (PROF_VMEXIT_TIME ptr [rbx]).last_cpu_id,  rax

    ; serialize
    call profiling_serialize

    ; rdtsc
    push    rdx
    push    rcx
    rdtsc
    shl     rdx, 32
    add     rax, rdx

    ; save this vmexit time
    mov  (PROF_VMEXIT_TIME ptr [rbx]).this_vmexit, rax
    mov  (PROF_VMEXIT_TIME ptr [rbx]).this_cpu_id, r8


	pop    rcx
	pop    rdx


    ; restore registers
    pop r8
    pop rbx
    pop rax

    ret
profiling_save_vmexit_time ENDP

profiling_save_vmentry_time PROC
    ; save registers
    push rax
    push rbx

    ; calculate host cpu id and put it into the rax (ax)
    call hw_cpu_id

    ; put pointer to the array of GUEST_CPU_SAVE_AREA_PREFIX* to RBX
    mov  rbx, g_tmsl_profiling_vmexit
    shl  rax, 6 ;size of PROF_VMEXIT_TIME = 64 * rax
    add  rbx, rax

    ; serialize
    call profiling_serialize

    ; rdtsc
    push    rdx
    push    rcx
    rdtsc
    shl     rdx, 32
    add     rax, rdx

    ; save this vmexit time
    mov  (PROF_VMEXIT_TIME ptr [rbx]).this_vmentry, rax

	pop    rcx
	pop    rdx


    ; restore registers
    pop rbx
    pop rax

    ret
profiling_save_vmentry_time ENDP
endif

;------------------------------------------------------------------------------
;  Function:    Called upon VMEXIT. Saves GP registers, allocates stack
;               for C-function and calls it.
;
;  Arguments:   none
;------------------------------------------------------------------------------
vmexit_func     PROC


ifdef ENABLE_TMSL_PROFILING
        call profiling_save_vmexit_time
endif

        call    gcpu_save_registers
        xor     rcx, rcx
        ALLOCATE_C_STACK
   
        call    vmexit_common_handler
        jmp     $                       ;; should never return
vmexit_func     ENDP


;------------------------------------------------------------------------------
;  Function:    Called upon VMENTRY.
;
;  Arguments:   RCX = 1 if called first time
;------------------------------------------------------------------------------
vmentry_func    PROC
        push    rcx
        cmp     rcx, 0
        jnz     do_launch
do_resume:

       
		
    
ifdef ENABLE_TMSL_PROFILING
        call profiling_save_vmentry_time
        call profiling_vmexit            ; profiling the cost before vmentry
endif

        call    gcpu_restore_registers 

		vmresume                        ; Resume execution of Guest Virtual Machine

        jmp     handle_error
do_launch:
        call    gcpu_restore_registers
        vmlaunch                        ; Launch execution of Guest Virtual Machine

handle_error:
        pushfq                          ; use RFLAGS as argument if VMRESUME failed
        pop     rdx                     ; save RFLAGS in RDX
        mov     rcx, 1                  ; RCX contains number of argments for vmentry_failure_function
        ALLOCATE_C_STACK                ; for for vmentry_failure_function
        mov     rcx, rdx                ; 1st argument (passed via RCX) contains RFLAGS
        call    vmentry_failure_function
        mov     rcx, 1                  ; RCX contains number of argments for vmentry_failure_function
        RESTORE_C_STACK
        pop     rcx                     ; restore RCX. stack is expected to be the same as in entry point
        jmp     vmentry_func            ; retry
vmentry_func   ENDP


;------------------------------------------------------------------------------
;  Function:    VMCALL
;
;  uVMM expects the following:
;      vmcall_id in RCX
;      arg1      in RDX
;      arg2      in RDI
;      arg3      in RSI
;
;  return value in RAX
;------------------------------------------------------------------------------
VMM_NATIVE_VMCALL_SIGNATURE equ 024694D40h
hw_vmcall PROC
        push    rdi
        push    rsi
        mov     rdi, r8
        mov     rsi, r9
        mov     rax, VMM_NATIVE_VMCALL_SIGNATURE
        vmcall
        mov     r9, rsi
        mov     r8, rdi
        pop     rsi
        pop     rdi
        ret
hw_vmcall ENDP

ITP_JMP_DEADLOOP PROC
        jmp $
        ret
ITP_JMP_DEADLOOP ENDP

END

