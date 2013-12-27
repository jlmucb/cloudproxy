      TITLE   em64t_gcpu_regs_save_restore.asm: Assembly code for the IA-32e

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

; Assumption - hw_cpu_id() uses RAX only and returns host cpu id in ax
extrn hw_cpu_id:NEAR

; pointer to the array of pointers to the GUEST_CPU_SAVE_AREA_PREFIX
extrn g_guest_regs_save_area:NEAR

;---------------------------------------------------------------------------
       include       ia32_registers.equ
;---------------------------------------------------------------------------
; Define initial part of GUEST_CPU_SAVE_AREA structure
GUEST_CPU_SAVE_AREA_PREFIX STRUCT
    gp  VMM_GP_REGISTERS    <>
    xmm VMM_XMM_REGISTERS   <>
GUEST_CPU_SAVE_AREA_PREFIX ENDS

;
; Load pointer to the active GUEST_CPU_SAVE_AREA_PREFIX into rbx
; No other registers are modified
;
load_save_area_into_rbx PROC
    ; save RAX temporary
    push rax

    ; calculate host cpu id and put it into the rax (ax)
    call hw_cpu_id

    ; put pointer to the array of GUEST_CPU_SAVE_AREA_PREFIX* to RBX
    mov  rbx, g_guest_regs_save_area
    mov  rbx, [rbx]

    ; put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
    mov  rbx, [rbx + SIZEOF QWORD * rax]

    ; restore RAX
    pop rax

    ret
load_save_area_into_rbx ENDP

;****************************************************************************
;*
;* This functions are part of the GUEST_CPU class.
;* They are called by assembler-lever VmExit/VmResume functions
;* to save all registers that are not saved in VMCS but may be used immediately
;* by C-language VMM code.
;*
;* The following registers are NOT saved here
;*
;*   RIP            part of VMCS
;*   RSP            part of VMCS
;*   RFLAGS         part of VMCS
;*   segment regs   part of VMCS
;*   control regs   saved in C-code later
;*   debug regs     saved in C-code later
;*   FP/MMX regs    saved in C-code later
;*
;* Assumptions:
;*   No free registers except of RSP/RFLAGS
;*   FS contains host CPU id (should be calculated)
;*
;****************************************************************************

;
; Assumption - no free registers on entry, all are saved on exit
;
gcpu_save_registers PROC
    ; save RAX and RBX temporary on a stack
    push rbx

    ; put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
    call load_save_area_into_rbx

    ; now save rax and rbx first
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RAX], rax

    pop  rax    ; this is rbx
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RBX], rax

    ; now save all other GP registers except of RIP,RSP,RFLAGS
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RCX], rcx
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RDX], rdx
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RDI], rdi
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RSI], rsi
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RBP], rbp
    ; skip RSP
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R8],  r8
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R9],  r9
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R10], r10
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R11], r11
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R12], r12
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R13], r13
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R14], r14
    mov  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R15], r15
    ; skip RIP
    ; skip RFLAGS
     
    ; now save XMM registers

    ; Depending on the compiler used, not all XMMs are needed to save/restore
    ; Before any release, use dumpbin.exe to examine asm code and remove
    ; the unused XMMs.
    movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM0], xmm0
    movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM1], xmm1
    movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM2], xmm2
    movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM3], xmm3
    movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM4], xmm4
    movaps (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM5], xmm5
    
    ; done
    ret
gcpu_save_registers ENDP

;
; Assumption - all free registers on entry, no free registers on exit
;
gcpu_restore_registers PROC

    ; put pointer to our GUEST_CPU_SAVE_AREA_PREFIX struct to RBX
    call load_save_area_into_rbx

    ; restore all XMM first
    movaps xmm0, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM0]
    movaps xmm1, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM1]
    movaps xmm2, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM2]
    movaps xmm3, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM3]
    movaps xmm4, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM4]
    movaps xmm5, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).xmm.reg[IA32_REG_XMM5]
    
    ; restore all GP except of RBX

    ; now save all other GP registers except of RIP,RSP,RFLAGS
    mov  rax, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RAX]
    ; RBX restore later
    mov  rcx, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RCX]
    mov  rdx, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RDX]
    mov  rdi, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RDI]
    mov  rsi, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RSI]
    mov  rbp, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RBP]
    ; skip RSP
    mov  r8,  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R8]
    mov  r9,  (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R9]
    mov  r10, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R10]
    mov  r11, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R11]
    mov  r12, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R12]
    mov  r13, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R13]
    mov  r14, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R14]
    mov  r15, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_R15]
    ; skip RIP
    ; skip RFLAGS

    ; restore RBX
    mov  rbx, (GUEST_CPU_SAVE_AREA_PREFIX ptr [rbx]).gp.reg[IA32_REG_RBX]

    ; done
    ret
gcpu_restore_registers ENDP

END

