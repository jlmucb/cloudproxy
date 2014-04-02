      TITLE   em64t_setjmp.asm: Assembly code for the IA-32e ISR

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

UINT64  typedef qword
SETJMP_BUFFER   struc
    _rbx       UINT64  ?
    _rsi       UINT64  ?
    _rdi       UINT64  ?
    _rbp       UINT64  ?
    _r12       UINT64  ?
    _r13       UINT64  ?
    _r14       UINT64  ?
    _r15       UINT64  ?
    _rsp       UINT64  ?
    _rip       UINT64  ?
SETJMP_BUFFER   ends


;------------------------------------------------------------------------------
;  int setjmp(SETJMP_BUFFER *env)
;
;  Save context registers in buffer, pointed by RCX
;------------------------------------------------------------------------------
setjmp PROC
        mov     (SETJMP_BUFFER ptr [rcx])._rbx, rbx
        mov     (SETJMP_BUFFER ptr [rcx])._rsi, rsi
        mov     (SETJMP_BUFFER ptr [rcx])._rdi, rdi
        mov     (SETJMP_BUFFER ptr [rcx])._rbp, rbp
        mov     (SETJMP_BUFFER ptr [rcx])._r12, r12
        mov     (SETJMP_BUFFER ptr [rcx])._r13, r13
        mov     (SETJMP_BUFFER ptr [rcx])._r14, r14
        mov     (SETJMP_BUFFER ptr [rcx])._r15, r15
        pop     rax            ; now rax contains return rip, rsp got post-return value
        mov     (SETJMP_BUFFER ptr [rcx])._rsp, rsp
        mov     (SETJMP_BUFFER ptr [rcx])._rip, rax
        push    rax            ; fix stack back
        xor     rax, rax       ; Return value
        ret
setjmp ENDP


;------------------------------------------------------------------------------
;  void longjmp(SETJMP_BUFFER *env, int errcode);
;
;  Save context registers in buffer, pointed by RCX
;------------------------------------------------------------------------------
longjmp PROC
        mov     rax, rdx        ; Return value (int)
        mov     rbx, (SETJMP_BUFFER ptr [rcx])._rbx
        mov     rsi, (SETJMP_BUFFER ptr [rcx])._rsi
        mov     rdi, (SETJMP_BUFFER ptr [rcx])._rdi
        mov     rbp, (SETJMP_BUFFER ptr [rcx])._rbp
        mov     r12, (SETJMP_BUFFER ptr [rcx])._r12
        mov     r13, (SETJMP_BUFFER ptr [rcx])._r13
        mov     r14, (SETJMP_BUFFER ptr [rcx])._r14
        mov     rsp, (SETJMP_BUFFER ptr [rcx])._rsp
        jmp     (SETJMP_BUFFER ptr [rcx])._rip
longjmp ENDP

hw_exception_post_handler PROC
        mov     rdx, 1          ; err code for longjmp
        mov     rcx, rsp        ; address of SETJMP_BUFFER
        jmp     longjmp
hw_exception_post_handler ENDP


END

