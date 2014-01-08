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

TITLE   ept.asm

;include ept.inc

.CODE

; VS2010 supports the INVEPT and INVVPID instructions
; These 2 macros are kept for compatibility with VS2005
; The Intel Software Development Emulator XED was used to decode the hardcoded opcode
; TODO: Replace macro with this instruction in VS2010
;   invept ecx, xmmword ptr [eax]
_INVEPT macro
    DB  66h, 48h, 0fh, 38h, 80h, 08h
endm

; TODO: Replace macro with this instruction in VS2010
;   invvpid ecx, xmmword ptr [eax]
_INVVPID macro
    DB  66h, 48h, 0fh, 38h, 81h, 08h
endm

;------------------------------------------------------------------------------
;  VOID
;  vmm_asm_invept (
;    INVEPT_ARG   *arg,		;rcx
;    UINT32       modifier	;rdx
;    UINT64       *rflags	;r8
;    )
;------------------------------------------------------------------------------

vmm_asm_invept PROC
	mov rax, rcx
	mov rcx, rdx
	_INVEPT
	pushfq
	pop [r8]
	ret
vmm_asm_invept ENDP

;------------------------------------------------------------------------------
;  VOID
;  vmm_asm_invvpid (
;    INVEPT_ARG   *arg,		;rcx
;    UINT32       modifier	;rdx
;    UINT64       *rflags	;r8
;    )
;------------------------------------------------------------------------------

vmm_asm_invvpid PROC
	mov rax, rcx
	mov rcx, rdx
	_INVVPID
	pushfq
	pop [r8]
	ret
vmm_asm_invvpid ENDP

END
