      TITLE   ia32_mem.asm: Assembly code for the IA-32 resources

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

.686P
.MODEL FLAT, C
.CODE

externdef vmm_memset:NEAR
externdef vmm_memcpy:NEAR
externdef vmm_strlen:NEAR

PUBLIC vmm_lock_xchg_dword
PUBLIC vmm_lock_xchg_byte

;------------------------------------------------------------------------------
;  force compiler intrinsics to use our code
;------------------------------------------------------------------------------
memset PROC
    jmp vmm_memset
memset ENDP

memcpy PROC
    jmp vmm_memcpy
memcpy ENDP

strlen PROC
    jmp vmm_strlen
strlen ENDP


;****************************************************************************
;*
;* Lock exchange dword
;* VOID
;* vmm_lock_xchg_dword (
;*                     UINT32 *dst, ; ebp + 8
;*                     UINT32 *src  ; ebp + 12
;*                    )
;****************************************************************************
vmm_lock_xchg_dword PROC
    push ebx

    mov ebx, [ebp + 12] ; copy src to ebx
    lock xchg [ebp + 8], ebx

    pop ebx
    ret
vmm_lock_xchg_dword ENDP

;****************************************************************************
;*
;* Lock exchange byte
;* VOID
;* vmm_lock_xchg_byte (
;*                     UINT8 *dst, ; ebp + 8
;*                     UINT8 *src  ; ebp + 12
;*                    )
;****************************************************************************
vmm_lock_xchg_byte PROC
    push ebx

    mov bl, byte ptr [ebp + 12] ; copy src to bl
    lock xchg byte ptr [ebp + 8], bl

    pop ebx
    ret
vmm_lock_xchg_byte ENDP

END

