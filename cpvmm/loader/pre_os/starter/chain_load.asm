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
; Copyright 2013 Intel Corporation All Rights Reserved.
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

_text segment para public use16 'code'
.586p
.model flat, c
.code

    org 0000h

chain_load:

    ; dx indicates the boot sector.

    test dx, dx
    jns read_mbr
    int 19h
    jmp $

read_mbr:

    movzx bp, dh
    mov ax, 0201h
    mov cx, 0001h
    mov bx, 7c00h
    mov dh, 0000h
    int 13h
    jc disk_error

    ; No logical partition support.

    test bp, bp
    jz start_guest
    cmp bp, 4
    jg disk_error

read_part:

    sub esp, 16
    xor esi, esi
    mov esi, esp
    mov word ptr  [esi +  0], 0010h ; dap->size
    mov word ptr  [esi +  2], 0001h ; dap->sector_count
    mov dword ptr [esi +  4], 7c00h ; dap->buffer
    mov dword ptr [esi + 12], 0000h ; dap->start_lba_high

    xor edi, edi
    mov di, bp
    dec di
    shl di, 4

    ; partition table offset is 0x01be.

    mov edi, dword ptr [7c00h + edi + 1beh]
    mov dword ptr [esi + 8], edi ; dap->start_lba_low
    mov ah, 42h
    int 13h
    jc disk_error

start_guest:
    jmp cs:buffer

disk_error:
    jmp $

    org 5c00h
buffer:

end chain_load
_text ends
