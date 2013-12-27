/****************************************************************************
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
****************************************************************************/

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

/*---------------------------------------------------*
*
* file      : x32_init64.c
* purpose   : implement transition to 64-bit execution mode
*
*----------------------------------------------------*/

#include "vmm_defs.h"
#include "ia32_low_level.h"
#include "x32_init64.h"

#define PSE_BIT     0x10
#define PAE_BIT     0x20


void __cdecl start_64bit_mode(
    UINT32 address,
    UINT32 segment, // MUST BE 32-bit wide, because it delivered to 64-bit code using 32-bit push/retf commands
    UINT32 * arg1,
    UINT32 * arg2,
    UINT32 * arg3,
    UINT32 * arg4)
{
    __asm
    {
        ;; prepare arguments for 64-bit mode
        ;; there are 3 arguments
        ;; align stack and push them on 8-byte alignment
        xor eax, eax
        and esp, ~7
        push eax
        push arg4
        push eax
        push arg3
        push eax
        push arg2
        push eax
        push arg1

        cli

        push   segment    ;; push segment and offset
        push   START64    ;; for following retf
        mov ebx, address

        // initialize CR3 with PML4 base
        // mov   eax, [esp+4]
        // mov   cr3, eax
        ;; enable 64-bit mode
        mov ecx, 0C0000080h     ; EFER MSR register
        rdmsr                   ; read EFER into EAX
        bts eax, 8                ; set EFER.LME=1
        wrmsr                   ; write EFER
        ;; enable paging CR0.PG=1
        mov eax, cr0

        bts eax, 31                ; set PG=1
        mov cr0, eax

        ;; at this point we are in 32-bit compatibility mode
        ;; LMA=1, CS.L=0, CS.D=1
        ;; jump from 32bit compatibility mode into 64bit mode.

        retf
START64:
        pop    ecx              ;; in 64bit this is actually pop rcx
        pop    edx              ;; in 64bit this is actually pop rdx

        _emit  0x41
        _emit  0x58             ;; pop r8

        _emit  0x41
        _emit  0x59             ;; pop r9

        _emit 0x48              ;; in 64bit this is actually
        sub    esp,0x18         ;;   sub  rsp, 0x18

        call   ebx              ;; in 64bit this is actually
                                ;;    call rbx
    }
}


void x32_init64_start(
    INIT64_STRUCT *p_init64_data,
    UINT32 address_of_64bit_code,
    void * arg1,
    void * arg2,
    void * arg3,
    void * arg4)
{
    UINT32 cr4;

    ia32_write_gdtr(&p_init64_data->i64_gdtr);
    ia32_write_cr3(p_init64_data->i64_cr3);
    cr4 = ia32_read_cr4();
    BITMAP_SET(cr4, PAE_BIT | PSE_BIT);
    ia32_write_cr4(cr4);
    ia32_write_msr(0xC0000080, &p_init64_data->i64_efer);
    start_64bit_mode(address_of_64bit_code, p_init64_data->i64_cs, arg1, arg2, arg3, arg4);
}


