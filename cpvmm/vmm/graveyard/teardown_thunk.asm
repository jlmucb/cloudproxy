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

      TITLE   teardown_thunk.asm: Assembly code for the IA-32e mode

.CODE



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
;  Function:    call teardown thunk
;    int ASM_FUNCTION 
;    call_teardown_thunk32(
;                        UINT64 current_guest_states_virt_addr
;                        UINT16 compatibility_cs,
;                        UINT64 teardown_thunk_entry_virt_addr,    // thuk addraddress
;                        UINT64 cr3_td_sm_32, // cr3 with page table compatibale with guest
;                        BOOLEAN cr4_pae_is_on
;                        );
;      arg1      in RCX
;      arg2      in RDX
;      arg3      in R8
;      arg4      in R9
;      arg5      [rsp+28h]
;  never return: 
;  since this function will not return, all the registers free to use.
;------------------------------------------------------------------------------

call_teardown_thunk32 PROC
    mov 	ebx, r8d            ;; save teardown_thunk_entry_address
    mov		rsi, rcx            ;; save current_guest_states_virt_addr to rsi temporarily
    mov     rdi, r9			    ;; save cr3_td_sm_32 to rdi temporarily
    ;; cr4_pae_is_on value is on stack
    mov     rcx, 028h[rsp]

    vmxoff
	;; clear cr4.vmx, must be after vmx off. otherwise #GP fault
    mov		rax, cr4
    and     rax, 0FFFFDFFFh
    mov		cr4, rax

    ;; prepare cs : rip pair for retf by first pushing
    ;; 64 bit compatibility segment, then pushing 64 bits return
    ;; address
    xor     rax, rax
    mov     rax,  rdx             ;; rdx holds compatibility_cs
    push    rax
    xor     rax, rax
    lea     rax, compat_code
    push    rax
    db 048h						;; REX.W - opcode prefix to following retf to set the
                  				;; operand size to 64 bits
    retf                        ;; brings IP to compat_code
    ;; compatibility mode starts right here, below code is running on
    ;; 32bit mode.
compat_code:                   
    mov		rax, cr0
    btc eax, 31                 ;; disable IA32e paging
    mov		cr0, rax

    ;; rcx is modified below, so save it
    push    rcx
	mov		ecx, 0C0000080h     ;; EFER MSR register
	rdmsr                   	;; read EFER into EAX
	btc		eax, 8             	;; clear EFER.LME
	wrmsr                  		;; write EFER back
    pop     rcx

    ;; Check whether PAE was on originally in guest or not. If yes, turn ON PAE
    ;; Use byte code for CR3 and CR4 operations so they are
    ;; translated correctly in 32bit mode (not 64bit opcodes).
    ;; Below byte code is equivalent to "mov eax, cr4".
    byte    0fh
    byte    020h
    byte    0e0h

    cmp     ecx, 01h
    jz      pae_mode
    or      eax, 010h			;; set PSE bit of cr4 - non PAE mode
    and     eax, 0FFFFFFDFh     ;; clear PAE bit of cr4
    jmp     after_pae_check
pae_mode:
    or      eax, 030h			;; set PSE and PAE bits of cr4
after_pae_check:
    ;; Use byte code for CR3 and CR4 operations so they are
    ;; translated correctly in 32bit mode (not 64bit opcodes).
    ;; Below byte code is equivalent to "mov cr4, eax".
    byte    0fh
    byte    022h
    byte    0e0h 

	mov		ecx, esi            ;; restore current_guest_states_virt_addr in rcx

	xor     eax, eax
    mov     eax, edi
    ;; load CR3 with cr3_td_sm_32 which has the mapping of
    ;; Use byte code for CR3 and CR4 operations so they are
    ;; translated correctly in 32bit mode (not 64bit opcodes).
    ;; Below byte code is equivalent to "mov cr3, eax"
    byte    0fh
    byte    022h
    byte    0d8h
                                ;; teardown_shared_memory's gva and gpa, except those 3
                                ;; pages of shared memory, other are 1:1 mapping (va = pa)
                                ;; for 32-bit mode

	mov rax, cr0           		;; use Rxx notation for compiler, only 32-bit are valuable
 	bts eax, 31            		;; enable IA32 paging (32-bits)
 	mov cr0, rax

    ; finally, call teardownthunk entry in guest space. and never returns.              
    jmp rbx                  	;; the same as "jmp ebx" in 32bit code mode.
    
call_teardown_thunk32 ENDP

;------------------------------------------------------------------------------
;  Function:    call teardown thunk at 64 bits guest mode
;    int ASM_FUNCTION 
;    call_teardown_thunk64(
;                        UINT32 current_cpu_idx ,        // cpuidx 
;                        UINT64 current_guest_states_hva 
;                        UINT64 teardown_thunk_entry_hva    // address 
;                        );
;      arg1      in RCX
;      arg2      in RDX
;      arg3      in R8
;  never return: 
;  since this function will not return, all the registers free to use.
;------------------------------------------------------------------------------

call_teardown_thunk64 PROC

    mov rbx, r8                 ; save teardown_thunk_entry_address  
      
     ; call teardownthunk entry in guest space. and never returns.              
    jmp rbx                  
    
call_teardown_thunk64 ENDP

END

