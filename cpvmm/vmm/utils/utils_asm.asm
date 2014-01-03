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


TITLE   utils_asm.asm

.CODE

;------------------------------------------------------------------------------
;  VOID
;  vmm_lock_write (
;    UINT64   *mem_loc,  ;rcx
;    UINT64    new_data	 ;rdx
;    )
;------------------------------------------------------------------------------

vmm_lock_write PROC
	lock xchg [rcx], rdx
	ret
vmm_lock_write ENDP

;------------------------------------------------------------------------------
;  UINT32
;  vmm_rdtsc (
;    UINT32   *upper  ;ecx
;    )
;------------------------------------------------------------------------------

vmm_rdtsc PROC
    rdtsc
    mov     [ecx], edx
	ret
vmm_rdtsc ENDP

vmm_write_xcr PROC
	mov rax,r8
	;xsetbv
	db 0Fh
	db 01h
	db 0D1h
	ret
vmm_write_xcr ENDP

vmm_read_xcr PROC
	push rdx
	push rcx
	mov rcx,r8
	;xgetbv
	db 0Fh
	db 01h
	db 0D0h
	pop rcx
	mov [rcx],eax
	pop rcx
	mov [rcx],edx
	ret
vmm_read_xcr ENDP

gcpu_read_guestrip PROC
    mov rax,681eh
    vmread   rax, rax
	;mov [rcx],rax
	ret
gcpu_read_guestrip ENDP


vmexit_reason PROC
    mov rax,4402h
; 4402h is encoding for vmcs field -- exit reason    
    vmread rax,rax
	ret
vmexit_reason ENDP

;
; UINT32 vmexit_check_ept_violation(void)
;
; if it is ept_voilation_vmexit, return exit qualification
;   in EAX, otherwise, return 0 in EAX

vmexit_check_ept_violation PROC
    mov rax,4402h
; 4402h is encoding for vmcs field -- exit reason    
    vmread rax,rax
    cmp al,48
    jnz not_ept_vmexit
    mov	rax,6400h
; 6400h is encoding for vmcs field- exit qualification    
    vmread rax,rax
	ret
not_ept_vmexit:
	mov rax,0
	ret
vmexit_check_ept_violation ENDP

vmm_vmcs_guest_state_read PROC
    mov	rax,681eh
    vmread rax,rax
    mov [rcx], rax

    mov	rax,6820h
    vmread rax,rax
    mov [rcx+8], rax

	add rcx,16

    mov	rax,440ch
    vmread rax,rax
    mov [rcx], rax

    mov	rax,6800h
    vmread rax,rax
    mov [rcx+8], rax

    mov	rax,6802h
    vmread rax,rax
    mov [rcx+16], rax

    mov	rax,6804h
    vmread rax,rax
    mov [rcx+24], rax

    mov	rax,681ah
    vmread rax,rax
    mov [rcx+32], rax

    mov	rax,800h
    vmread rax,rax
    mov [rcx+40], rax

    mov	rax,6806h
    vmread rax,rax
    mov [rcx+48], rax

    mov	rax,4800h
    vmread rax,rax
    mov [rcx+56], rax

    mov	rax,4814h
    vmread rax,rax
    mov [rcx+64], rax

    mov	rax,802h
    vmread rax,rax
    mov [rcx+72], rax

    mov	rax,6808h
    vmread rax,rax
    mov [rcx+80], rax

    mov	rax,4802h
    vmread rax,rax
    mov [rcx+88], rax

    mov	rax,4816h
    vmread rax,rax
    mov [rcx+96], rax

    mov	rax,804h
    vmread rax,rax
    mov [rcx+104], rax

    mov	rax,680ah
    vmread rax,rax
    mov [rcx+112], rax

    mov	rax,4804h
    vmread rax,rax
    mov [rcx+120], rax

    mov	rax,4818h
    vmread rax,rax
    mov [rcx+128], rax

    mov	rax,806h
    vmread rax,rax
    mov [rcx+136], rax

    mov	rax,680ch
    vmread rax,rax
    mov [rcx+144], rax

    mov	rax,4806h
    vmread rax,rax
    mov [rcx+152], rax

    mov	rax,481ah
    vmread rax,rax
    mov [rcx+160], rax

    mov	rax,808h
    vmread rax,rax
    mov [rcx+168], rax

    mov	rax,680eh
    vmread rax,rax
    mov [rcx+176], rax

    mov	rax,4808h
    vmread rax,rax
    mov [rcx+184], rax

    mov	rax,481ch
    vmread rax,rax
    mov [rcx+192], rax

    mov	rax,80ah
    vmread rax,rax
    mov [rcx+200], rax

    mov	rax,6810h
    vmread rax,rax
    mov [rcx+208], rax

    mov	rax,480ah
    vmread rax,rax
    mov [rcx+216], rax

    mov	rax,481eh
    vmread rax,rax
    mov [rcx+224], rax

    mov	rax,80ch
    vmread rax,rax
    mov [rcx+232], rax

    mov	rax,6812h
    vmread rax,rax
    mov [rcx+240], rax

    mov	rax,480ch
    vmread rax,rax
    mov [rcx+248], rax

    mov	rax,4820h
    vmread rax,rax
    mov [rcx+256], rax

    mov	rax,80eh
    vmread rax,rax
    mov [rcx+264], rax

    mov	rax,6814h
    vmread rax,rax
    mov [rcx+272], rax

    mov	rax,480eh
    vmread rax,rax
    mov [rcx+280], rax

    mov	rax,4822h
    vmread rax,rax
    mov [rcx+288], rax

    mov	rax,6816h
    vmread rax,rax
    mov [rcx+296], rax

    mov	rax,4810h
    vmread rax,rax
    mov [rcx+304], rax

    mov	rax,6818h
    vmread rax,rax
    mov [rcx+312], rax

    mov	rax,4812h
    vmread rax,rax
    mov [rcx+320], rax

    mov	rax,681ch
    vmread rax,rax
    mov [rcx+328], rax

    mov	rax,681eh
    vmread rax,rax
    mov [rcx+336], rax

    mov	rax,6820h
    vmread rax,rax
    mov [rcx+344], rax

    mov	rax,6822h
    vmread rax,rax
    mov [rcx+352], rax

    mov	rax,2800h
    vmread rax,rax
    mov [rcx+360], rax

    mov	rax,2802h
    vmread rax,rax
    mov [rcx+368], rax

    mov	rax,4824h
    vmread rax,rax
    mov [rcx+376], rax

    mov	rax,4826h
    vmread rax,rax
    mov [rcx+384], rax

    mov	rax,4828h
    vmread rax,rax
    mov [rcx+392], rax

    mov	rax,482ah
    vmread rax,rax
    mov [rcx+400], rax

    mov	rax,6824h
    vmread rax,rax
    mov [rcx+408], rax

    mov	rax,6826h
    vmread rax,rax
    mov [rcx+416], rax

	mov eax,edx
	cmp eax,0
	jz ept_is_not_supported

    mov	rax,2804h
    vmread rax,rax
    mov [rcx+424], rax

    mov	rax,2806h
    vmread rax,rax
    mov [rcx+432], rax

    mov	rax,280ah
    vmread rax,rax
    mov [rcx+440], rax

    mov	rax,280ch
    vmread rax,rax
    mov [rcx+448], rax

    mov	rax,280eh
    vmread rax,rax
    mov [rcx+456], rax

    mov	rax,2810h
    vmread rax,rax
    mov [rcx+464], rax

    mov	rax,482eh
    vmread rax,rax
    mov [rcx+472], rax

	ret
	
ept_is_not_supported:	
    mov	rax,0
    mov [rcx+424], rax

    mov [rcx+432], rax

    mov [rcx+440], rax

    mov [rcx+448], rax

    mov [rcx+456], rax

    mov [rcx+464], rax

    mov [rcx+472], rax

	ret
vmm_vmcs_guest_state_read ENDP


END
