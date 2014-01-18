/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


void vmm_lock_write (
        UINT64   *mem_loc,  // rcx
        UINT64    new_data  // rdx
        )
{
/*
        lock xchg (%rcx), rdx
        ret
 */
}


UINT32 vmm_rdtsc (
                    UINT32   *upper  // ecx
)
{
/*
    rdtsc
    mov     (%ecx), %edx
        ret
 */
}


void vmm_write_xcr(UINT64 xcr)
{
/*
        mov %rax, %r8
        /* xsetbv */
        .byte 0x0f
        .byte 0x01
        .byte 0x0D1
        ret
 */
}


UINT64 vmm_read_xcr()
{
/*
        push %rdx
        push %rcx
        mov %rcx,%r8
        #xgetbv
        .byte 0x0F
        .byte 0x01
        .byte 0x0D0
        pop %rcx
#REK: not sure why (%rcx) doesn't work, while [%rcx] works
        mov [%rcx], %eax
        pop %rcx
        mov [%rcx], %edx
        ret

.globl  gcpu_read_guestrip 
gcpu_read_guestrip:
    mov %rax, 0x681e
    vmread   %rax, (%rax)
        ;mov (%rcx), %rax
        ret
*/
}


UINT64 vmexit_reason()
{
/*
    mov %rax,0x4402
    # 0x4402 is encoding for vmcs field -- exit reason    
    vmread %rax, %rax
    ret
 */
}


UINT32 vmexit_check_ept_violation(void)
{
//if it is ept_voilation_vmexit, return exit qualification
//  in EAX, otherwise, return 0 in EAX
/*

    mov %rax,0x4402
    # 4402 is encoding for vmcs field -- exit reason    
    vmread %rax,%rax
    cmp %al,48
    jnz not_ept_vmexit
    mov %rax,0x6400
    # 6400 is encoding for vmcs field- exit qualification    
    vmread %rax,%rax
    ret
not_ept_vmexit:
    mov %rax,0
    ret
*/


void vmm_vmcs_guest_state_read(void)
{
/*
    mov %rax,0x681e
    vmread %rax,%rax
    mov (%rcx), %rax
    mov %rax,0x6820
    vmread %rax,%rax
    mov [rcx+8],%rax
    add %rcx,16
    mov %rax,0x440c
    vmread %rax,%rax
    mov (%rcx), %rax
    mov %rax,0x6800
    vmread %rax,%rax
    mov [%rcx+8], %rax
    mov %rax,0x6802
    vmread %rax,%rax
    mov [%rcx+16], %rax
    mov %rax,0x6804
    vmread %rax,%rax
    mov [%rcx+24], %rax
    mov %rax,0x681a
    vmread %rax,%rax
    mov [%rcx+32], %rax
    mov %rax,0x0800
    vmread %rax,%rax
    mov [%rcx+40], %rax
    mov %rax,0x6806
    vmread %rax,%rax
    mov [%rcx+48], %rax
    mov %rax,0x4800
    vmread %rax,%rax
    mov [%rcx+56], %rax
    mov %rax,0x4814
    vmread %rax,%rax
    mov [%rcx+64], %rax
    mov %rax,0x0802
    vmread %rax,%rax
    mov [%rcx+72], %rax
    mov %rax,0x6808
    vmread %rax,%rax
    mov [%rcx+80], %rax
    mov %rax,0x4802
    vmread %rax,%rax
    mov [%rcx+88], %rax
    mov %rax,0x4816
    vmread %rax,%rax
    mov [%rcx+96], %rax
    mov %rax,0x0804
    vmread %rax,%rax
    mov [%rcx+104], %rax
    mov %rax,0x680a
    vmread %rax,%rax
    mov [%rcx+112], %rax
    mov %rax,0x4804
    vmread %rax,%rax
    mov [%rcx+120], %rax
    mov %rax,0x4818
    vmread %rax,%rax
    mov [%rcx+128], %rax
    mov %rax,0x0806
    vmread %rax,%rax
    mov [%rcx+136], %rax
    mov %rax,0x680c
    vmread %rax,%rax
    mov [%rcx+144], %rax
    mov %rax,0x4806
    vmread %rax,%rax
    mov [%rcx+152], %rax
    mov %rax,0x481a
    vmread %rax,%rax
    mov [%rcx+160], %rax
    mov %rax,0x0808
    vmread %rax,%rax
    mov [%rcx+168], %rax
    mov %rax,0x680e
    vmread %rax,%rax
    mov [%rcx+176], %rax
    mov %rax,0x4808
    vmread %rax,%rax
    mov [%rcx+184], %rax
    mov %rax,0x481c
    vmread %rax,%rax
    mov [%rcx+192], %rax
    mov %rax,0x080a
    vmread %rax,%rax
    mov [%rcx+200], %rax
    mov %rax,0x6810
    vmread %rax,%rax
    mov [%rcx+208], %rax
    mov %rax,0x480a
    vmread %rax,%rax
    mov [%rcx+216], %rax
    mov %rax,0x481e
    vmread %rax,%rax
    mov [%rcx+224], %rax
    mov %rax,0x080c
    vmread %rax,%rax
    mov [%rcx+232], %rax
    mov %rax,0x6812
    vmread %rax,%rax
    mov [%rcx+240], %rax
    mov %rax,0x480c
    vmread %rax,%rax
    mov [%rcx+248], %rax
    mov %rax,0x4820
    vmread %rax,%rax
    mov [%rcx+256], %rax
    mov %rax,0x080e
    vmread %rax,%rax
    mov [%rcx+264], %rax
    mov %rax,0x6814
    vmread %rax,%rax
    mov [%rcx+272], %rax
    mov %rax,0x480e
    vmread %rax,%rax
    mov [%rcx+280], %rax
    mov %rax,0x4822
    vmread %rax,%rax
    mov [%rcx+288], %rax
    mov %rax,0x6816
    vmread %rax,%rax
    mov [%rcx+296], %rax
    mov %rax,0x4810
    vmread %rax,%rax
    mov [%rcx+304], %rax
    mov %rax,0x6818
    vmread %rax,%rax
    mov [%rcx+312], %rax
    mov %rax,0x4812
    vmread %rax,%rax
    mov [%rcx+320], %rax
    mov %rax,0x681c
    vmread %rax,%rax
    mov [%rcx+328], %rax
    mov %rax,0x681e
    vmread %rax,%rax
    mov [%rcx+336], %rax
    mov %rax,0x6820
    vmread %rax,%rax
    mov [%rcx+344], %rax
    mov %rax,0x6822
    vmread %rax,%rax
    mov [%rcx+352], %rax
    mov %rax,0x2800
    vmread %rax,%rax
    mov [%rcx+360], %rax
    mov %rax,0x2802
    vmread %rax,%rax
    mov [%rcx+368], %rax
    mov %rax,0x4824
    vmread %rax,%rax
    mov [%rcx+376], %rax
    mov %rax,0x4826
    vmread %rax,%rax
    mov [%rcx+384], %rax
    mov %rax,0x4828
    vmread %rax,%rax
    mov [%rcx+392], %rax
    mov %rax,0x482a
    vmread %rax,%rax
    mov [%rcx+400], %rax
    mov %rax,0x6824
    vmread %rax,%rax
    mov [%rcx+408], %rax
    mov %rax,0x6826
    vmread %rax,%rax
    mov [%rcx+416], %rax

    mov %eax,%edx
    cmp %eax,0
    jz ept_is_not_supported

    mov %rax,0x2804
    vmread %rax,%rax
    mov [%rcx+424], %rax
    mov %rax,0x2806
    vmread %rax,%rax
    mov [%rcx+432], %rax
    mov %rax,0x280a
    vmread %rax,%rax
    mov [%rcx+440], %rax
    mov %rax,0x280c
    vmread %rax,%rax
    mov [%rcx+448], %rax
    mov %rax,0x280e
    vmread %rax,%rax
    mov [%rcx+456], %rax
    mov %rax,0x2810
    vmread %rax,%rax
    mov [%rcx+464], %rax
    mov %rax,0x482e
    vmread %rax,%rax
    mov [%rcx+472], %rax
        ret
*/
}
        

UINT64 ept_is_not_supported ()
{
/*
    mov %rax,0
    mov [%rcx+424], %rax
    mov [%rcx+432], %rax
    mov [%rcx+440], %rax
    mov [%rcx+448], %rax
    mov [%rcx+456], %rax
    mov [%rcx+464], %rax
    mov [%rcx+472], %rax
    ret
*/
}


