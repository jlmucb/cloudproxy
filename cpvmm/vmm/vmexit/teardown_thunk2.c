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


//     arg1      in RCX
//     arg2      in RDX
//     arg3      in R8
//     arg4      in R9
//     arg5      [rsp+28h]
// never return: 
// since this function will not return, all the registers free to use.
//
int call_teardown_thunk32( UINT64 current_guest_states_virt_addr,
                 UINT16 compatibility_cs, UINT64 teardown_thunk_entry_virt_addr,
                 UINT64 cr3_td_sm_32, BOOLEAN cr4_pae_is_on)
{
    int result;
    asm volatile(
        "\tmovl    %[current_guest_states_virt_addr], %%rcx\n" \
        "\tmovq    %[compatibility_cs], %%rdx\n" \
    : [result]"=g" (result)
    : [current_guest_states_virt_addr] "g" (current_guest_states_virt_addr), 
      [compatibility_cs] "g" (compatibility_cs), 
      [teardown_thunk_entry_virt_addr] "g" (teardown_thunk_entry_virt_addr), 
      [cr3_td_sm_32] "g" (cr3_td_sm_32), 
      [cr4_pae_is_on] "g" (cr4_pae_is_on)
    :"%rax", "%r8");
/*
    mov     %ebx, %r8d   #; save teardown_thunk_entry_address
    mov     %rsi, %rcx   #; save current_guest_states_virt_addr to rsi temporarily
    mov     %rdi, %r9        #; save cr3_td_sm_32 to rdi temporarily
    #; cr4_pae_is_on value is on stack
    mov     %rcx, 0x28[rsp]
    vmxoff
    #; clear cr4.vmx, must be after vmx off. otherwise #GP fault
    mov      %rax, %cr4
    and      %rax, $0xFFFFDFFF
    mov      %cr4, %rax

    #; prepare cs : rip pair for retf by first pushing
    #; 64 bit compatibility segment, then pushing 64 bits return
    #; address
    xor     %rax, %rax
    mov     %rax,  %rdx             #; rdx holds compatibility_cs
    push    %rax
    xor     %rax, %rax
    lea     %rax, compat_code
    push    %rax
    .byte    0x048   #; REX.W - opcode prefix to following retf to set the
                    #; operand size to 64 bits
    retf                        #; brings IP to compat_code
    #; compatibility mode starts right here, below code is running on
    #; 32bit mode.
compat_code:                   
    mov      %rax, %cr0
    btc      %eax, 31                 #; disable IA32e paging
    mov      %cr0, %rax

    #; rcx is modified below, so save it
    push    %rcx
    mov     %ecx, 0x0C0000080     #; EFER MSR register
    rdmsr                           #; read EFER into EAX
    btc     %eax, 8                  #; clear EFER.LME
    wrmsr                           #; write EFER back
    pop     %rcx

    #; Check whether PAE was on originally in guest or not. If yes, turn ON PAE
    #; Use byte code for CR3 and CR4 operations so they are
    #; translated correctly in 32bit mode (not 64bit opcodes).
    #; Below byte code is equivalent to "mov eax, cr4".
    .byte    0x0f
    .byte    0x20
    .byte    0xe0

    cmp     %ecx, 0x01
    jz      pae_mode
    or      %eax, 0x10           #; set PSE bit of cr4 - non PAE mode
    and     %eax, 0xFFFFFFDF     #; clear PAE bit of cr4
    jmp     after_pae_check
pae_mode:
    or      %eax, 0x30           #; set PSE and PAE bits of cr4
after_pae_check:
    #; Use byte code for CR3 and CR4 operations so they are
    #; translated correctly in 32bit mode (not 64bit opcodes).
    #; Below byte code is equivalent to "mov cr4, eax".
    .byte    0x0f
    .byte    0x22
    .byte    0xe0 

    mov     %ecx, %esi            #; restore current_guest_states_virt_addr in rcx
    xor     %eax, %eax
    mov     %eax, %edi
    #; load CR3 with cr3_td_sm_32 which has the mapping of
    #; Use byte code for CR3 and CR4 operations so they are
    #; translated correctly in 32bit mode (not 64bit opcodes).
    #; Below byte code is equivalent to "mov cr3, eax"
    .byte    0x0f
    .byte    0x22
    .byte    0xd8
    #; teardown_shared_memory's gva and gpa, except those 3
    #; pages of shared memory, other are 1:1 mapping (va = pa)
    #; for 32-bit mode
    mov %rax, %cr0    #; use Rxx notation for compiler, only 32-bit are valuable
    bts %eax, 31                     #; enable IA32 paging (32-bits)
    mov %cr0, %rax

    # finally, call teardownthunk entry in guest space. and never returns.  
    jmp rbx                     #; the same as "jmp ebx" in 32bit code mode.
 */
}



//   call teardown thunk at 64 bits guest mode
//    arg1      in RCX
//    arg2      in RDX
//    arg3      in R8
// never return: 
// since this function will not return, all the registers free to use.
int call_teardown_thunk64(UINT32 current_cpu_idx,
                          UINT64 current_guest_states_hva, UINT64 teardown_thunk_entry_hva)
{
    asm volatile(
        "\tmovl    %[current_cpu_idx], %%rcx\n" \
        "\tmovq    %[current_guest_states_hvu], %%rdx\n" \
        "\tmovq    %[teardown_thunk_entry_hva], %%r8\n" \
        "\tmovq    %%r8, %%rbx\n" \
        "\tjmp     %%rbx\n"
        "\tmovq    %%rax, %[result]\n" \
    : [result]"=g" (result)
    : [current_cpu_idx] "g" (current_cpu_idx), 
      [current_guest_states_hvu] "g" (current_guest_states_hva), 
      [teardown_thunk_entry_hva] "g" (teardown_thunk_entry_hva)
    :"%rax", "%r8");
    return result;
}

