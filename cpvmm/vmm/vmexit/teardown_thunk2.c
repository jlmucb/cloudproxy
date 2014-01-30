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
#include "vmm_defs.h"

int call_teardown_thunk32 (UINT64 current_guest_states_phy_addr,
		UINT16 compatibility_cs, UINT64 teardown_thunk_entry_phy_addr,
		UINT64 cr3_td_sm_32, BOOLEAN cr4_pae_is_on)
{
    UINT64 result = 0;

    asm volatile(
        "\tmovq    %[current_guest_states_phy_addr], %%rcx\n"
        "\tmovw    %[compatibility_cs], %%dx\n"
        "\tmovq    %[teardown_thunk_entry_phy_addr], %%r8\n"
        "\tmovq    %[cr3_td_sm_32], %%r9\n"
        "\tmovl    %%r8d, %%ebx\n"
        "\tmovq    %%rcx, %%rsi\n"
        // save cr3_td_sm_32 to rdi temporarily
        "\tmovq    %%r9, %%rdi\n"
				"\tmovq    0x28(%%rsp), %%rcx \n"
        "\tvmxoff\n"
        // clear cr4.vmx, must be after vmx off. otherwise #GP fault
        "\tmovq    %%cr4, %%rax\n"
        "\tandl    $0xFFFFDFFF, %%eax\n"
        "\tmovq    %%rax, %%cr4\n"
        // prepare cs : rip pair for retf by first pushing
        // 64 bit compatibility segment, then pushing 64 bits return
        // address
        "\txorq     %%rax, %%rax\n"
        "\tmovq     %%rdx, %%rax\n"
        "\tpush     %%rax\n"
        "\txorq     %%rax, %%rax\n"
        // fix this
        "\tleaq     1f, %%rax\n"
        "\tpush     %%rax\n"
        "\t.byte    0x048 \n" 
        // REX.W - opcode prefix to following retf to set the
        // operand size to 64 bits
        // brings IP to compat_code
        // compatibility mode starts right here, below code is running on
        // 32bit mode.
        "\tlret \n"
				"1: \n"
        "\tmovq     %%cr0, %%rax\n"
        "\tbtcl     $31, %%eax \n"
        "\tmovq     %%rax, %%cr0\n"

        "\tpush     %%rcx\n"
        // EFER MSR register
        "\tmovl $0x0C0000080, %%ecx\n"
        // read EFER into EAX
        "\trdmsr\n"
        // clear EFER.LME
        "\tbtcl $8, %%eax\n"
        "\twrmsr\n"
        "\npop     %%rcx\n"

        // Check whether PAE was on originally in guest or not. If yes, turn ON PAE
        // Use byte code for CR3 and CR4 operations so they are
        // translated correctly in 32bit mode (not 64bit opcodes).
        // Byte code below is equivalent to "mov eax, cr4".
        "\t.byte 0x0f \n"
				"\t.byte 0x20 \n"
				"\t.byte 0xe0 \n"
        "\tcmpl $0x1, %%ecx\n"
        "\tjz 2f\n"
        // set PSE bit of cr4 - non PAE mode
        "\torl $0x10,%%eax\n"
        // clear PAE bit of cr4
        "\tandl $0xFFFFFFDF, %%eax \n"
        "\tjmp     3f\n"
        "2:\n"
        // pae_mode:
        // set PSE and PAE bits of cr4
        "\torl $0x30,%%eax\n"
        // after_pae_check:
        "3:\n"
        // Use byte code for CR3 and CR4 operations so they are
        // translated correctly in 32bit mode (not 64bit opcodes).
        // Below byte code is equivalent to "mov cr4, eax".
        "\t.byte    0x0f \n"
        "\t.byte    0x22 \n"
        "\t.byte    0xe0 \n"

        // restore current_guest_states_virt_addr in rcx
        "\tmovl %%esi, %%ecx\n"
        "\txorl %%eax, %%eax\n"
        "\tmovl %%edi, %%eax\n"
        // load CR3 with cr3_td_sm_32 which has the mapping of
        // Use byte code for CR3 and CR4 operations so they are
        // translated correctly in 32bit mode (not 64bit opcodes).
        // Below byte code is equivalent to "mov cr3, eax"
        "\t.byte    0x0f \n"
        "\t.byte    0x22 \n"
        "\t.byte    0xd8 \n"
        // teardown_shared_memory's gva and gpa, except those 3
        // pages of shared memory, other are 1:1 mapping (va = pa)
        // for 32-bit mode
				"\tmovq  %%cr0, %%rax\n"
				//; enable IA32 paging (32-bits)
				"\tbts  $31, %%eax\n"
				"\tmovq  %%rax, %%cr0 \n"
				// finally, call teardownthunk entry in guest space. and never returns.  
				"\tjmp  %%rbx\n"
				"\tmovq %%rax, %[result]\n"
    : [result]"=g" (result)
    : [current_guest_states_phy_addr] "g" (current_guest_states_phy_addr), 
      [compatibility_cs] "g" (compatibility_cs), 
      [teardown_thunk_entry_phy_addr] "g" (teardown_thunk_entry_phy_addr), 
      [cr3_td_sm_32] "g" (cr3_td_sm_32), 
      [cr4_pae_is_on] "g" (cr4_pae_is_on)
    :"%rax", "%r8", "cc"
	);
	return result;
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
	int result = 0;
	/*
  asm volatile(
        "\tmovl    %[current_cpu_idx], %%rcx\n"
        "\tmovq    %[current_guest_states_hvu], %%rdx\n"
        "\tmovq    %[teardown_thunk_entry_hva], %%r8\n"
        "\tmovq    %%r8, %%rbx\n"
        "\tjmp     %%rbx\n"
        "\tmovq    %%rax, %[result]\n"
    : [result]"=g" (result)
    : [current_cpu_idx] "g" (current_cpu_idx), 
      [current_guest_states_hvu] "g" (current_guest_states_hva), 
      [teardown_thunk_entry_hva] "g" (teardown_thunk_entry_hva)
    :"%rax", "%r8"
	);
*/
  return result;
}

