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


void vmm_lock_write (UINT64 *mem_loc, UINT64 new_data)
{
    asm volatile(
        "\tmovq       %[mem_loc], %%rcx\n" \
        "\tmovq       %[new_data], %%rdx\n" \
        "\tlock xchg    (%%rdx),(%%rcx)\n"
    :
    : [mem_loc] "m"(mem_loc), [new_data] "m"(new_data)
    :"%rcx", "%rdx");
}


UINT32 vmm_rdtsc (UINT32   *upper)
{
    asm volatile(
        "\tmovl       %[upper], %%ecx\n" \
        "\trstsc\n" \
        "\tmovl    %eds, (%%ecx)\n"
    :
    : [mem_loc] "m"(mem_loc), [new_data] "m"(new_data)
    :"%ecx", "%edx");
}


void vmm_write_xcr(UINT64 xcr)
{
    asm volatile(
        "\tmovq       %[xcr], %%rax\n" \
        "\txsetbv\n"
    :
    : [xcr] "g"(xcr)
    :"%rax");
}


UINT64 vmm_read_xcr()
{
    UINT64  result;

    asm volatile(
        "\txgetbv\n"
        "movq   %%rcx, %[result]\n"
    : [result]"=g"(result)
    : 
    :"%rcx", "%rdx");
    return result;
}


UINT64 gcpu_read_guestrip (void)
{
    UINT64  result;

    asm volatile(
        "\tvmread    %%rax,%%rax\n" \
        "movq   %%rax, %[result]\n"
    : [result]"=g"(result)
    : 
    :"%rax");
    return result;
}


UINT64 vmexit_reason()
{
    UINT64  result;
    asm volatile(
        "\tmovq   0x4402, %%rax\n"
        "\tvmread %%rax, %%rax\n"
        "\tmovq   %%rax, %[result]\n"
    : [result]"=g"(result)
    : 
    :"%rax");
    return result;
}


UINT32 vmexit_check_ept_violation(void)
//if it is ept_voilation_vmexit, return exit qualification
//  in EAX, otherwise, return 0 in EAX
{
    UINT32  result;
    asm volatile(
        "\tmovq   0x4402, %%rax\n"
        "\tvmread %%rax, %%rax\n" 
        "\tcmpb   %%rax, $48\n" 
        "\tjnz    1f\n" 
        "\tmovq   0x6400, %%rax\n" 
        "\tvmread %%rax, %%rax\n" 
        "\tmovl   %%rax, %[result]\n"
        "\tjmp    2f\n" 
        "1:\n" 
        "\tmovq   0x00, %%rax\n" 
        "\tmovl   %%rax, %[result]\n"
        "2:\n" 
    : [result]"=g"(result)
    : 
    :"%rax");
    return result;
}


void vmm_vmcs_guest_state_read(void)
{
    UINT64  result;

    // JLM: note assumes arg is in %rcx, FIX
    asm volatile(
        "\tmovq     0x681e, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     0x620e, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%rcx+8)\n" \
        "\taddq     $16, %%rcx\n" \
        "\tmovq     0x440c, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx)\n" \
        "\tmovq     0x6800, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+8)\n" \
        "\tmovq     0x6802, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+16)\n" \
        "\tmovq     0x6804, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+24)\n" \
        "\tmovq     0x681a, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+32)\n" \
        "\tmovq     0x0800, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+40)\n" \
        "\tmovq     0x6806, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+48)\n" \
        "\tmovq     0x4800, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+56)\n" \
        "\tmovq     0x4814, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+64)\n" \
        "\tmovq     0x0802, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+72)\n" \
        "\tmovq     0x6808, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, 0(%%rcx+8)\n" \
        "\tmovq     0x4802, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+88)\n" \
        "\tmovq     0x4816, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+96)\n" \
        "\tmovq     0x0804, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+104)\n" \
        "\tmovq     0x680a, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+112)\n" \
        "\tmovq     0x4804, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+120)\n" \
        "\tmovq     0x4818, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+128)\n" \
        "\tmovq     0x0806, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+136)\n" \
        "\tmovq     0x680c, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+144)\n" \
        "\tmovq     0x4806, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+152)\n" \
        "\tmovq     0x481a, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+160)\n" \
        "\tmovq     0x0808, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+168)\n" \
        "\tmovq     0x680e, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+176)\n" \
        "\tmovq     0x4808, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+184)\n" \
        "\tmovq     0x481c, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+192)\n" \
        "\tmovq     0x080a, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+200)\n" \
        "\tmovq     0x6810, %%rax\n" \
        "\tmovq     0x6810, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+208)\n" \
        "\tmovq     0x480a, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+216)\n" \
        "\tmovq     0x481e, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+224)\n" \
        "\tmovq     0x080c, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+232)\n" \
        "\tmovq     0x6812, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+240)\n" \
        "\tmovq     0x480c, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+248)\n" \
        "\tmovq     0x4820, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+256)\n" \
        "\tmovq     0x080e, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+264)\n" \
        "\tmovq     0x6814, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+272)\n" \
        "\tmovq     0x480e, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+280)\n" \
        "\tmovq     0x4822, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+288)\n" \
        "\tmovq     0x6816, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+296)\n" \
        "\tmovq     0x4810, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+304)\n" \
        "\tmovq     0x6818, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+312)\n" \
        "\tmovq     0x4812, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+320)\n" \
        "\tmovq     0x681c, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+328)\n" \
        "\tmovq     0x681e, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+336)\n" \
        "\tmovq     0x6820, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+344)\n" \
        "\tmovq     0x6822, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+352)\n" \
        "\tmovq     0x2800, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+360)\n" \
        "\tmovq     0x2802, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+368)\n" \
        "\tmovq     0x4824, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+376)\n" \
        "\tmovq     0x4826, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+384)\n" \
        "\tmovq     0x4828, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+392)\n" \
        "\tmovq     0x482a, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+400)\n" \
        "\tmovq     0x6824, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+408)\n" \
        "\tmovq     0x6826, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+416)\n" \

        "\tmovl     %%edx, %%eax\n" \
        "\tcmpl     %%eax, $0\n" \
        "jnz        $1f\n" \

        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+424)\n" \
        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+432)\n" \
        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+440)\n" \
        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+440)\n" \
        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+448)\n" \
        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+456)\n" \
        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+464)\n" \
        "\tmovq     0x, %%rax\n" \
        "\tvmread   %%rax, %%rax\n" \
        "\tmovq     %%rax, (%%rcx+472)\n" \
        "\tjmp      2f\n" \
        
        "1:\n" \
        "\tmovq 0x00, %%rax\n" \
        "\tmovq %%rax, (%%rcx+424)\n" \
        "\tmovq %%rax, (%%rcx+432)\n" \
        "\tmovq %%rax, (%%rcx+440)\n" \
        "\tmovq %%rax, (%%rcx+448)\n" \
        "\tmovq %%rax, (%%rcx+456)\n" \
        "\tmovq %%rax, (%%rcx+464)\n" \
        "\tmovq %%rax, (%%rcx+472)\n" \

        "2:\n" \
        "\tmovq %%rax, %[result]\n" \
    : [result]"=g"(result)
    : 
    :"%rax", "%rcx");
}
        
