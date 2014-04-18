/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "vmm_defs.h"


void vmm_lock_write (UINT64 *mem_loc, UINT64 new_data)
{
    asm volatile(
        "\tmovq       %[mem_loc], %%rcx\n"
        "\tmovq       %[new_data], %%rdx\n"
        "\tlock; xchgq (%%rcx),%%rdx\n"
    :
    : [mem_loc] "m"(mem_loc), [new_data] "m"(new_data)
    :"%rcx", "%rdx");
}


UINT32 vmm_rdtsc (UINT32   *upper)
{
    UINT32 ret;
    asm volatile(
        "\tmovl  %[upper], %%ecx\n"
        "\trdtsc\n"
        "\tmovl    (%%ecx), %%edx\n"
        "\tmovl    %%edx,%[ret]\n"
    : [ret] "=m" (ret)
    : [upper] "m"(upper)
    :"%ecx", "%edx");
    return ret;
}


void vmm_write_xcr(UINT64 xcr)
{
    asm volatile(
        "\tmovq       %[xcr], %%rax\n"
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
        "\tvmread    %%rax,%%rax\n"
        "\tmovq     %%rax, %[result]\n"
    : [result]"=g"(result)
    : 
    :"%rax");
    return result;
}


UINT64 vmexit_reason()
{
    UINT64  result;
    asm volatile(
        "\tmovq   $0x4402, %%rax\n"
        "\tvmread %%rax, %%rax\n"
        "\tmovq   %%rax, %[result]\n"
    : [result]"=g"(result)
    : 
    :"%rax");
    return result;
}


UINT32 vmexit_check_ept_violation(void)
//if it is ept_violation_vmexit, return exit qualification
//  in EAX, otherwise, return 0 in EAX
{
    UINT32  result;
    asm volatile(
        "\tmovq   $0x4402, %%rax\n"
        "\tvmread %%rax, %%rax\n" 
        "\tcmp     $48,%%ax\n" 
        "\tjnz    1f\n" 
        "\tmovq   $0x6400, %%rax\n" 
        "\tvmread %%rax, %%rax\n" 
        "\tmovl   %%eax, %[result]\n"
        "\tjmp    2f\n" 
        "1:\n" 
        "\tmovq   $0x00, %%rax\n" 
        "\tmovl   %%eax, %[result]\n"
        "2:\n" 
    : [result]"=m"(result)
    : :"%rax", "%al");
    return result;
}


// CHECK(JLM)
void vmm_vmcs_guest_state_read(void)
{
    UINT64  result;

    // JLM: note assumes arg is in %rcx
    asm volatile(
        "\tmovq     $0x681e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\tmovq     $0x6820, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x440c, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6800, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6802, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6804, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x681a, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0800, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6806, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4800, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4814, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0802, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6808, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4802, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4816, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0804, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x680a, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4804, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4818, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0806, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x680c, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4806, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x481a, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0808, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x680e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4808, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x481c, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x080a, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6810, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x480a, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x481e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x080c, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6812, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x480c, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4820, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x080e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6814, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x480e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4822, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6816, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4810, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6818, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4812, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x681c, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x681e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6820, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6822, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2800, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2802, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4824, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4826, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4828, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x482a, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6824, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6826, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\tmovl     %%edx, %%eax\n"
        "\tcmp      $0, %%eax\n"
        "jnz        1f\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2804, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2806, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x280a, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x280c, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x280e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2810, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x482e, %%rax\n"
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\tjmp      2f\n"
        
        "1:\n"
        "\tmovq     $0x00, %%rax\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq %%rax, (%%rcx)\n"

        "2:\n"
        "\tmovq %%rax, %[result]\n"
    : [result]"=g"(result)
    : 
    :"%rax", "%rcx");
}
