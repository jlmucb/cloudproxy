/*
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
 */

#include "vmm_defs.h"
#include "ept_hw_layer.h"

void vmm_asm_invept (INVEPT_ARG *arg, UINT32 modifier, UINT64 *rflags)
{
    asm volatile(
        "\tmovq %[arg], %%rcx\n" 
        "\tmovq %[modifier], %%rdx\n" 
        "\tmovq %[rflags], %%r8\n" 
        "\tmov %%rcx, %%rax \n"
        "\tmov %%rdx, %%rcx \n"
        "\tinvept (%%rax), %%rcx\n" 
        "\tpushfq\n"
        "\tpop (%%r8) \n"
    : 
    : [arg] "m" (arg), [modifier] "m" (modifier), [rflags] "m" (rflags)
    : "rax", "rcx", "rdx", "r8");
        return;
}

/*
 * VOID vmm_asm_invvpid (
 *    INVEPT_ARG   *arg,                ;rcx
 *    UINT32       modifier     ;rdx
 *    UINT64       *rflags)     ;r8
 */
void vmm_asm_invvpid (INVVPID_ARG *arg, UINT32 modifier, UINT64 *rflags) 
{
    asm volatile(
        "\tmovq %[arg], %%rcx\n" 
        "\tmovq %[modifier], %%rdx\n" 
        "\tmovq %[rflags], %%r8\n" 
        "\tmovq %%rcx, %%rax \n"
        "\tmovq %%rdx, %%rcx \n"
        "\tinvvpid (%%rax), %%rcx\n" 
        "\tpushfq \n"
        "\tpop (%%r8) \n"
    :
    : [arg] "m" (arg), [modifier] "m" (modifier), [rflags] "m" (rflags)
    : "%rax", "%rcx", "%rdx", "%r8");
    return;
}
