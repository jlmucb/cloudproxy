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
#include "ept_hw_layer.h"


void vmm_asm_invept(INVEPT_ARG *arg, UINT32 modifier, UINT64 *rflags)
{
    __asm__ volatile(
        "\tmovq     %[arg], %%rdi\n" 
        "\txorq     %%rsi, %%rsi\n" 
        "\tmovl     %[modifier], %%esi\n" 
        "\tmovq     %[rflags], %%rdx\n" 
        "\tinvept   (%%rdi), %%rsi\n" 
        "\tpushfq\n"
        "\tpop      (%%rdx) \n"
    : 
    : [arg] "g" (arg), [modifier] "g" (modifier), [rflags] "g" (rflags)
    : "%rdx", "%rdi", "%rsi");
    return;
}


void vmm_asm_invvpid (INVVPID_ARG *arg, UINT32 modifier, UINT64 *rflags) 
{
    __asm__ volatile(
        "\tmovq     %[arg], %%rdi\n" 
        "\txorq     %%rsi, %%rsi\n" 
        "\tmovl     %[modifier], %%esi\n" 
        "\tmovq     %[rflags], %%rdx\n" 
        "\tinvvpid  (%%rdi), %%rsi\n" 
        "\tpushfq\n"
        "\tpop      (%%rdx) \n"
    : : [arg] "g" (arg), [modifier] "g" (modifier), [rflags] "g" (rflags)
    : "%rdx", "%rdi", "%rsi");
    return;
}
