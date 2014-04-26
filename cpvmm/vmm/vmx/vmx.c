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
#include "hw_utils.h"
#include "hw_vmx_utils.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


int vmx_on(UINT64* ptr_to_vmcs_region) {
    int  ret= 0;
    UINT64   address= *ptr_to_vmcs_region;
#ifdef JLMDEBUG
    bprint("vmx_on %p %d %d\n", ptr_to_vmcs_region, sizeof(int), ret);
#endif
    asm volatile(
        "\tmovl $0, %[ret]\n"
        "\tvmxon %[address]\n"
        "\tjnc    1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp    2f\n"
    "1:\n"
        "\tjnz   2f\n"
        "\tmovl  $1, %[ret]\n"
    "2:\n"
    : [ret]"=g" (ret)
    :[address]"m" (address)
    :);
    return ret;
}

void vmx_off() {
#ifdef JLMDEBUG
    bprint("vmx_off\n");
#endif
    asm volatile(
        "\tvmxoff\n"
    :: :"cc");
    return;
}


int vmx_vmclear(UINT64* ptr_to_vmcs_region) {
    int ret= 0;
    UINT64   address= *ptr_to_vmcs_region;
#ifdef JLMDEBUG
    bprint("vmclear %p\n", ptr_to_vmcs_region);
#endif
    asm volatile(
        "\tmovl $0, %[ret]\n"
        "\tvmclear %[address]\n"
        "\tjnc    1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp    2f\n"
    "1:\n"
        "\tjnz   2f\n"
        "\tmovl  $1, %[ret]\n"
    "2:\n"
    : [ret]"=g" (ret)
    : [address]"m"(address)
    :"memory");
    return ret;
}

int hw_vmx_flush_current_vmcs(UINT64 *address) {
    return vmx_vmclear(address);
}

int vmx_vmlaunch() {
    int ret= 0;
#ifdef JLMDEBUG
    bprint("vmxlaunch, waiting\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tmovl $0, %[ret]\n"
        "\tvmlaunch\n"
        "\tjnc    1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp    2f\n"
    "1:\n"
        "\tjnz   2f\n"
        "\tmovl  $1, %[ret]\n"
    "2:\n"
    :  [ret]"=g" (ret)
    :: "memory");
    return ret;
}

int vmx_vmresume() {
    int ret= 0;
#ifdef JLMDEBUG
    bprint("vmresume\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tmovl $0, %[ret]\n"
        "\tvmresume\n"
        "\tjnc    1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp    2f\n"
    "1:\n"
        "\tjnz   2f\n"
        "\tmovl  $1, %[ret]\n"
    "2:\n"
    : [ret]"=g" (ret)
    ::"cc", "memory");
    return ret;
}


int vmx_vmptrld(UINT64 *ptr_to_vmcs_region) {
    int ret= 0;
    UINT64   address= *ptr_to_vmcs_region;
#ifdef JLMDEBUG
    bprint("vmptrld, waiting 0x%016lx\n", address);
#endif
    asm volatile(
        "\tmovl $0, %[ret]\n"
        "\tvmptrld %[address]\n"
        "\tjnc    1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp    2f\n"
    "1:\n"
        "\tjnz   2f\n"
        "\tmovl  $1, %[ret]\n"
    "2:\n"
    : [ret]"=g" (ret)
    :[address] "m" (address)
    :"memory");
    return ret;
}

void vmx_vmptrst(UINT64 *ptr_to_vmcs_region) {
    int ret= 0;
    UINT64   address= *ptr_to_vmcs_region;
#ifdef JLMDEBUG
    bprint("vmptrst, waiting\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tvmptrst %[address]\n"
    ::[address] "p" (address)
    :"memory");
    return;
}


int vmx_vmread(UINT64 index, UINT64 *value) {
    int ret= 0;
#ifdef JLMDEBUG
    bprint("vmread, waiting %d, 0x%016lx\n", index, *value);
#endif
    asm volatile(
        "\tmovq %[index], %%rax\n"
        "\tmovl $0, %[ret]\n"
        "\tvmread %%rax, %%rax\n"
        "\tjnc   1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp   3f\n"
    "1:\n"
        "\tjnz   2f\n"
        "\tmovl  $1, %[ret]\n"
        "\tjmp   3f\n"
    "2:\n"
        "\tmovq %[value], %%rbx\n"
        "\tmovq %%rax, (%%rbx)\n"
    "3:\n"
    : [ret]"=g" (ret)
    : [value] "p"(value), [index] "g"(index)
    :"%rax", "%rbx");
#ifdef JLMDEBUG
    bprint("vmread, done 0x%016lx\n", *value);
    LOOP_FOREVER
#endif
    return ret;
}

// CHECK(JLM)
int vmx_vmwrite(UINT64 index, UINT64 *value) {
    int ret= 0;
#ifdef JLMDEBUG
    bprint("vmwrite, waiting\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tmovq %[index], %%rax\n"
        "\tmovq %[value], %%rbx\n"
        "\tmovq (%%rbx), %%rbx\n"
        "\tmovl $0, %[ret]\n"
        "\tvmwrite %%rax, %%rbx\n"
        "\tjnc    1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp    2f\n"
    "1:\n"
        "\tjnz   2f\n"
        "\tmovl  $1, %[ret]\n"
    "2:\n"
    : [ret] "=g" (ret) 
    : [index] "g"(index), [value] "g"(value)
    :"%rbx", "%rax");
    return ret;
}


int hw_vmx_write_current_vmcs(UINT64 field_id, UINT64 *value ) {
        return vmx_vmwrite(field_id, value);
}


int hw_vmx_read_current_vmcs(UINT64 field_id, UINT64 *value ) {
        return vmx_vmread(field_id, value);
}

