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


int vmx_on(UINT64* address) {
    int  ret= 0;
#ifdef JLMDEBUG
    bprint("vmx_on %p 0x%016lx\n", address, *address);
#endif
    asm volatile(
        "\tclc\n"
        "\tvmxon %[address]\n"
        "\tjnc    1f\n"
        "\tmovl  $2, %[ret]\n"
        "\tjmp    2f\n"
    "1:\n"
        "\tjz    2f\n"
        "\tmovl  $1, %[ret]\n"
    "2:\n"
    : [ret]"=g" (ret)
    :[address]"m" (address)
    :"memory");
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

int vmx_vmclear(UINT64* address) {
#ifdef JLMDEBUG
    bprint("vmclear %p 0x%016lx\n", address, *address);
    HexDump((UINT8*)address, (UINT8*)address+16);
    // HexDump((UINT8*)*address, (UINT8*)*address+16);
    LOOP_FOREVER
#endif
    asm volatile(
        "\tvmclear %[address]\n"
    ::[address]"m"(address)
    :"memory");
#ifdef JLMDEBUG
    bprint("vmclear done\n");
    LOOP_FOREVER
#endif
    return 0;
}

HW_VMX_RET_VALUE hw_vmx_flush_current_vmcs(UINT64 *address) {
    return vmx_vmclear(address);
}

int vmx_vmlaunch() {
#ifdef JLMDEBUG
    bprint("vmxlaunch, waiting\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tvmlaunch\n"
    ::: "memory");
    return 0;
}

int vmx_vmresume() {
#ifdef JLMDEBUG
    bprint("vmresume\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tvmresume\n"
    :::"cc", "memory");
    return 0;
}


int vmx_vmptrld(UINT64 *address) {
#ifdef JLMDEBUG
    bprint("vmptrld, waiting\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tvmptrld %[address]\n"
    ::[address] "p" (address)
    :"memory");
    return 0;
}

void vmx_vmptrst(UINT64 *address) {
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
#ifdef JLMDEBUG
    bprint("vmread, waiting\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tvmread %1, %0\n"
    :"=rm"(value)
    :"r"(index)
    :"cc");
    return 0;
}

int vmx_vmwrite(UINT64 index, UINT64 *value) {
#ifdef JLMDEBUG
    bprint("vmwrite, waiting\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tvmwrite %1, %0\n"
    : :"r"(index), "rm"(value)
    :"cc", "memory");
    return 0;
}

HW_VMX_RET_VALUE hw_vmx_write_current_vmcs(UINT64 field_id, UINT64 *value ) {
        return vmx_vmwrite(field_id, value);
}

HW_VMX_RET_VALUE hw_vmx_read_current_vmcs(UINT64 field_id, UINT64 *value ) {
        return vmx_vmread(field_id, value);
}

