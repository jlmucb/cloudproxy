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


// CHECK(JLM)
void hw_pause( void ) {
// Execute assembler 'pause' instruction
    asm volatile(
        "pause\n"
        :::);
    return;
}


void hw_monitor( void* addr, UINT32 extension, UINT32 hint) {
    // Execute assembler 'monitor' instruction
    asm volatile(
        "\tmovq %[addr], %%rcx\n" 
        "\tmovq %[extension], %%rdx\n" 
        "\tmovq %[hint], %%r8\n" 
        "\tmovq %%rcx, %%rax\n" 
        "\tmovq %%rdx, %%rcx\n"
        "\tmovq %%r8, %%rdx\n"
        "\tmonitor\n"
        : : [addr] "m" (addr), [extension] "m" (extension), [hint] "m" (hint)
        :"rax", "rcx", "rdx", "r8");
        return;
}

// Execute assembler 'mwait' instruction
void hw_mwait( UINT32 extension, UINT32 hint ) {
    asm volatile(
        "\tmovq %[extension], %%rcx\n"
        "\tmovq %[hint], %%rdx\n"
        "\tmovq %%rdx, %%rax\n"
        // changed the macro .byte... to mwait instruction for better portability.
        "\tmwait %%rax, %%rcx\n"
    : : [extension] "m" (extension), [hint] "m" (hint)
    :"rax", "rbx", "rcx", "rdx");
    return;
}

