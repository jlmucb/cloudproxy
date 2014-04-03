/*
 * File: linktest.c
 * Description: Get tbooted and boot 64 bit evmm
 * Author: John Manferdelli
 *
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *           http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "stdio.h"
#include "string.h"
#include <stdlib.h>


typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef long long unsigned uint64_t;


void vmm_main(uint32_t local_apic_id, uint64_t startup_struct_u, 
              uint64_t application_params_struct_u, uint64_t reserved)
{
    printf("In vmm_main\n");
    printf("\tlocal_apic_id: %d, startup_struct_u: %ld\n", local_apic_id, (long int)startup_struct_u);
    printf("\tapplication_params_struct_u: %ld, reserved: %ld\n",
           (long int)application_params_struct_u, (long int)reserved);
    exit(0);
}


int main(int an, char* av)
{
    uint64_t vmm_main_entry_point= (uint64_t) vmm_main;
    uint32_t local_apic_id= 1;
    uint64_t p_startup_struct= 2ULL;
    uint64_t application_params_struct= 3ULL;
    uint64_t evmm_reserved= 4ULL;

    printf("vmm_main: 0x%016lx, vmm_main: 0x%016lx\n", 
           (long unsigned int) vmm_main_entry_point, (long unsigned int)vmm_main);

    asm volatile (
        "\tpushq    %[evmm_reserved]\n"
        "\tpushq    %[application_params_struct]\n"
        "\tpushq    %[p_startup_struct]\n"
        "\tpushq    %[local_apic_id]\n"

        // for following retf
        // "\tjmp 1f\n"
        "\tpush $1f\n"
        "\tret\n"
"1:\n"
        "\tpopq %%rdi\n"
        "\tpopq %%rsi\n"
        "\tpopq %%rdx\n"
        "\tpopq %%rcx\n"
        "\tjmpq   %[vmm_main_entry_point]\n"
        "\tud2\n"
    :: [local_apic_id] "m" (local_apic_id), [p_startup_struct] "m" (p_startup_struct), 
       [application_params_struct] "m" (application_params_struct), [evmm_reserved] "m" (evmm_reserved), 
       [vmm_main_entry_point] "m" (vmm_main_entry_point)
    : "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi");

    return 0;
}

