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

#include "vmm_defs.h"
typedef long long unsigned uint64_t;
typedef unsigned uint32_t;
typedef short unsigned uint16_t;
typedef unsigned char uint8_t;
typedef int bool;
#include "multiboot.h"
#include "elf_defns.h"
#include "tboot.h"


// this is all 32 bit code
// tboot jumps in here

// Questions: where does the multiboot header come from


multiboot_info_t *g_mbi;


typedef void (*tboot_printk)(const char *fmt, ...);
// TODO(tmroeder): this should be the real base, but I want it to compile.
//uint64_t tboot_shared_page = 0;

int main(int an, char** av) {

    //tboot_shared_t *shared_page = (tboot_shared_t *)(tboot_shared_page);
    tboot_printk tprintk = (tboot_printk)(0x80d7f0);
    tprintk("<3>Testing printf\n");
    while(1) ;


    // TODO(tmroeder): remove this debugging while loop: added so we can see the
    // code that we're calling
    // get mbi and shared page info
    // flip into 64 bit mode
    // set up stack 
    // jump to evmm_main

   // int evmm_main (multiboot_info_t *evmm_mbi, const void *elf_image, int size) 
}

