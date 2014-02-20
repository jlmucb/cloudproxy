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


/*---------------------------------------------------*
*
* file      : x32_init64.c
* purpose   : implement transition to 64-bit execution mode
*
*----------------------------------------------------*/

#include "vmm_defs.h"
#include "ia32_low_level.h"
#include "x32_init64.h"

#define PSE_BIT     0x10
#define PAE_BIT     0x20


// void __cdecl start_64bit_mode(
//      address MUST BE 32-bit wide, because it delivered to 64-bit code 
//      using 32-bit push/retf commands
//      __attribute__((cdecl)) 
void start_64bit_mode(UINT32 address, UINT32 segment, UINT32* arg1, 
                        UINT32* arg2, UINT32* arg3, UINT32* arg4)
{
#if 0
    asm volatile (
        // prepare arguments for 64-bit mode
        // there are 3 arguments
        // align stack and push them on 8-byte alignment
        "\txor      %%eax, %%eax\n"\
        "\tand      $7, %%esp\n"\
        "\tpush     %%eax\n"\
        "\tpush     %[arg4]\n"\
        "\tpush     %%eax\n"\
        "\tpush     %[arg3]\n"\
        "\tpush     %%eax\n"\
        "\tpush     %[arg2]\n"\
        "\tpush     %%eax\n"\
        "\tpush     %[arg1]\n"\

        "\tcli\n"\
        // push segment and offset
        "\tpush   %[segment]\n"\

        // for following retf
        "\tpush  START64\n"\
        "\tmov   %[address], %%ebx\n"\

        // initialize CR3 with PML4 base
        // mov   eax, [esp+4]
        // mov   cr3, eax
        // enable 64-bit mode
        // EFER MSR register
        "\tmov      0x0C0000080, %%ecx\n"\
        // read EFER into EAX
        "\trdmsr\n"\
        // set EFER.LME=1
        "\tbts     $8, %%eax\n"\
        // write EFER
        "\twrmsr\n"

        // enable paging CR0.PG=1
        "\tmov     cr0, %%eax\n"\
        "\tbts     $31, %%eax\n"\
        "\tmov     %%eax, cr0\n"\

        // at this point we are in 32-bit compatibility mode
        // LMA=1, CS.L=0, CS.D=1
        // jump from 32bit compatibility mode into 64bit mode.
        "\tret\n"\
"START64:\n"\
        // in 64bit this is actually pop rcx
        "\tpop    %%ecx\n"\
        // in 64bit this is actually pop rdx
        "\tpop    %%edx\n"\

        "\t_emit  0x41\n"\
        // pop r8
        "\t_emit  0x58\n"\
        "\t_emit  0x41\n"\
        // pop r9
        "\t_emit  0x59\n"\
        // in 64bit this is actually
        "\t_emit 0x48\n"\

        // sub  %%rsp, 0x18
        "\tsub    0x18, %%esp\n"\
        // in 64bit this is actually
        "\tcall   %%ebx\n"

        : // [carryout] "=m"(uCarryOut)
        : [arg1] "m" (arg1), [arg2] "m" (arg2), [arg3] "m" (arg3), [arg4] "m" (arg4), 
          [address] "m" (address), [segment] "m" (segment)
        : "%eax", "%ebx", "%ecx", "%edx");
#endif
}


void x32_init64_start( INIT64_STRUCT *p_init64_data, UINT32 address_of_64bit_code,
                      void * arg1, void * arg2, void * arg3, void * arg4)
{
    UINT32 cr4;

    ia32_write_gdtr(&p_init64_data->i64_gdtr);
    ia32_write_cr3(p_init64_data->i64_cr3);
    cr4 = ia32_read_cr4();
    BITMAP_SET(cr4, PAE_BIT | PSE_BIT);
    ia32_write_cr4(cr4);
    ia32_write_msr(0xC0000080, &p_init64_data->i64_efer);
    start_64bit_mode(address_of_64bit_code, p_init64_data->i64_cs, arg1, arg2, arg3, arg4);
}


