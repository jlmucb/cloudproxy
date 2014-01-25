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
#define VMM_NATIVE_VMCALL_SIGNATURE 0x024694D40

struct VMEXIT_TIME {
    UINT64  last_vmexit;
    UINT64  last_vmentry;
    UINT64  last_reason;
    UINT64  last_cpu_id;
    UINT64  this_vmexit;
    UINT64  this_vmentry;
    UINT64  this_reason;
    UINT64  this_cpu_id;
};


void zero_exit_time(struct VMEXIT_TIME *p)
{
    p->last_vmexit= 0ULL;
    p->last_vmentry= 0ULL;
    p->last_reason= 0ULL;
    p->last_cpu_id= 0ULL;
    p->this_vmexit= 0ULL;
    p->this_vmentry= 0ULL;
    p->this_reason= 0ULL;
    p->this_cpu_id= 0ULL;
}

void vmexit_func()
// Function:    Called upon VMEXIT. Saves GP registers, allocates stack
//              for C-function and calls it.
// Arguments:   none
{
    gcpu_save_registers();
    asm volatile(
        "\txor      %%rcx, %%rcx\n" \
        "\tcmpq     $4,%%rcx\n" \
        "\tja       1f\n" \
        "\tmovq     $4, %%rcx\n" \
        // vmexit_l1:      # parameters are normalized
        "1:\n" \
        "\tshlq     $3, %%rcx\n" \
        "\tsubq     %%rcx, %%rsp\n" \
        "\tcall    vmexit_common_handler\n" \
        "2:\n" \
        "\tjmp     2b\n"
    : 
    : 
    :"%rcx");
}

void vmentry_func(UINT32 firsttime)
// Function:    Called upon VMENTRY.
// Arguments:   firsttime = 1 if called first time
{

    if(firsttime==0ULL)
        gcpu_restore_registers();

    asm volatile(
        // Resume execution of Guest Virtual Machine
        "\tvmresume\n" \
        "\tjmp     1f\n" \
//do_launch:
        "\tcall    gcpu_restore_registers\n" \
        // Launch execution of Guest Virtual Machine
        "\tvmlaunch\n" \
// handle_error:
        "1:\n" \
        // use RFLAGS as argument if VMRESUME failed
        "\tpushfq\n" \
        // JLM FIX:  save arguments for vm_failure function
    : 
    : 
    :"%rcx", "%rdx");
    vmentry_failure_function();
    vmentry_func(0ULL);
}

UINT64 hw_vmcall(UINT64 vmcall_id, UINT64 arg1, UINT64 arg2, UINT64 arg3)
// Function:    VMCALL
// uVMM expects the following:
//     vmcall_id in RCX
//     arg1      in RDX
//     arg2      in RDI
//     arg3      in RSI
// return value in RAX
{
    UINT64  result;

    asm volatile(
        "\tmovq %[vmcall_id], %%rcx\n" \
        "\tmovq %[arg1], %%rdx\n" \
        "\tmovq %[arg2], %%rdi\n" \
        "\tmovq %[arg3], %%rsi\n" \
        "\tmovq 0x024694D40, %%rax\n" \
        "\tvmcall\n" \
        "\tjmp  2f\n" \
        "1:\n" \
        "\tjmp  1b\n" \
        "2:\n" \
    : 
    : [vmcall_id] "g" (vmcall_id), [arg1] "g" (arg1), [arg2] "g" (arg2), [arg3] "g" (arg3)
    :"%rax", "%rdi", "%rsi", "%r8", "%rcx", "%rdx");
    return result;
}
