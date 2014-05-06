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
#define VMM_NATIVE_VMCALL_SIGNATURE 0x024694D40
#ifdef JLMDEBUG
#include "bootstrap_print.h"
#include "jlmdebug.h"

UINT64   t_vmcs_save_area[512];  // never bigger than 4KB
extern void vmm_print_vmcs_region(UINT64* pu);
extern void vmm_vmcs_guest_state_read(UINT64* area);
#endif

extern void gcpu_save_registers();
extern void gcpu_restore_registers();
extern void vmentry_failure_function(ADDRESS);
extern void vmm_vmcs_guest_state_read(UINT64* area);

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


// Function:    Called upon VMEXIT. Saves GP registers, allocates stack
//              for C-function and calls it.
#if 0
// temporary hack so we dont loop
#ifdef JLMDEBUG
static int count= 0;
#endif
void vmexit_func()
{
#ifdef JLMDEBUG
    bprint("vmexit_func %d\n", count);
    if(count>1)
        LOOP_FOREVER
    count++;
#endif
    gcpu_save_registers();
#if 0
    asm volatile(
        "\txor      %%rcx, %%rcx\n"
        "\tshlq     $3, %%rcx\n" 
        "\tsubq     %%rcx, %%rsp\n"
        "\tcall     vmexit_common_handler\n"
        "2:\n"
        "\tjmp     2b\n"
    : : :"%rcx");
#else
    vmexit_common_handler();
#endif
}

#else

asm(
".text\n"
".globl vmexit_func\n"
".type vmexit_func,@function\n"
"vmexit_func:\n"
    "\tcall   gcpu_save_registers\n"
    // call c-function
    // QUESTION for Tom: do need to do this mov to rbp?
    "\tmov    %rsp, %rbp\n"
    "\tsubq   $8, %rsp\n"  // is this needed?
    "\tcall   vmexit_common_handler\n"
    "\tjmp    .\n"
    "\tret\n"
);

#endif


#ifdef JLMDEBUG
// remove: to prevent loops in single guest testing
static int count= 0;

asm(
".text\n"
".globl loop_forever\n"
".type loop_forever, @function\n"
"loop_forever:\n"
    "\tjmp   .\n"
    "\tret\n"
);


extern int vmx_vmread(UINT64 index, UINT64 *value);
extern int vmx_vmwrite(UINT64 index, UINT64 value);
// fixup control registers and make guest loop forever
void fixupvmcs()
{
    UINT64  value;
    void loop_forever();
    UINT16* loop= loop_forever;

#ifdef JLMDEBUG
    bprint("fixupvmcs %04x\n", *loop);
#endif
    vmx_vmread(0x681e, &value);  // guest_rip
    *((UINT16*) value)= *loop;    // feeb

    vmx_vmread(0x4000, &value);  // vmx_pin_controls
    // vmx_vmwrite(0x4000, value);  // vmx_pin_controls

    vmx_vmread(0x4002, &value);  // vmx_cpu_controls)
    // vmx_vmwrite(0x4002, value);  // vmx_cpu_controls)

    vmx_vmread(0x4012, &value);  // vmx_entry_controls
    // vmx_vmwrite(0x4012, value);  // vmx_entry_controls

    vmx_vmread(0x4002, &value);  // vmx_exit_controls
    // vmx_vmwrite(0x4002, value);  // vmx_exit_controls
}


#endif


void vmentry_func(UINT32 firsttime)
// Function:    Called upon VMENTRY.
// Arguments:   firsttime = 1 if called first time
{
#ifdef JLMDEBUG
    // first time print out vmcs
    if(firsttime) {
        fixupvmcs();
        if(count++>0)
            LOOP_FOREVER
        bprint("vmentry_func: %d, vmcs area:\n", firsttime);
        vmm_vmcs_guest_state_read((UINT64*) t_vmcs_save_area);
        vmm_print_vmcs_region((UINT64*) t_vmcs_save_area);
        bprint("I think linux starts at 0x%016llx\n", t_vmcs_save_area[0]);
    }
#endif
    // Assumption: rflags_arg is still addressable (by %rsp).
    // The asm file sets rcx to the number of args (1)
    ADDRESS rflags_arg = 0;

    if(firsttime) { //do_launch
        gcpu_restore_registers();
        asm volatile (
            "\tvmlaunch\n"
            "\tpushfq\n"  // push rflags
            "\tpop      %%rdx\n" 
            "\tmovq     %%rdx, %[rflags_arg]\n" 
        :[rflags_arg] "=m" (rflags_arg) 
        ::);  // rdx need not be saved
    } 
    else {  //do_resume
        gcpu_restore_registers();
#ifdef JLMDEBUG
        bprint("In resume\n");
        LOOP_FOREVER
#endif
        asm volatile(
            // Resume execution of Guest Virtual Machine
            "\tvmresume\n" 
            "\tpushfq \n"  // push rflags
            "\tpop      %%rdx\n" 
            "\tmovq     %%rdx, %[rflags_arg]\n" 
        : [rflags_arg] "=m" (rflags_arg) 
        ::);  // rdx need not be saved
    }               
    vmentry_failure_function(rflags_arg);
#ifdef JLMDEBUG
    bprint("after vmentry_failure_function returns\n");
    LOOP_FOREVER
#endif
    vmentry_func(0ULL);  // 0ULL= FALSE
}


// CHECK(JLM)
UINT64 hw_vmcall(UINT64 vmcall_id, UINT64 arg1, UINT64 arg2, UINT64 arg3)
// Function:    VMCALL
// uVMM expects the following:
{
    UINT64  result= 0ULL;

    // Original asm file mov r8 -> rsi and r9 ->rdi, not sure why?
    asm volatile(
        "\tmovq %[vmcall_id], %%rcx\n"
        "\tmovq %[arg1], %%rdx\n"
        "\tmovq %[arg2], %%rdi\n"
        "\tmovq %[arg3], %%rsi\n"
        "\tmovq $0x024694D40, %%rax\n"
        "\tvmcall\n"
        "\tmovq %%rax, %[result] \n"
        "\tjmp  2f\n"
        "1:\n"
        "\tjmp 1b\n"
        "2:\n"
    : [result] "=g" (result) 
    : [vmcall_id] "g" (vmcall_id), [arg1] "g" (arg1), 
      [arg2] "g" (arg2), [arg3] "g" (arg3)
    : "%rax", "%rdi", "%rsi", "%r8", "%rcx", "%rdx");
    return result;
}


