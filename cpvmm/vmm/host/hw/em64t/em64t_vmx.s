#
# Copyright (c) 2013 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. 
#

# Reset the stack after a C-function call.
# %rcx must be set to the number of arguments before this macro is called.
.macro RESTORE_C_STACK
        cmp     $4, %rcx
        ja      1f
        mov     $4, %rcx                # at least 4 arguments
1:                                     # parameters are normalized
        shl     $3, %rcx
        add     %rcx, %rsp
.endm


# Prepare the stack for a call to a C function.
# %rcx must be set to the number of arguments before this macro is called.
.macro ALLOCATE_C_STACK
        cmp     $4, %rcx
        ja      1f
        mov     $4, %rcx
1:
        shl     $3, %rcx
        sub     %rcx, %rsp
.endm

# vmexit_func is called when a vmexit happens.
.globl vmexit_func
.type vmexit_func, @function
vmexit_func:
        call    gcpu_save_registers
        xor     %rcx, %rcx
        ALLOCATE_C_STACK
   
        call    vmexit_common_handler
        jmp     .                       # should never return


# vmentry_func is called by eVMM to perform a vmlaunch/vmresume.
# %rdi (the first argument) is set to 1 if this is the first time this
# function is called, and it's set to 0 otherwise.
.globl vmentry_func
.type vmentry_func, @function
vmentry_func:
        push    %rdi
        cmp     $0, %rdi
        jnz     1f
        call    gcpu_restore_registers 
        vmresume                        # Resume execution of Guest Virtual Machine

        jmp     2f
1:
        # remove the following 
        #call    fixupvmcs               # temporary debug function
        call    gcpu_restore_registers
        vmlaunch                        # Launch execution of Guest Virtual Machine

2:
        pushfq                          # use RFLAGS as argument if VMRESUME failed
        pop     %rdx                    # save RFLAGS in RDX
        mov     $1, %rcx                # RCX contains number of argments for vmentry_failure_function
        ALLOCATE_C_STACK                # for for vmentry_failure_function
        mov     %rdx, %rdi              # 1st argument (passed via RDI) contains RFLAGS
        call    vmentry_failure_function
        mov     $1, %rcx                # RCX contains number of argments for vmentry_failure_function
        RESTORE_C_STACK
        pop     %rdi                    # restore RDI. stack is expected to be the same as in entry point
        jmp     vmentry_func            # retry


# hw_vmcall converts a C function call in the guest into a vmcall VM exit
# with arguments that match the vmcall calling convention for eVMM. That is:
#      vmcall_id in RCX
#      arg1 in RDX
#      arg2 in RDI
#      arg3 in RSI
#
# Note that the original code could avoid dealing with the first two arguments,
# since they are also the first two arguments in the Microsoft calling
# convention. But these arguments need to be transformed by this version.
# In this case, the arguments come in as rdi, rsi, rcx, rdx, and they need to be
# rcx, rdx, rdi, rsi. So, we swap rdi and rcx, and we swap rsi and rdx.
.globl hw_vmcall
.type hw_vmcall, @function
hw_vmcall:
        push    %rdi
        mov     %rcx, %rdi
        pop     %rcx

        push    %rsi
        mov     %rdx, %rsi
        pop     %rdx

        mov     $0x024694D40, %rax
        vmcall
        ret
