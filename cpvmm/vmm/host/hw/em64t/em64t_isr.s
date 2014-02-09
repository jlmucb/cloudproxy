#
# Copyright (c) 2013 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

.intel_syntax
.text

# Calling conventions
#
# Floating : First 4 parameters – XMM0 through XMM3. Others passed on stack.
#
# Integer  : First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
#
# Aggregates (8, 16, 32, or 64 bits) and __m64:
#              First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
#
# Aggregates (other):
#            By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
#
# __m128   : By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
#
#
#
# Return values that can fit into 64-bits are returned through RAX (including __m64 types),
# except for __m128, __m128i, __m128d, floats, and doubles, which are returned in XMM0.
# If the return value does not fit within 64 bits, then the caller assumes the responsibility
# of allocating and passing a pointer for the return value as the first argument. Subsequent
# arguments are then shifted one argument to the right. That same pointer must be returned
# by the callee in RAX. User defined types to be returned must be 1, 2, 4, 8, 16, 32, or 64
# bits in length.
#
#
#.include       ia32_registers.equ
#.include "vmm_arch_defs.h"
.extern VMM_GP_REGISTERS
#
#
# Register usage
#
# Caller-saved and scratch:
#        RAX, RCX, RDX, R8, R9, R10, R11
# Callee-saved
#        RBX, RBP, RDI, RSI, R12, R13, R14, and R15
#

.extern g_exception_gpr
.extern exception_class
.extern isr_c_handler

.set	VECTOR_19, 19

# enum EXCEPTION_CLASS_ENUM in uVmm\vmm\host\isr.c
.set	FAULT_CLASS, 2

.text

#
#  UINT8 __stdcall
#  hw_isr (
#          void
#  );
#
#  ISR handler. Pushes hardcoded CPU ID onto stack and jumps to vector routine
#
#  Stack offsets on entry:
#
#  eax register will contain result         Bits 7-0: #Physical Address Bits
#                                Bits 15-8: #Virtual Address Bits
#                                Bits 31-16: Reserved =
#

.macro isr_entry_macro vector
        push vector
        jmp  hw_isr_c_wrapper
.endm

.globl	hw_isr_c_wrapper
hw_isr_c_wrapper:
        push   %rax	# offset 08
        push   %rbx  	# offset 00

        # If an exception fault is detected, save the GPRs
        # for the assertion debug buffer

        mov    %rbx, qword ptr [%rsp+0x10]	# vector number
        # all exception faults have vector number up to 19
        cmp    %rbx, VECTOR_19
        jg    1f 

        # check the exception type
        lea    %rax, qword ptr exception_class
        movzx  %ebx, byte ptr [%rbx+%rax]
        cmp    %ebx, FAULT_CLASS
        jne    1f 

        # Save GPRs
        mov    %rax, qword ptr [%rsp+0x08]             # this is rax
        mov    %rbx, g_exception_gpr
        mov    [%rbx], %rax

        mov    %rax, qword ptr [%rsp+0x00]             # this is rbx
        mov    8[%rbx], %rax

        # now save all other GP registers except RIP,RSP,RFLAGS
        mov    16[%rbx], %rcx
        mov    24[%rbx], %rdx
        mov    32[%rbx], %rdi
        mov    40[%rbx], %rsi
        mov    48[%rbx], %rbp
        mov    64[%rbx],  %r8
        mov    72[%rbx],  %r9
        mov    80[%rbx], %r10
        mov    88[%rbx], %r11
        mov    96[%rbx], %r12
        mov    104[%rbx], %r13
        mov    112[%rbx], %r14
        mov    120[%rbx], %r15
			1:
        pop    %rbx
        pop    %rax

        #; save context and prepare stack for C-function
        #; at this point stack contains
        #;..................................
        #; [       SS         ]
        #; [       RSP        ]
        #; [      RFLAGS      ]
        #; [       CS         ]
        #; [       RIP        ] <= here RSP should point prior iret
        #; [[   errcode      ]]    optionally
        #; [    vector ID     ] <= RSP
        push    %rcx             # save RCX which used for argument passing
        mov     %rcx, %rsp
        add     %rcx, 0x8         # now RCX points to the location of vector ID
        push    %rdx
        push    %rax
        push    %r8
        push    %r9
        push    %r10
        push    %r11
        push    %r15             # used for saving unaligned stack
        mov     %r15, %rsp        # save RSP prior alignment
        and     %rsp, 0x0FFFFFFFFFFFFFFF0 # align on 16 bytes boundary
        sub     %rsp, 0x020       # prepare space for C-function
        call    isr_c_handler
        mov     %rsp, %r15        # restore unaligned RSP
        pop     %r15
        pop     %r11
        pop     %r10
        pop     %r9
        pop     %r8
        pop     %rax
        pop     %rdx
        pop     %rcx
        pop     %rsp             # isr_c_handler replaces vector ID with pointer to the
                                # RIP. Just pop the pointer to the RIP into RSP.
        iretq

#; functions below instantiate isr_entry_macro for 256 vectors (IDT entries)

.func isr_entry_00
        push 0x000
        jmp  hw_isr_c_wrapper
.endfunc
#isr_entry_00 ENDP

.func isr_entry_01
        push 0x001
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_02
        push 0x002
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_03
        push 0x003
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_04
        push 0x004
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_05
        push 0x005
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_06
        push 0x006
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_07
        push 0x007
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_08
        push 0x008
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_09
        push 0x009
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_0a
        push 0x00a
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_0b
        push 0x00b
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_0c
        push 0x00c
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_0d
        push 0x00d
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_0e
        push 0x00e
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_0f
        push 0x00f
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_10
        push 0x010
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_11
        push 0x011
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_12
        push 0x012
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_13
        push 0x013
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_14
        push 0x014
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_15
        push 0x015
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_16
        push 0x016
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_17
        push 0x017
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_18
        push 0x018
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_19
        push 0x019
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_1a
        push 0x01a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_1b
        push 0x01b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_1c
        push 0x01c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_1d
        push 0x01d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_1e
        push 0x01e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_1f
        push 0x01f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_20
        push 0x020
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_21
        push 0x021
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_22
        push 0x022
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_23
        push 0x023
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_24
        
.endfunc

.func isr_entry_25
        push 0x025
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_26
        push 0x026
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_27
        push 0x027
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_28
        push 0x028
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_29
        push 0x029
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_2a
        push 0x02a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_2b
        push 0x02b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_2c
        push 0x02c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_2d
        push 0x02d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_2e
        push 0x02e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_2f
        push 0x02f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_30
        push 0x030
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_31
        push 0x031
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_32
        push 0x032
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_33
        push 0x033
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_34
        push 0x034
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_35
        push 0x035
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_36
        push 0x036
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_37
        push 0x037
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_38
        push 0x038
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_39
        push 0x039
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_3a
        push 0x03a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_3b
        push 0x03b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_3c
        push 0x03c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_3d
        push 0x03d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_3e
        push 0x03e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_3f
        push 0x03f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_40
        push 0x040
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_41
        push 0x041
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_42
        push 0x042
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_43
        push 0x043
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_44
        push 0x044
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_45
        push 0x045
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_46
        push 0x046
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_47
        
.endfunc

.func isr_entry_48
        push 0x048
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_49
        push 0x049
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_4a
        push 0x04a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_4b
        push 0x04b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_4c
        push 0x04c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_4d
        push 0x04d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_4e
        push 0x04e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_4f
        push 0x04f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_50
        push 0x050
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_51
        push 0x051
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_52
        push 0x052
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_53
        push 0x053
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_54
        push 0x054
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_55
        push 0x055
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_56
        push 0x056
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_57
        push 0x057
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_58
        push 0x058
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_59
        push 0x059
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_5a
        push 0x05a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_5b
        push 0x05b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_5c
        push 0x05c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_5d
        push 0x05d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_5e
        push 0x05e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_5f
        push 0x05f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_60
        push 0x060
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_61
        push 0x061
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_62
        push 0x062
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_63
        push 0x063
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_64
        push 0x064
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_65
        push 0x065
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_66
        push 0x066
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_67
        push 0x067
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_68
        push 0x068
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_69
        push 0x069
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_6a
        push 0x06a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_6b
        push 0x06b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_6c
        push 0x06c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_6d
        push 0x06d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_6e
        push 0x06e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_6f
        push 0x06f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_70
        push 0x070
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_71
        push 0x071
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_72
        push 0x072
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_73
        push 0x073
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_74
        push 0x074
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_75
        push 0x075
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_76
        push 0x076
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_77
        push 0x077
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_78
        push 0x078
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_79
        
.endfunc

.func isr_entry_7a
        push 0x07a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_7b
        push 0x07b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_7c
        push 0x07c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_7d
        push 0x07d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_7e
        push 0x07e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_7f
        push 0x07f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_80
        push 0x080
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_81
        push 0x081
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_82
        push 0x082
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_83
        push 0x083
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_84
        push 0x084
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_85
        push 0x085
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_86
        push 0x086
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_87
        push 0x087
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_88
        push 0x088
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_89
        push 0x089
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_8a
        push 0x08a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_8b
        push 0x08b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_8c
        push 0x08c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_8d
        push 0x08d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_8e
        push 0x08e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_8f
        push 0x08f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_90
        push 0x090
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_91
        push 0x091
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_92
        push 0x092
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_93
        push 0x093
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_94
        push 0x094
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_95
        push 0x095
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_96
        push 0x096
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_97
        push 0x097
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_98
        push 0x098
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_99
        push 0x099
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_9a
        push 0x09a
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_9b
        push 0x09b
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_9c
        push 0x09c
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_9d
        push 0x09d
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_9e
        push 0x09e
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_9f
        push 0x09f
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a0
        push 0x0a0
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a1
        push 0x0a1
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a2
        push 0x0a2
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a3
        push 0x0a3
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a4
        push 0x0a4
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a5
        push 0x0a5
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a6
        push 0x0a6
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a7
        push 0x0a7
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a8
        push 0x0a8
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_a9
        push 0x0a9
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_aa
        push 0x0aa
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ab
        push 0x0ab
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ac
        push 0x0ac
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ad
        push 0x0ad
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ae
        push 0x0ae
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_af
        
.endfunc

.func isr_entry_b0
        push 0x0b0
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b1
        push 0x0b1
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b2
        push 0x0b2
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b3
        push 0x0b3
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b4
        push 0x0b4
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b5
        push 0x0b5
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b6
        push 0x0b6
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b7
        push 0x0b7
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b8
        push 0x0b8
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_b9
        push 0x0b9
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ba
        push 0x0ba
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_bb
        push 0x0bb
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_bc
        push 0x0bc
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_bd
        push 0x0bd
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_be
        push 0x0be
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_bf
        push 0x0bf
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c0
        push 0x0c0
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c1
        push 0x0c1
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c2
        push 0x0c2
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c3
        push 0x0c3
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c4
        push 0x0c4
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c5
        push 0x0c5
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c6
        push 0x0c6
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c7
        push 0x0c7
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c8
        push 0x0c8
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_c9
        push 0x0c9
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ca
        push 0x0ca
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_cb
        push 0x0cb
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_cc
        push 0x0cc
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_cd
        push 0x0cd
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_ce
        push 0x0ce
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_cf
        push 0x0cf
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_d0
        push 0x0d0
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_d1
        push 0x0d1
        jmp  hw_isr_c_wrapper
.endfunc

.func isr_entry_d2
        push 0x0d2
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_d3
        push 0x0d3
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_d4
        push 0x0d4
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_d5
        push 0x0d5
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_d6
        push 0x0d6
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_d7
        push 0x0d7
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_d8
        push 0x0d8
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_d9
        push 0x0d9
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_da
        push 0x0da
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_db
        push 0x0db
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_dc
        push 0x0dc
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_dd
        push 0x0dd
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_de
        push 0x0de
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_df
        push 0x0df
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e0
        push 0x0e0
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e1
        push 0x0e1
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e2
        push 0x0e2
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e3
        push 0x0e3
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e4
        push 0x0e4
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e5
        push 0x0e5
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e6
        push 0x0e6
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e7
        push 0x0e7
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e8
        push 0x0e8
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_e9
        push 0x0e9
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ea
        push 0x0ea
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_eb
        push 0x0eb
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ec
        push 0x0ec
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ed
        push 0x0ed
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ee
        push 0x0ee
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ef
        push 0x0ef
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f0
        push 0x0f0
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f1
        push 0x0f1
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f2
        push 0x0f2
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f3
        push 0x0f3
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f4
        push 0x0f4
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f5
        push 0x0f5
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f6
        push 0x0f6
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f7
        push 0x0f7
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f8
        push 0x0f8
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_f9
        push 0x0f9
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_fa
        push 0x0fa
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_fb
        push 0x0fb
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_fc
        push 0x0fc
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_fd
        push 0x0fd
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_fe
        push 0x0fe
        jmp  hw_isr_c_wrapper
        
.endfunc

.func isr_entry_ff
        push 0x0ff
        jmp  hw_isr_c_wrapper
.endfunc
