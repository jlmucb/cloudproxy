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

        mov    %rbx, qword ptr [%rsp+$0x10h]	# vector number
        # all exception faults have vector number up to 19
        cmp    %rbx, VECTOR_19
        jg     continue

        # check the exception type
        lea    %rax, qword ptr exception_class
        movzx  %ebx, byte ptr [%rbx+%rax]
        cmp    %ebx, FAULT_CLASS
        jne     continue

        # Save GPRs
        mov    %rax, qword ptr [%rsp+$0x08h]             # this is rax
        mov    %rbx, g_exception_gpr
#RNB: TODO need to fix the struct VMM_GP_REGISTERS
        mov    [%rbx], %rax

        mov    %rax, qword ptr [%rsp+$0x00h]             # this is rbx
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
continue:
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
        add     %rcx, $8         # now RCX points to the location of vector ID
        push    %rdx
        push    %rax
        push    %r8
        push    %r9
        push    %r10
        push    %r11
        push    %r15             # used for saving unaligned stack
        mov     %r15, %rsp        # save RSP prior alignment
        and     %rsp, $0x0FFFFFFFFFFFFFFF0h # align on 16 bytes boundary
        sub     %rsp, $0x020h       # prepare space for C-function
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


#; the functions below instantiate isr_entry_macro for 256 vectors (IDT entries)

#RNB: TODO the constants should potentially be prefixed with $0x, but waiting
# 	until the proc/macro are fixed

.text

.func isr_entry_00
        isr_entry_macro $0x000
.endfunc
#isr_entry_00 ENDP

.func isr_entry_01
        isr_entry_macro $0x001
.endfunc

.func isr_entry_02
        isr_entry_macro $0x002
.endfunc

.func isr_entry_03
        isr_entry_macro $0x003
.endfunc

.func isr_entry_04
        isr_entry_macro $0x004
.endfunc

.func isr_entry_05
        isr_entry_macro $0x005
.endfunc

.func isr_entry_06
        isr_entry_macro $0x006
.endfunc

.func isr_entry_07
        isr_entry_macro $0x007
.endfunc

.func isr_entry_08
        isr_entry_macro $0x008
.endfunc

.func isr_entry_09
        isr_entry_macro $0x009
.endfunc

.func isr_entry_0a
        isr_entry_macro $0x00a
.endfunc

.func isr_entry_0b
        isr_entry_macro $0x00b
.endfunc

.func isr_entry_0c
        isr_entry_macro $0x00c
.endfunc

.func isr_entry_0d
        isr_entry_macro $0x00d
.endfunc

.func isr_entry_0e
        isr_entry_macro $0x00e
.endfunc

.func isr_entry_0f
        isr_entry_macro $0x00f
.endfunc

.func isr_entry_10
        isr_entry_macro $0x010
.endfunc

.func isr_entry_11
        isr_entry_macro $0x011
.endfunc

.func isr_entry_12
        isr_entry_macro $0x012
.endfunc

.func isr_entry_13
        isr_entry_macro $0x013
.endfunc

.func isr_entry_14
        isr_entry_macro $0x014
.endfunc

.func isr_entry_15
        isr_entry_macro $0x015
.endfunc

.func isr_entry_16
        isr_entry_macro $0x016
.endfunc

.func isr_entry_17
        isr_entry_macro $0x017
.endfunc

.func isr_entry_18
        isr_entry_macro $0x018
.endfunc

.func isr_entry_19
        isr_entry_macro $0x019
.endfunc

.func isr_entry_1a
        isr_entry_macro $0x01a
.endfunc

.func isr_entry_1b
        isr_entry_macro $0x01b
.endfunc

.func isr_entry_1c
        isr_entry_macro $0x01c
.endfunc

.func isr_entry_1d
        isr_entry_macro $0x01d
.endfunc

.func isr_entry_1e
        isr_entry_macro $0x01e
.endfunc

.func isr_entry_1f
        isr_entry_macro $0x01f
.endfunc

.func isr_entry_20
        isr_entry_macro $0x020
.endfunc

.func isr_entry_21
        isr_entry_macro $0x021
.endfunc

.func isr_entry_22
        isr_entry_macro $0x022
.endfunc

.func isr_entry_23
        isr_entry_macro $0x023
.endfunc

.func isr_entry_24
        isr_entry_macro $0x024
.endfunc

.func isr_entry_25
        isr_entry_macro $0x025
.endfunc

.func isr_entry_26
        isr_entry_macro $0x026
.endfunc

.func isr_entry_27
        isr_entry_macro $0x027
.endfunc

.func isr_entry_28
        isr_entry_macro $0x028
.endfunc

.func isr_entry_29
        isr_entry_macro $0x029
.endfunc

.func isr_entry_2a
        isr_entry_macro $0x02a
.endfunc

.func isr_entry_2b
        isr_entry_macro $0x02b
.endfunc

.func isr_entry_2c
        isr_entry_macro $0x02c
.endfunc

.func isr_entry_2d
        isr_entry_macro $0x02d
.endfunc

.func isr_entry_2e
        isr_entry_macro $0x02e
.endfunc

.func isr_entry_2f
        isr_entry_macro $0x02f
.endfunc

.func isr_entry_30
        isr_entry_macro $0x030
.endfunc

.func isr_entry_31
        isr_entry_macro $0x031
.endfunc

.func isr_entry_32
        isr_entry_macro $0x032
.endfunc

.func isr_entry_33
        isr_entry_macro $0x033
.endfunc

.func isr_entry_34
        isr_entry_macro $0x034
.endfunc

.func isr_entry_35
        isr_entry_macro $0x035
.endfunc

.func isr_entry_36
        isr_entry_macro $0x036
.endfunc

.func isr_entry_37
        isr_entry_macro $0x037
.endfunc

.func isr_entry_38
        isr_entry_macro $0x038
.endfunc

.func isr_entry_39
        isr_entry_macro $0x039
.endfunc

.func isr_entry_3a
        isr_entry_macro $0x03a
.endfunc

.func isr_entry_3b
        isr_entry_macro $0x03b
.endfunc

.func isr_entry_3c
        isr_entry_macro $0x03c
.endfunc

.func isr_entry_3d
        isr_entry_macro $0x03d
.endfunc

.func isr_entry_3e
        isr_entry_macro $0x03e
.endfunc

.func isr_entry_3f
        isr_entry_macro $0x03f
.endfunc

.func isr_entry_40
        isr_entry_macro $0x040
.endfunc

.func isr_entry_41
        isr_entry_macro $0x041
.endfunc

.func isr_entry_42
        isr_entry_macro $0x042
.endfunc

.func isr_entry_43
        isr_entry_macro $0x043
.endfunc

.func isr_entry_44
        isr_entry_macro $0x044
.endfunc

.func isr_entry_45
        isr_entry_macro $0x045
.endfunc

.func isr_entry_46
        isr_entry_macro $0x046
.endfunc

.func isr_entry_47
        isr_entry_macro $0x047
.endfunc

.func isr_entry_48
        isr_entry_macro $0x048
.endfunc

.func isr_entry_49
        isr_entry_macro $0x049
.endfunc

.func isr_entry_4a
        isr_entry_macro $0x04a
.endfunc

.func isr_entry_4b
        isr_entry_macro $0x04b
.endfunc

.func isr_entry_4c
        isr_entry_macro $0x04c
.endfunc

.func isr_entry_4d
        isr_entry_macro $0x04d
.endfunc

.func isr_entry_4e
        isr_entry_macro $0x04e
.endfunc

.func isr_entry_4f
        isr_entry_macro $0x04f
.endfunc

.func isr_entry_50
        isr_entry_macro $0x050
.endfunc

.func isr_entry_51
        isr_entry_macro $0x051
.endfunc

.func isr_entry_52
        isr_entry_macro $0x052
.endfunc

.func isr_entry_53
        isr_entry_macro $0x053
.endfunc

.func isr_entry_54
        isr_entry_macro $0x054
.endfunc

.func isr_entry_55
        isr_entry_macro $0x055
.endfunc

.func isr_entry_56
        isr_entry_macro $0x056
.endfunc

.func isr_entry_57
        isr_entry_macro $0x057
.endfunc

.func isr_entry_58
        isr_entry_macro $0x058
.endfunc

.func isr_entry_59
        isr_entry_macro $0x059
.endfunc

.func isr_entry_5a
        isr_entry_macro $0x05a
.endfunc

.func isr_entry_5b
        isr_entry_macro $0x05b
.endfunc

.func isr_entry_5c
        isr_entry_macro $0x05c
.endfunc

.func isr_entry_5d
        isr_entry_macro $0x05d
.endfunc

.func isr_entry_5e
        isr_entry_macro $0x05e
.endfunc

.func isr_entry_5f
        isr_entry_macro $0x05f
.endfunc

.func isr_entry_60
        isr_entry_macro $0x060
.endfunc

.func isr_entry_61
        isr_entry_macro $0x061
.endfunc

.func isr_entry_62
        isr_entry_macro $0x062
.endfunc

.func isr_entry_63
        isr_entry_macro $0x063
.endfunc

.func isr_entry_64
        isr_entry_macro $0x064
.endfunc

.func isr_entry_65
        isr_entry_macro $0x065
.endfunc

.func isr_entry_66
        isr_entry_macro $0x066
.endfunc

.func isr_entry_67
        isr_entry_macro $0x067
.endfunc

.func isr_entry_68
        isr_entry_macro $0x068
.endfunc

.func isr_entry_69
        isr_entry_macro $0x069
.endfunc

.func isr_entry_6a
        isr_entry_macro $0x06a
.endfunc

.func isr_entry_6b
        isr_entry_macro $0x06b
.endfunc

.func isr_entry_6c
        isr_entry_macro $0x06c
.endfunc

.func isr_entry_6d
        isr_entry_macro $0x06d
.endfunc

.func isr_entry_6e
        isr_entry_macro $0x06e
.endfunc

.func isr_entry_6f
        isr_entry_macro $0x06f
.endfunc

.func isr_entry_70
        isr_entry_macro $0x070
.endfunc

.func isr_entry_71
        isr_entry_macro $0x071
.endfunc

.func isr_entry_72
        isr_entry_macro $0x072
.endfunc

.func isr_entry_73
        isr_entry_macro $0x073
.endfunc

.func isr_entry_74
        isr_entry_macro $0x074
.endfunc

.func isr_entry_75
        isr_entry_macro $0x075
.endfunc

.func isr_entry_76
        isr_entry_macro $0x076
.endfunc

.func isr_entry_77
        isr_entry_macro $0x077
.endfunc

.func isr_entry_78
        isr_entry_macro $0x078
.endfunc

.func isr_entry_79
        isr_entry_macro $0x079
.endfunc

.func isr_entry_7a
        isr_entry_macro $0x07a
.endfunc

.func isr_entry_7b
        isr_entry_macro $0x07b
.endfunc

.func isr_entry_7c
        isr_entry_macro $0x07c
.endfunc

.func isr_entry_7d
        isr_entry_macro $0x07d
.endfunc

.func isr_entry_7e
        isr_entry_macro $0x07e
.endfunc

.func isr_entry_7f
        isr_entry_macro $0x07f
.endfunc

.func isr_entry_80
        isr_entry_macro $0x080
.endfunc

.func isr_entry_81
        isr_entry_macro $0x081
.endfunc

.func isr_entry_82
        isr_entry_macro $0x082
.endfunc

.func isr_entry_83
        isr_entry_macro $0x083
.endfunc

.func isr_entry_84
        isr_entry_macro $0x084
.endfunc

.func isr_entry_85
        isr_entry_macro $0x085
.endfunc

.func isr_entry_86
        isr_entry_macro $0x086
.endfunc

.func isr_entry_87
        isr_entry_macro $0x087
.endfunc

.func isr_entry_88
        isr_entry_macro $0x088
.endfunc

.func isr_entry_89
        isr_entry_macro $0x089
.endfunc

.func isr_entry_8a
        isr_entry_macro $0x08a
.endfunc

.func isr_entry_8b
        isr_entry_macro $0x08b
.endfunc

.func isr_entry_8c
        isr_entry_macro $0x08c
.endfunc

.func isr_entry_8d
        isr_entry_macro $0x08d
.endfunc

.func isr_entry_8e
        isr_entry_macro $0x08e
.endfunc

.func isr_entry_8f
        isr_entry_macro $0x08f
.endfunc

.func isr_entry_90
        isr_entry_macro $0x090
.endfunc

.func isr_entry_91
        isr_entry_macro $0x091
.endfunc

.func isr_entry_92
        isr_entry_macro $0x092
.endfunc

.func isr_entry_93
        isr_entry_macro $0x093
.endfunc

.func isr_entry_94
        isr_entry_macro $0x094
.endfunc

.func isr_entry_95
        isr_entry_macro $0x095
.endfunc

.func isr_entry_96
        isr_entry_macro $0x096
.endfunc

.func isr_entry_97
        isr_entry_macro $0x097
.endfunc

.func isr_entry_98
        isr_entry_macro $0x098
.endfunc

.func isr_entry_99
        isr_entry_macro $0x099
.endfunc

.func isr_entry_9a
        isr_entry_macro $0x09a
.endfunc

.func isr_entry_9b
        isr_entry_macro $0x09b
.endfunc

.func isr_entry_9c
        isr_entry_macro $0x09c
.endfunc

.func isr_entry_9d
        isr_entry_macro $0x09d
.endfunc

.func isr_entry_9e
        isr_entry_macro $0x09e
.endfunc

.func isr_entry_9f
        isr_entry_macro $0x09f
.endfunc

.func isr_entry_a0
        isr_entry_macro $0x0a0
.endfunc

.func isr_entry_a1
        isr_entry_macro $0x0a1
.endfunc

.func isr_entry_a2
        isr_entry_macro $0x0a2
.endfunc

.func isr_entry_a3
        isr_entry_macro $0x0a3
.endfunc

.func isr_entry_a4
        isr_entry_macro $0x0a4
.endfunc

.func isr_entry_a5
        isr_entry_macro $0x0a5
.endfunc

.func isr_entry_a6
        isr_entry_macro $0x0a6
.endfunc

.func isr_entry_a7
        isr_entry_macro $0x0a7
.endfunc

.func isr_entry_a8
        isr_entry_macro $0x0a8
.endfunc

.func isr_entry_a9
        isr_entry_macro $0x0a9
.endfunc

.func isr_entry_aa
        isr_entry_macro $0x0aa
.endfunc

.func isr_entry_ab
        isr_entry_macro $0x0ab
.endfunc

.func isr_entry_ac
        isr_entry_macro $0x0ac
.endfunc

.func isr_entry_ad
        isr_entry_macro $0x0ad
.endfunc

.func isr_entry_ae
        isr_entry_macro $0x0ae
.endfunc

.func isr_entry_af
        isr_entry_macro $0x0af
.endfunc

.func isr_entry_b0
        isr_entry_macro $0x0b0
.endfunc

.func isr_entry_b1
        isr_entry_macro $0x0b1
.endfunc

.func isr_entry_b2
        isr_entry_macro $0x0b2
.endfunc

.func isr_entry_b3
        isr_entry_macro $0x0b3
.endfunc

.func isr_entry_b4
        isr_entry_macro $0x0b4
.endfunc

.func isr_entry_b5
        isr_entry_macro $0x0b5
.endfunc

.func isr_entry_b6
        isr_entry_macro $0x0b6
.endfunc

.func isr_entry_b7
        isr_entry_macro $0x0b7
.endfunc

.func isr_entry_b8
        isr_entry_macro $0x0b8
.endfunc

.func isr_entry_b9
        isr_entry_macro $0x0b9
.endfunc

.func isr_entry_ba
        isr_entry_macro $0x0ba
.endfunc

.func isr_entry_bb
        isr_entry_macro $0x0bb
.endfunc

.func isr_entry_bc
        isr_entry_macro $0x0bc
.endfunc

.func isr_entry_bd
        isr_entry_macro $0x0bd
.endfunc

.func isr_entry_be
        isr_entry_macro $0x0be
.endfunc

.func isr_entry_bf
        isr_entry_macro $0x0bf
.endfunc

.func isr_entry_c0
        isr_entry_macro $0x0c0
.endfunc

.func isr_entry_c1
        isr_entry_macro $0x0c1
.endfunc

.func isr_entry_c2
        isr_entry_macro $0x0c2
.endfunc

.func isr_entry_c3
        isr_entry_macro $0x0c3
.endfunc

.func isr_entry_c4
        isr_entry_macro $0x0c4
.endfunc

.func isr_entry_c5
        isr_entry_macro $0x0c5
.endfunc

.func isr_entry_c6
        isr_entry_macro $0x0c6
.endfunc

.func isr_entry_c7
        isr_entry_macro $0x0c7
.endfunc

.func isr_entry_c8
        isr_entry_macro $0x0c8
.endfunc

.func isr_entry_c9
        isr_entry_macro $0x0c9
.endfunc

.func isr_entry_ca
        isr_entry_macro $0x0ca
.endfunc

.func isr_entry_cb
        isr_entry_macro $0x0cb
.endfunc

.func isr_entry_cc
        isr_entry_macro $0x0cc
.endfunc

.func isr_entry_cd
        isr_entry_macro $0x0cd
.endfunc

.func isr_entry_ce
        isr_entry_macro $0x0ce
.endfunc

.func isr_entry_cf
        isr_entry_macro $0x0cf
.endfunc

.func isr_entry_d0
        isr_entry_macro $0x0d0
.endfunc

.func isr_entry_d1
        isr_entry_macro $0x0d1
.endfunc

.func isr_entry_d2
        isr_entry_macro $0x0d2
.endfunc

.func isr_entry_d3
        isr_entry_macro $0x0d3
.endfunc

.func isr_entry_d4
        isr_entry_macro $0x0d4
.endfunc

.func isr_entry_d5
        isr_entry_macro $0x0d5
.endfunc

.func isr_entry_d6
        isr_entry_macro $0x0d6
.endfunc

.func isr_entry_d7
        isr_entry_macro $0x0d7
.endfunc

.func isr_entry_d8
        isr_entry_macro $0x0d8
.endfunc

.func isr_entry_d9
        isr_entry_macro $0x0d9
.endfunc

.func isr_entry_da
        isr_entry_macro $0x0da
.endfunc

.func isr_entry_db
        isr_entry_macro $0x0db
.endfunc

.func isr_entry_dc
        isr_entry_macro $0x0dc
.endfunc

.func isr_entry_dd
        isr_entry_macro $0x0dd
.endfunc

.func isr_entry_de
        isr_entry_macro $0x0de
.endfunc

.func isr_entry_df
        isr_entry_macro $0x0df
.endfunc

.func isr_entry_e0
        isr_entry_macro $0x0e0
.endfunc

.func isr_entry_e1
        isr_entry_macro $0x0e1
.endfunc

.func isr_entry_e2
        isr_entry_macro $0x0e2
.endfunc

.func isr_entry_e3
        isr_entry_macro $0x0e3
.endfunc

.func isr_entry_e4
        isr_entry_macro $0x0e4
.endfunc

.func isr_entry_e5
        isr_entry_macro $0x0e5
.endfunc

.func isr_entry_e6
        isr_entry_macro $0x0e6
.endfunc

.func isr_entry_e7
        isr_entry_macro $0x0e7
.endfunc

.func isr_entry_e8
        isr_entry_macro $0x0e8
.endfunc

.func isr_entry_e9
        isr_entry_macro $0x0e9
.endfunc

.func isr_entry_ea
        isr_entry_macro $0x0ea
.endfunc

.func isr_entry_eb
        isr_entry_macro $0x0eb
.endfunc

.func isr_entry_ec
        isr_entry_macro $0x0ec
.endfunc

.func isr_entry_ed
        isr_entry_macro $0x0ed
.endfunc

.func isr_entry_ee
        isr_entry_macro $0x0ee
.endfunc

.func isr_entry_ef
        isr_entry_macro $0x0ef
.endfunc

.func isr_entry_f0
        isr_entry_macro $0x0f0
.endfunc

.func isr_entry_f1
        isr_entry_macro $0x0f1
.endfunc

.func isr_entry_f2
        isr_entry_macro $0x0f2
.endfunc

.func isr_entry_f3
        isr_entry_macro $0x0f3
.endfunc

.func isr_entry_f4
        isr_entry_macro $0x0f4
.endfunc

.func isr_entry_f5
        isr_entry_macro $0x0f5
.endfunc

.func isr_entry_f6
        isr_entry_macro $0x0f6
.endfunc

.func isr_entry_f7
        isr_entry_macro $0x0f7
.endfunc

.func isr_entry_f8
        isr_entry_macro $0x0f8
.endfunc

.func isr_entry_f9
        isr_entry_macro $0x0f9
.endfunc

.func isr_entry_fa
        isr_entry_macro $0x0fa
.endfunc

.func isr_entry_fb
        isr_entry_macro $0x0fb
.endfunc

.func isr_entry_fc
        isr_entry_macro $0x0fc
.endfunc

.func isr_entry_fd
        isr_entry_macro $0x0fd
.endfunc

.func isr_entry_fe
        isr_entry_macro $0x0fe
.endfunc

.func isr_entry_ff
        isr_entry_macro $0x0ff
.endfunc
