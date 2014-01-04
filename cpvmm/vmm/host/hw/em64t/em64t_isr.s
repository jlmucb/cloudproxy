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
       include       ia32_registers.equ
#
#
# Register usage
#
# Caller-saved and scratch:
#        RAX, RCX, RDX, R8, R9, R10, R11
# Callee-saved
#        RBX, RBP, RDI, RSI, R12, R13, R14, and R15
#

extern g_exception_gpr:NEAR
extern exception_class:NEAR
extern isr_c_handler : NEAR

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

isr_entry_macro MACRO vector:REQ
        push vector
        jmp  hw_isr_c_wrapper
ENDM



.globl	hw_isr_c_wrapper
hw_isr_c_wrapper:
        push   rax	# offset 08h
        push   rbx  	# offset 00h

        # If an exception fault is detected, save the GPRs
        # for the assertion debug buffer

        mov    rbx, qword ptr [rsp+10h]	# vector number
        # all exception faults have vector number up to 19
        cmp    rbx, VECTOR_19
        jg     continue

        # check the exception type
        lea    rax, qword ptr exception_class
        movzx  ebx, byte ptr [rbx+rax]
        cmp    ebx, FAULT_CLASS
        jne     continue

        # Save GPRs
        mov    rax, qword ptr [rsp+08h]             # this is rax
        mov    rbx, g_exception_gpr
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_RAX], rax

        mov    rax, qword ptr [rsp+00h]             # this is rbx
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_RBX], rax

        # now save all other GP registers except RIP,RSP,RFLAGS
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_RCX], rcx
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_RDX], rdx
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_RDI], rdi
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_RSI], rsi
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_RBP], rbp
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R8],  r8
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R9],  r9
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R10], r10
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R11], r11
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R12], r12
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R13], r13
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R14], r14
        mov    (VMM_GP_REGISTERS ptr [rbx]).reg[IA32_REG_R15], r15
continue:
        pop    rbx
        pop    rax

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
        push    rcx             # save RCX which used for argument passing
        mov     rcx, rsp
        add     rcx, 8         # now RCX points to the location of vector ID
        push    rdx
        push    rax
        push    r8
        push    r9
        push    r10
        push    r11
        push    r15             # used for saving unaligned stack
        mov     r15, rsp        # save RSP prior alignment
        and     rsp, 0FFFFFFFFFFFFFFF0h # align on 16 bytes boundary
        sub     rsp, 020h       # prepare space for C-function
        call    isr_c_handler
        mov     rsp, r15        # restore unaligned RSP
        pop     r15
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rax
        pop     rdx
        pop     rcx
        pop     rsp             # isr_c_handler replaces vector ID with pointer to the
                                # RIP. Just pop the pointer to the RIP into RSP.
        iretq


#; the functions below instantiate isr_entry_macro for 256 vectors (IDT entries)

isr_entry_00 PROC
        isr_entry_macro 000h
isr_entry_00 ENDP

isr_entry_01 PROC
        isr_entry_macro 001h
isr_entry_01 ENDP

isr_entry_02 PROC
        isr_entry_macro 002h
isr_entry_02 ENDP

isr_entry_03 PROC
        isr_entry_macro 003h
isr_entry_03 ENDP

isr_entry_04 PROC
        isr_entry_macro 004h
isr_entry_04 ENDP

isr_entry_05 PROC
        isr_entry_macro 005h
isr_entry_05 ENDP

isr_entry_06 PROC
        isr_entry_macro 006h
isr_entry_06 ENDP

isr_entry_07 PROC
        isr_entry_macro 007h
isr_entry_07 ENDP

isr_entry_08 PROC
        isr_entry_macro 008h
isr_entry_08 ENDP

isr_entry_09 PROC
        isr_entry_macro 009h
isr_entry_09 ENDP

isr_entry_0a PROC
        isr_entry_macro 00ah
isr_entry_0a ENDP

isr_entry_0b PROC
        isr_entry_macro 00bh
isr_entry_0b ENDP

isr_entry_0c PROC
        isr_entry_macro 00ch
isr_entry_0c ENDP

isr_entry_0d PROC
        isr_entry_macro 00dh
isr_entry_0d ENDP

isr_entry_0e PROC
        isr_entry_macro 00eh
isr_entry_0e ENDP

isr_entry_0f PROC
        isr_entry_macro 00fh
isr_entry_0f ENDP

isr_entry_10 PROC
        isr_entry_macro 010h
isr_entry_10 ENDP

isr_entry_11 PROC
        isr_entry_macro 011h
isr_entry_11 ENDP

isr_entry_12 PROC
        isr_entry_macro 012h
isr_entry_12 ENDP

isr_entry_13 PROC
        isr_entry_macro 013h
isr_entry_13 ENDP

isr_entry_14 PROC
        isr_entry_macro 014h
isr_entry_14 ENDP

isr_entry_15 PROC
        isr_entry_macro 015h
isr_entry_15 ENDP

isr_entry_16 PROC
        isr_entry_macro 016h
isr_entry_16 ENDP

isr_entry_17 PROC
        isr_entry_macro 017h
isr_entry_17 ENDP

isr_entry_18 PROC
        isr_entry_macro 018h
isr_entry_18 ENDP

isr_entry_19 PROC
        isr_entry_macro 019h
isr_entry_19 ENDP

isr_entry_1a PROC
        isr_entry_macro 01ah
isr_entry_1a ENDP

isr_entry_1b PROC
        isr_entry_macro 01bh
isr_entry_1b ENDP

isr_entry_1c PROC
        isr_entry_macro 01ch
isr_entry_1c ENDP

isr_entry_1d PROC
        isr_entry_macro 01dh
isr_entry_1d ENDP

isr_entry_1e PROC
        isr_entry_macro 01eh
isr_entry_1e ENDP

isr_entry_1f PROC
        isr_entry_macro 01fh
isr_entry_1f ENDP

isr_entry_20 PROC
        isr_entry_macro 020h
isr_entry_20 ENDP

isr_entry_21 PROC
        isr_entry_macro 021h
isr_entry_21 ENDP

isr_entry_22 PROC
        isr_entry_macro 022h
isr_entry_22 ENDP

isr_entry_23 PROC
        isr_entry_macro 023h
isr_entry_23 ENDP

isr_entry_24 PROC
        isr_entry_macro 024h
isr_entry_24 ENDP

isr_entry_25 PROC
        isr_entry_macro 025h
isr_entry_25 ENDP

isr_entry_26 PROC
        isr_entry_macro 026h
isr_entry_26 ENDP

isr_entry_27 PROC
        isr_entry_macro 027h
isr_entry_27 ENDP

isr_entry_28 PROC
        isr_entry_macro 028h
isr_entry_28 ENDP

isr_entry_29 PROC
        isr_entry_macro 029h
isr_entry_29 ENDP

isr_entry_2a PROC
        isr_entry_macro 02ah
isr_entry_2a ENDP

isr_entry_2b PROC
        isr_entry_macro 02bh
isr_entry_2b ENDP

isr_entry_2c PROC
        isr_entry_macro 02ch
isr_entry_2c ENDP

isr_entry_2d PROC
        isr_entry_macro 02dh
isr_entry_2d ENDP

isr_entry_2e PROC
        isr_entry_macro 02eh
isr_entry_2e ENDP

isr_entry_2f PROC
        isr_entry_macro 02fh
isr_entry_2f ENDP

isr_entry_30 PROC
        isr_entry_macro 030h
isr_entry_30 ENDP

isr_entry_31 PROC
        isr_entry_macro 031h
isr_entry_31 ENDP

isr_entry_32 PROC
        isr_entry_macro 032h
isr_entry_32 ENDP

isr_entry_33 PROC
        isr_entry_macro 033h
isr_entry_33 ENDP

isr_entry_34 PROC
        isr_entry_macro 034h
isr_entry_34 ENDP

isr_entry_35 PROC
        isr_entry_macro 035h
isr_entry_35 ENDP

isr_entry_36 PROC
        isr_entry_macro 036h
isr_entry_36 ENDP

isr_entry_37 PROC
        isr_entry_macro 037h
isr_entry_37 ENDP

isr_entry_38 PROC
        isr_entry_macro 038h
isr_entry_38 ENDP

isr_entry_39 PROC
        isr_entry_macro 039h
isr_entry_39 ENDP

isr_entry_3a PROC
        isr_entry_macro 03ah
isr_entry_3a ENDP

isr_entry_3b PROC
        isr_entry_macro 03bh
isr_entry_3b ENDP

isr_entry_3c PROC
        isr_entry_macro 03ch
isr_entry_3c ENDP

isr_entry_3d PROC
        isr_entry_macro 03dh
isr_entry_3d ENDP

isr_entry_3e PROC
        isr_entry_macro 03eh
isr_entry_3e ENDP

isr_entry_3f PROC
        isr_entry_macro 03fh
isr_entry_3f ENDP

isr_entry_40 PROC
        isr_entry_macro 040h
isr_entry_40 ENDP

isr_entry_41 PROC
        isr_entry_macro 041h
isr_entry_41 ENDP

isr_entry_42 PROC
        isr_entry_macro 042h
isr_entry_42 ENDP

isr_entry_43 PROC
        isr_entry_macro 043h
isr_entry_43 ENDP

isr_entry_44 PROC
        isr_entry_macro 044h
isr_entry_44 ENDP

isr_entry_45 PROC
        isr_entry_macro 045h
isr_entry_45 ENDP

isr_entry_46 PROC
        isr_entry_macro 046h
isr_entry_46 ENDP

isr_entry_47 PROC
        isr_entry_macro 047h
isr_entry_47 ENDP

isr_entry_48 PROC
        isr_entry_macro 048h
isr_entry_48 ENDP

isr_entry_49 PROC
        isr_entry_macro 049h
isr_entry_49 ENDP

isr_entry_4a PROC
        isr_entry_macro 04ah
isr_entry_4a ENDP

isr_entry_4b PROC
        isr_entry_macro 04bh
isr_entry_4b ENDP

isr_entry_4c PROC
        isr_entry_macro 04ch
isr_entry_4c ENDP

isr_entry_4d PROC
        isr_entry_macro 04dh
isr_entry_4d ENDP

isr_entry_4e PROC
        isr_entry_macro 04eh
isr_entry_4e ENDP

isr_entry_4f PROC
        isr_entry_macro 04fh
isr_entry_4f ENDP

isr_entry_50 PROC
        isr_entry_macro 050h
isr_entry_50 ENDP

isr_entry_51 PROC
        isr_entry_macro 051h
isr_entry_51 ENDP

isr_entry_52 PROC
        isr_entry_macro 052h
isr_entry_52 ENDP

isr_entry_53 PROC
        isr_entry_macro 053h
isr_entry_53 ENDP

isr_entry_54 PROC
        isr_entry_macro 054h
isr_entry_54 ENDP

isr_entry_55 PROC
        isr_entry_macro 055h
isr_entry_55 ENDP

isr_entry_56 PROC
        isr_entry_macro 056h
isr_entry_56 ENDP

isr_entry_57 PROC
        isr_entry_macro 057h
isr_entry_57 ENDP

isr_entry_58 PROC
        isr_entry_macro 058h
isr_entry_58 ENDP

isr_entry_59 PROC
        isr_entry_macro 059h
isr_entry_59 ENDP

isr_entry_5a PROC
        isr_entry_macro 05ah
isr_entry_5a ENDP

isr_entry_5b PROC
        isr_entry_macro 05bh
isr_entry_5b ENDP

isr_entry_5c PROC
        isr_entry_macro 05ch
isr_entry_5c ENDP

isr_entry_5d PROC
        isr_entry_macro 05dh
isr_entry_5d ENDP

isr_entry_5e PROC
        isr_entry_macro 05eh
isr_entry_5e ENDP

isr_entry_5f PROC
        isr_entry_macro 05fh
isr_entry_5f ENDP

isr_entry_60 PROC
        isr_entry_macro 060h
isr_entry_60 ENDP

isr_entry_61 PROC
        isr_entry_macro 061h
isr_entry_61 ENDP

isr_entry_62 PROC
        isr_entry_macro 062h
isr_entry_62 ENDP

isr_entry_63 PROC
        isr_entry_macro 063h
isr_entry_63 ENDP

isr_entry_64 PROC
        isr_entry_macro 064h
isr_entry_64 ENDP

isr_entry_65 PROC
        isr_entry_macro 065h
isr_entry_65 ENDP

isr_entry_66 PROC
        isr_entry_macro 066h
isr_entry_66 ENDP

isr_entry_67 PROC
        isr_entry_macro 067h
isr_entry_67 ENDP

isr_entry_68 PROC
        isr_entry_macro 068h
isr_entry_68 ENDP

isr_entry_69 PROC
        isr_entry_macro 069h
isr_entry_69 ENDP

isr_entry_6a PROC
        isr_entry_macro 06ah
isr_entry_6a ENDP

isr_entry_6b PROC
        isr_entry_macro 06bh
isr_entry_6b ENDP

isr_entry_6c PROC
        isr_entry_macro 06ch
isr_entry_6c ENDP

isr_entry_6d PROC
        isr_entry_macro 06dh
isr_entry_6d ENDP

isr_entry_6e PROC
        isr_entry_macro 06eh
isr_entry_6e ENDP

isr_entry_6f PROC
        isr_entry_macro 06fh
isr_entry_6f ENDP

isr_entry_70 PROC
        isr_entry_macro 070h
isr_entry_70 ENDP

isr_entry_71 PROC
        isr_entry_macro 071h
isr_entry_71 ENDP

isr_entry_72 PROC
        isr_entry_macro 072h
isr_entry_72 ENDP

isr_entry_73 PROC
        isr_entry_macro 073h
isr_entry_73 ENDP

isr_entry_74 PROC
        isr_entry_macro 074h
isr_entry_74 ENDP

isr_entry_75 PROC
        isr_entry_macro 075h
isr_entry_75 ENDP

isr_entry_76 PROC
        isr_entry_macro 076h
isr_entry_76 ENDP

isr_entry_77 PROC
        isr_entry_macro 077h
isr_entry_77 ENDP

isr_entry_78 PROC
        isr_entry_macro 078h
isr_entry_78 ENDP

isr_entry_79 PROC
        isr_entry_macro 079h
isr_entry_79 ENDP

isr_entry_7a PROC
        isr_entry_macro 07ah
isr_entry_7a ENDP

isr_entry_7b PROC
        isr_entry_macro 07bh
isr_entry_7b ENDP

isr_entry_7c PROC
        isr_entry_macro 07ch
isr_entry_7c ENDP

isr_entry_7d PROC
        isr_entry_macro 07dh
isr_entry_7d ENDP

isr_entry_7e PROC
        isr_entry_macro 07eh
isr_entry_7e ENDP

isr_entry_7f PROC
        isr_entry_macro 07fh
isr_entry_7f ENDP

isr_entry_80 PROC
        isr_entry_macro 080h
isr_entry_80 ENDP

isr_entry_81 PROC
        isr_entry_macro 081h
isr_entry_81 ENDP

isr_entry_82 PROC
        isr_entry_macro 082h
isr_entry_82 ENDP

isr_entry_83 PROC
        isr_entry_macro 083h
isr_entry_83 ENDP

isr_entry_84 PROC
        isr_entry_macro 084h
isr_entry_84 ENDP

isr_entry_85 PROC
        isr_entry_macro 085h
isr_entry_85 ENDP

isr_entry_86 PROC
        isr_entry_macro 086h
isr_entry_86 ENDP

isr_entry_87 PROC
        isr_entry_macro 087h
isr_entry_87 ENDP

isr_entry_88 PROC
        isr_entry_macro 088h
isr_entry_88 ENDP

isr_entry_89 PROC
        isr_entry_macro 089h
isr_entry_89 ENDP

isr_entry_8a PROC
        isr_entry_macro 08ah
isr_entry_8a ENDP

isr_entry_8b PROC
        isr_entry_macro 08bh
isr_entry_8b ENDP

isr_entry_8c PROC
        isr_entry_macro 08ch
isr_entry_8c ENDP

isr_entry_8d PROC
        isr_entry_macro 08dh
isr_entry_8d ENDP

isr_entry_8e PROC
        isr_entry_macro 08eh
isr_entry_8e ENDP

isr_entry_8f PROC
        isr_entry_macro 08fh
isr_entry_8f ENDP

isr_entry_90 PROC
        isr_entry_macro 090h
isr_entry_90 ENDP

isr_entry_91 PROC
        isr_entry_macro 091h
isr_entry_91 ENDP

isr_entry_92 PROC
        isr_entry_macro 092h
isr_entry_92 ENDP

isr_entry_93 PROC
        isr_entry_macro 093h
isr_entry_93 ENDP

isr_entry_94 PROC
        isr_entry_macro 094h
isr_entry_94 ENDP

isr_entry_95 PROC
        isr_entry_macro 095h
isr_entry_95 ENDP

isr_entry_96 PROC
        isr_entry_macro 096h
isr_entry_96 ENDP

isr_entry_97 PROC
        isr_entry_macro 097h
isr_entry_97 ENDP

isr_entry_98 PROC
        isr_entry_macro 098h
isr_entry_98 ENDP

isr_entry_99 PROC
        isr_entry_macro 099h
isr_entry_99 ENDP

isr_entry_9a PROC
        isr_entry_macro 09ah
isr_entry_9a ENDP

isr_entry_9b PROC
        isr_entry_macro 09bh
isr_entry_9b ENDP

isr_entry_9c PROC
        isr_entry_macro 09ch
isr_entry_9c ENDP

isr_entry_9d PROC
        isr_entry_macro 09dh
isr_entry_9d ENDP

isr_entry_9e PROC
        isr_entry_macro 09eh
isr_entry_9e ENDP

isr_entry_9f PROC
        isr_entry_macro 09fh
isr_entry_9f ENDP

isr_entry_a0 PROC
        isr_entry_macro 0a0h
isr_entry_a0 ENDP

isr_entry_a1 PROC
        isr_entry_macro 0a1h
isr_entry_a1 ENDP

isr_entry_a2 PROC
        isr_entry_macro 0a2h
isr_entry_a2 ENDP

isr_entry_a3 PROC
        isr_entry_macro 0a3h
isr_entry_a3 ENDP

isr_entry_a4 PROC
        isr_entry_macro 0a4h
isr_entry_a4 ENDP

isr_entry_a5 PROC
        isr_entry_macro 0a5h
isr_entry_a5 ENDP

isr_entry_a6 PROC
        isr_entry_macro 0a6h
isr_entry_a6 ENDP

isr_entry_a7 PROC
        isr_entry_macro 0a7h
isr_entry_a7 ENDP

isr_entry_a8 PROC
        isr_entry_macro 0a8h
isr_entry_a8 ENDP

isr_entry_a9 PROC
        isr_entry_macro 0a9h
isr_entry_a9 ENDP

isr_entry_aa PROC
        isr_entry_macro 0aah
isr_entry_aa ENDP

isr_entry_ab PROC
        isr_entry_macro 0abh
isr_entry_ab ENDP

isr_entry_ac PROC
        isr_entry_macro 0ach
isr_entry_ac ENDP

isr_entry_ad PROC
        isr_entry_macro 0adh
isr_entry_ad ENDP

isr_entry_ae PROC
        isr_entry_macro 0aeh
isr_entry_ae ENDP

isr_entry_af PROC
        isr_entry_macro 0afh
isr_entry_af ENDP

isr_entry_b0 PROC
        isr_entry_macro 0b0h
isr_entry_b0 ENDP

isr_entry_b1 PROC
        isr_entry_macro 0b1h
isr_entry_b1 ENDP

isr_entry_b2 PROC
        isr_entry_macro 0b2h
isr_entry_b2 ENDP

isr_entry_b3 PROC
        isr_entry_macro 0b3h
isr_entry_b3 ENDP

isr_entry_b4 PROC
        isr_entry_macro 0b4h
isr_entry_b4 ENDP

isr_entry_b5 PROC
        isr_entry_macro 0b5h
isr_entry_b5 ENDP

isr_entry_b6 PROC
        isr_entry_macro 0b6h
isr_entry_b6 ENDP

isr_entry_b7 PROC
        isr_entry_macro 0b7h
isr_entry_b7 ENDP

isr_entry_b8 PROC
        isr_entry_macro 0b8h
isr_entry_b8 ENDP

isr_entry_b9 PROC
        isr_entry_macro 0b9h
isr_entry_b9 ENDP

isr_entry_ba PROC
        isr_entry_macro 0bah
isr_entry_ba ENDP

isr_entry_bb PROC
        isr_entry_macro 0bbh
isr_entry_bb ENDP

isr_entry_bc PROC
        isr_entry_macro 0bch
isr_entry_bc ENDP

isr_entry_bd PROC
        isr_entry_macro 0bdh
isr_entry_bd ENDP

isr_entry_be PROC
        isr_entry_macro 0beh
isr_entry_be ENDP

isr_entry_bf PROC
        isr_entry_macro 0bfh
isr_entry_bf ENDP

isr_entry_c0 PROC
        isr_entry_macro 0c0h
isr_entry_c0 ENDP

isr_entry_c1 PROC
        isr_entry_macro 0c1h
isr_entry_c1 ENDP

isr_entry_c2 PROC
        isr_entry_macro 0c2h
isr_entry_c2 ENDP

isr_entry_c3 PROC
        isr_entry_macro 0c3h
isr_entry_c3 ENDP

isr_entry_c4 PROC
        isr_entry_macro 0c4h
isr_entry_c4 ENDP

isr_entry_c5 PROC
        isr_entry_macro 0c5h
isr_entry_c5 ENDP

isr_entry_c6 PROC
        isr_entry_macro 0c6h
isr_entry_c6 ENDP

isr_entry_c7 PROC
        isr_entry_macro 0c7h
isr_entry_c7 ENDP

isr_entry_c8 PROC
        isr_entry_macro 0c8h
isr_entry_c8 ENDP

isr_entry_c9 PROC
        isr_entry_macro 0c9h
isr_entry_c9 ENDP

isr_entry_ca PROC
        isr_entry_macro 0cah
isr_entry_ca ENDP

isr_entry_cb PROC
        isr_entry_macro 0cbh
isr_entry_cb ENDP

isr_entry_cc PROC
        isr_entry_macro 0cch
isr_entry_cc ENDP

isr_entry_cd PROC
        isr_entry_macro 0cdh
isr_entry_cd ENDP

isr_entry_ce PROC
        isr_entry_macro 0ceh
isr_entry_ce ENDP

isr_entry_cf PROC
        isr_entry_macro 0cfh
isr_entry_cf ENDP

isr_entry_d0 PROC
        isr_entry_macro 0d0h
isr_entry_d0 ENDP

isr_entry_d1 PROC
        isr_entry_macro 0d1h
isr_entry_d1 ENDP

isr_entry_d2 PROC
        isr_entry_macro 0d2h
isr_entry_d2 ENDP

isr_entry_d3 PROC
        isr_entry_macro 0d3h
isr_entry_d3 ENDP

isr_entry_d4 PROC
        isr_entry_macro 0d4h
isr_entry_d4 ENDP

isr_entry_d5 PROC
        isr_entry_macro 0d5h
isr_entry_d5 ENDP

isr_entry_d6 PROC
        isr_entry_macro 0d6h
isr_entry_d6 ENDP

isr_entry_d7 PROC
        isr_entry_macro 0d7h
isr_entry_d7 ENDP

isr_entry_d8 PROC
        isr_entry_macro 0d8h
isr_entry_d8 ENDP

isr_entry_d9 PROC
        isr_entry_macro 0d9h
isr_entry_d9 ENDP

isr_entry_da PROC
        isr_entry_macro 0dah
isr_entry_da ENDP

isr_entry_db PROC
        isr_entry_macro 0dbh
isr_entry_db ENDP

isr_entry_dc PROC
        isr_entry_macro 0dch
isr_entry_dc ENDP

isr_entry_dd PROC
        isr_entry_macro 0ddh
isr_entry_dd ENDP

isr_entry_de PROC
        isr_entry_macro 0deh
isr_entry_de ENDP

isr_entry_df PROC
        isr_entry_macro 0dfh
isr_entry_df ENDP

isr_entry_e0 PROC
        isr_entry_macro 0e0h
isr_entry_e0 ENDP

isr_entry_e1 PROC
        isr_entry_macro 0e1h
isr_entry_e1 ENDP

isr_entry_e2 PROC
        isr_entry_macro 0e2h
isr_entry_e2 ENDP

isr_entry_e3 PROC
        isr_entry_macro 0e3h
isr_entry_e3 ENDP

isr_entry_e4 PROC
        isr_entry_macro 0e4h
isr_entry_e4 ENDP

isr_entry_e5 PROC
        isr_entry_macro 0e5h
isr_entry_e5 ENDP

isr_entry_e6 PROC
        isr_entry_macro 0e6h
isr_entry_e6 ENDP

isr_entry_e7 PROC
        isr_entry_macro 0e7h
isr_entry_e7 ENDP

isr_entry_e8 PROC
        isr_entry_macro 0e8h
isr_entry_e8 ENDP

isr_entry_e9 PROC
        isr_entry_macro 0e9h
isr_entry_e9 ENDP

isr_entry_ea PROC
        isr_entry_macro 0eah
isr_entry_ea ENDP

isr_entry_eb PROC
        isr_entry_macro 0ebh
isr_entry_eb ENDP

isr_entry_ec PROC
        isr_entry_macro 0ech
isr_entry_ec ENDP

isr_entry_ed PROC
        isr_entry_macro 0edh
isr_entry_ed ENDP

isr_entry_ee PROC
        isr_entry_macro 0eeh
isr_entry_ee ENDP

isr_entry_ef PROC
        isr_entry_macro 0efh
isr_entry_ef ENDP

isr_entry_f0 PROC
        isr_entry_macro 0f0h
isr_entry_f0 ENDP

isr_entry_f1 PROC
        isr_entry_macro 0f1h
isr_entry_f1 ENDP

isr_entry_f2 PROC
        isr_entry_macro 0f2h
isr_entry_f2 ENDP

isr_entry_f3 PROC
        isr_entry_macro 0f3h
isr_entry_f3 ENDP

isr_entry_f4 PROC
        isr_entry_macro 0f4h
isr_entry_f4 ENDP

isr_entry_f5 PROC
        isr_entry_macro 0f5h
isr_entry_f5 ENDP

isr_entry_f6 PROC
        isr_entry_macro 0f6h
isr_entry_f6 ENDP

isr_entry_f7 PROC
        isr_entry_macro 0f7h
isr_entry_f7 ENDP

isr_entry_f8 PROC
        isr_entry_macro 0f8h
isr_entry_f8 ENDP

isr_entry_f9 PROC
        isr_entry_macro 0f9h
isr_entry_f9 ENDP

isr_entry_fa PROC
        isr_entry_macro 0fah
isr_entry_fa ENDP

isr_entry_fb PROC
        isr_entry_macro 0fbh
isr_entry_fb ENDP

isr_entry_fc PROC
        isr_entry_macro 0fch
isr_entry_fc ENDP

isr_entry_fd PROC
        isr_entry_macro 0fdh
isr_entry_fd ENDP

isr_entry_fe PROC
        isr_entry_macro 0feh
isr_entry_fe ENDP

isr_entry_ff PROC
        isr_entry_macro 0ffh
isr_entry_ff ENDP

END

