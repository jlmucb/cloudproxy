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

#include ept.inc

.intel_syntax
.text


# VS2010 supports the INVEPT and INVVPID instructions
# These 2 macros are kept for compatibility with VS2005
# The Intel Software Development Emulator XED was used to decode the hardcoded opcode
# TODO: Replace macro with this instruction in VS2010
#   invept ecx, xmmword ptr [eax]
#_INVEPT macro
#.byte	0x66, 0x48, 0x0f, 0x38, 0x80, 0x08
#endm
.macro _INVEPT 
.byte	0x66, 0x48, 0x0f, 0x38, 0x80, 0x08
.endm

# TODO: Replace macro with this instruction in VS2010
#   invvpid ecx, xmmword ptr [eax]
.macro _INVVPID macro
.byte	0x66, 0x48, 0x0f, 0x38, 0x81, 0x08
.endm

#
#  VOID
#  vmm_asm_invept (
#    INVEPT_ARG   *arg,		;rcx
#    UINT32       modifier	;rdx
#    UINT64       *rflags	;r8
#    )
#

.globl	vmm_asm_invept
vmm_asm_invept:
	mov %rax, %rcx
	mov %rcx, %rdx
	_INVEPT
	pushfq
	pop [%r8]
	ret


#
#  VOID
#  vmm_asm_invvpid (
#    INVEPT_ARG   *arg,		;rcx
#    UINT32       modifier	;rdx
#    UINT64       *rflags	;r8
#    )
#
.globl  vmm_asm_invvpid
vmm_asm_invvpid:
	mov %rax, %rcx
	mov %rcx, %rdx
	_INVVPID
	pushfq
	pop [r8]
	ret


