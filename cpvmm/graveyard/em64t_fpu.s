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


#
#
# Calling conventions
#
# Floating : First 4 parameters – XMM0 through XMM3. Others passed on stack.
#
# Integer  : First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
#
# Aggregates (8, 16, 32, or 64 bits) and __m64:
#        First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
#
# Aggregates (other):
#        By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
#
# __m128   : By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
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

.set	ARG1_U8, %cl
.set	ARG1_U16, %cx
.set	ARG1_U32, %ecx
.set	ARG1_U64, %rcx
.set	ARG2_U8 , %dl
.set	ARG2_U16, %dx
.set	ARG2_U32, %edx
.set	ARG2_U64, %rdx
#RNB: GAS wants r8d instead of r8l to access low 32-bits of r8-r15 registers.
.set	ARG3_U32, %r8d
.set	ARG3_U64, %r8

#
# Register usage
#
# Caller-saved and scratch:
#        RAX, RCX, RDX, R8, R9, R10, R11
#
# Callee-saved
#        RBX, RBP, RDI, RSI, R12, R13, R14, and R15
#
#
#
#  void __stdcall
#  hw_fnstsw (
#          UINT16 *
#  );
#
#  Read FPU status word
#
.globl	hw_fnstsw 
hw_fnstsw:
        fnstsw word ptr [%rcx]
        ret

#
#  void __stdcall
#  hw_fnstcw (
#          UINT16 *
#  );
#
#  Read FPU control word
#
.globl	hw_fnstcw 
hw_fnstcw:
        fnstcw word ptr [%rcx]
        ret

#
#  void __stdcall
#  hw_fninit (void);
#
#  Init FP Unit
#
.globl	hw_fninit 
hw_fninit:
        fninit
        ret


