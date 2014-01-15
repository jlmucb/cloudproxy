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
# Register usage
#
# Caller-saved and scratch:
#        RAX, RCX, RDX, R8, R9, R10, R11
# Callee-saved
#        RBX, RBP, RDI, RSI, R12, R13, R14, and R15

#UINT64 typedef qword
#.long SETJMP_BUFFER_rbx
#.long SETJMP_BUFFER_rsi
#.long SETJMP_BUFFER_rdi
#.long SETJMP_BUFFER_rbp
#.long SETJMP_BUFFER_r12
#.long SETJMP_BUFFER_r13
#.long SETJMP_BUFFER_r14
#.long SETJMP_BUFFER_r15
#.long SETJMP_BUFFER_rsp
#.long SETJMP_BUFFER_rip
#
#
#  int setjmp(SETJMP_BUFFER *env)
#
#  Save context registers in buffer, pointed by RCX
#
#  RNB: This function has changed significantly, and is heavily based on the
#  longjmp implementation in the linux kernel.  Linux assumes that %rdi
#  contains the address to the start of the jump buffer, but keeping with the
#  spirit of the code in this file, the below function assumes that the address
#  of jump buffer is in %rcx.
#
.text
.align 4
.globl setjmp
.type setjmp, @function

setjmp:
	pop  %rsi			# Return address, and adjust the stack
#RNB: linux kernel uses xorl, but gcc doesn't like it, so I changed to xor
	xor %eax,%eax			# Return value
	movq %rbx,[%rcx]
	movq %rsp,8[%rcx]		# Post-return %rsp!
	push %rsi			# Make the call/return stack happy
	movq %rbp,16[%rcx]
	movq %r12,24[%rcx]
	movq %r13,32[%rcx]
	movq %r14,40[%rcx]
	movq %r15,48[%rcx]
	movq %rsi,56[%rcx]		# Return address
	ret

	.size setjmp,.-setjmp

#
#  void longjmp(SETJMP_BUFFER *env, int errcode);
#
#  Save context registers in buffer, pointed by RCX 
#
#  RNB: This function has changed significantly, and is heavily based on the
#  longjmp implementation in the linux kernel.  Linux assumes that %rdi
#  contains the address to the start of the jump buffer, but keeping with the
#  spirit of the code in this file, the below function assumes that the address
#  of jump buffer is in %rcx.
#
.text
.align 4
.globl longjmp
.type longjmp, @function
longjmp:
#RNB: linux kernel uses movl, but gcc doesn't like it, so I changed to mov
	mov  %esi,%eax			# Return value (int)
	movq [%rcx],%rbx
	movq 8[%rcx],%rsp
	movq 16[%rcx],%rbp
	movq 24[%rcx],%r12
	movq 32[%rcx],%r13
	movq 40[%rcx],%r14
	movq 48[%rcx],%r15
#RNB: I have doubt about the jmp  instruction.  linux kernel has jmp *56(%rcx)
	jmp 56[%rcx]

	.size longjmp,.-longjmp
#
#.globl	longjmp 
#longjmp:
#        mov     rax, rdx        # Return value (int)
#        mov     rbx, (SETJMP_BUFFER ptr [rcx])._rbx
#        mov     rsi, (SETJMP_BUFFER ptr [rcx])._rsi
#        mov     rdi, (SETJMP_BUFFER ptr [rcx])._rdi
#        mov     rbp, (SETJMP_BUFFER ptr [rcx])._rbp
#        mov     r12, (SETJMP_BUFFER ptr [rcx])._r12
#        mov     r13, (SETJMP_BUFFER ptr [rcx])._r13
#        mov     r14, (SETJMP_BUFFER ptr [rcx])._r14
#        mov     rsp, (SETJMP_BUFFER ptr [rcx])._rsp
#        jmp     (SETJMP_BUFFER ptr [rcx])._rip

.globl	hw_exception_post_handler
hw_exception_post_handler:
        mov     %rdx, 1          # err code for longjmp
        mov     %rcx, %rsp        # address of SETJMP_BUFFER
        jmp     longjmp
