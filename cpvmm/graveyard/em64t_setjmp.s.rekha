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

#  int setjmp(SETJMP_BUFFER *env)
#  Save context registers in buffer, pointed by RCX
#  RNB: This function has changed significantly, and is heavily based on the
#  longjmp implementation in the linux kernel.  Linux assumes that %rdi
#  contains the address to the start of the jump buffer, but keeping with the
#  spirit of the code in this file, the below function assumes that the address
#  of jump buffer is in %rcx.

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

#  void longjmp(SETJMP_BUFFER *env, int errcode);
#  Save context registers in buffer, pointed by RCX 
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
.globl	hw_exception_post_handler
hw_exception_post_handler:
        mov     %rdx, 1          # err code for longjmp
        mov     %rcx, %rsp        # address of SETJMP_BUFFER
        jmp     longjmp
