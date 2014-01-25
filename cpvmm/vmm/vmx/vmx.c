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
#include "hw_utils.h"
#include "hw_vmx_utils.h"
//#include "vmx.h"

//RNB: we shoudl have a ifdef VT supported and accordingly use 
//.byte version or the instructions for portability

int vmx_on(UINT64 *address) {
/*
	asm volatile ("push %%rbx \n\t"
		"movq %0, %%rbx \n\t"
		".byte 0xf3, 0x0f, 0xc7, 0x33 \n\t"
		"pop %%rbx \n\t"
		: : "b"(&address), "m"(address)
		: "memory", "rbx");
*/
	asm volatile("vmxon %0"
		::"m" (address)
		:"cc", "memory"
	);

//RNB: Need to figure out where the return value/state after vmxon
//is saved

	return 0;
}

void vmx_off() {
/*
	asm volatile(".byte 0x0f, 0x01, 0xc4\n\t"
	);
*/
	asm volatile("vmxoff"
		::
		:"cc"
	);
	return;
}

int vmx_vmclear(UINT64 *address) {
/*
	asm volatile("mov %0, %%rbx \n\t"
		".byte 0x66, 0x0f, 0xc7, 0x33 \n\t"
		:: "rbx" (&address), "m"(address)
		:"rbx", "memory"
	);
*/
	asm volatile("vmclear %0"
		::"m"(*address)
		:"cc", "memory"
	);
	return 0;
}

int hw_vmx_flush_current_vmcs(UINT64 *address) {
	return vmx_vmclear(address);
}
int vmx_vmlaunch() {
//	asm volatile(".byte 0x0f, 0x01, 0xc2");
	asm volatile("vmlaunch"
		::
		:"cc", "memory"
	);
	return 0;
}
int vmx_vmresume() {
//	asm volatile(".byte 0x0f, 0x01, 0xc3");
	asm volatile("vmresume"
		::
		:"cc", "memory"
	);
	return 0;
}

int vmx_vmptrld(UINT64 *address) {
/*
	asm volatile("mov %0, %%rbx \n\t"
		".byte 0x0f, 0xc7, 0x33"
		:: "rbx" (&address), "m"(address)
		:"rbx", "memory"
	);
*/
	asm volatile("vmptrld %0"
		::"m" (address)
		:"cc", "memory"
	);
	return 0;
}

void vmx_vmptrst(UINT64 *address) {
	/*
	asm volatile("mov %0, %%ebx \n\t"
		".byte 0x0f, 0xc7, 0x3b"
		:: "rbx" (&address), "m"(address)
		:"rbx", "memory"
	);
	*/
	asm volatile("vmptrst %0"
		::"m" (address)
		:"cc", "memory"
	);
	return;
}

int vmx_vmread(UINT64 index, UINT64 *value) {
//	asm volatile(".byte 0x0f, 0x78, 0xc2");
	asm volatile("vmread %1, %0"
		:"=rm"(value)
		:"r"(index)
		:"cc"
	);
	return 0;
}

int vmx_vmwrite(UINT64 index, UINT64 *value) {
//	asm volatile(".byte 0x0f, 0x79, 0xc2");
	asm volatile("vmwrite %1, %0"
		:
		:"r"(index), "rm"(value)
		:"cc", "memory"
	);
	return 0;
}

HW_VMX_RET_VALUE hw_vmx_write_current_vmcs(UINT64 field_id, UINT64 *value ) {
	return vmx_vmwrite(field_id, value);
}

HW_VMX_RET_VALUE hw_vmx_read_current_vmcs(UINT64 field_id, UINT64 *value ) {
	return vmx_vmread(field_id, value);
}

