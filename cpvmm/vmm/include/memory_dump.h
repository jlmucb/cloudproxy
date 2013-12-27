/****************************************************************************
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
****************************************************************************/

#ifndef _MEMORY_DUMP_H_
#define _MEMORY_DUMP_H_

#define OFFSET_EXCEPTION    0x02C0
#define OFFSET_GPR          0x0300
#define OFFSET_STACK        0x0400
#define OFFSET_VMCS         0x0800

// Number of stack trace entries copied to debug buffer
// The buffer has space to save up to 128 entries
#define STACK_TRACE_SIZE    48

// Space in buffer reserved for VMCS
#define VMCS_SIZE           2048

// version log
// 1.0 - 1st release
// 1.5 - add complete exception info, stack trace to buffer
//     - change to have data saved in binary format
// 1.7 - add support for 80 CPUs
#define VERSION           "01.7"

typedef struct _FILE_LINE_INFO {
	char	file_code[4];
	char	line_number[4];
} FILE_LINE_INFO;

typedef struct _DEBUG_INFO {
	char	        signature[8];
	char            flags[4];		// debug buffer format flag
	char	        cpu_id[4];		// cpu of the first deadloop/assert
	FILE_LINE_INFO	file_line[MAX_CPUS];	// support up to 80 CPUs
} DEBUG_INFO;

typedef struct _EXCEPT_INFO {
    UINT64          base_address;   // uVmm image base address
    ADDRESS         cr2;            // page fault address
    ISR_PARAMETERS_ON_STACK exception_stack;
} EXCEPT_INFO;

typedef struct _DEADLOOP_DUMP {
    DEBUG_INFO      header;
    EXCEPT_INFO     exception;
} DEADLOOP_DUMP;

#pragma PACK_ON

// only the existing vmcs fields are copied to guest buffer
typedef struct _VMCS_ENTRY {
	UINT16	index;			// index to g_field_data
	UINT64	value;			// vmcs value
} PACKED VMCS_ENTRY;

// the vmcs fields are arranged in the order of control, guest, host area
typedef struct _VMCS_GROUP {
	UINT16		count;		// number of entries copied to guest
	VMCS_ENTRY	entries;    // list of entries
} VMCS_GROUP;

// this is the layout of the 4K guest buffer
// the actual starting offsets are defined by the symbolic constants
typedef struct _MEMORY_DUMP {
    DEADLOOP_DUMP    deadloop_info;
    VMM_GP_REGISTERS gp_regs;
    UINT64           stack[STACK_TRACE_SIZE];
    VMCS_GROUP       vmcs_groups;   // list of groups
} MEMORY_DUMP;

#pragma PACK_OFF

#define DEADLOOP_SIGNATURE	"TMSLASST"


extern UINT64 g_debug_gpa;
extern UINT64 g_initial_vmcs[VMM_MAX_CPU_SUPPORTED];
extern UINT64 ept_compute_eptp(GUEST_HANDLE guest, UINT64 ept_root_table_hpa, UINT32 gaw);
extern void ept_get_default_ept(GUEST_HANDLE guest, UINT64 *ept_root_table_hpa, UINT32 *ept_gaw);
extern BOOLEAN vmcs_sw_shadow_disable[];

void vmm_deadloop_internal(UINT32 file_code, UINT32 line_num, GUEST_CPU_HANDLE gcpu);

#endif // _MEMORY_DUMP_H_
