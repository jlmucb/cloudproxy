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

#ifndef _VMM_CALLBACK_H
#define _VMM_CALLBACK_H

#include "vmm_defs.h"
#include "vmm_objects.h"
#include "vmx_vmcs.h"
#include "vmm_arch_defs.h"

#ifndef INVALID_GUEST_ID
#define INVALID_GUEST_ID    ((GUEST_ID) -1)
#endif

typedef void* VMM_IDENTIFICATION_DATA;

typedef struct _GUEST_VCPU {
    GUEST_ID guest_id;
    CPU_ID   guest_cpu_id; // guest cpu id and not host
} GUEST_VCPU;

typedef struct _GUEST_DATA {
    BOOLEAN primary_guest;
    GUEST_ID guest_id;
    UINT16 padding;
}GUEST_DATA;

typedef struct _REPORT_INITIALIZATION_DATA {
    UINT16 num_of_cpus;
    UINT16 padding[3];
    GUEST_DATA guest_data[VMM_MAX_GUESTS_SUPPORTED];
}REPORT_INITIALIZATION_DATA;

typedef struct _REPORT_EPT_VIOLATION_DATA {
	UINT64 qualification;
    UINT64 guest_linear_address;
    UINT64 guest_physical_address;
}REPORT_EPT_VIOLATION_DATA;

typedef struct _REPORT_CR_ACCESS_DATA {
    UINT64 qualification;
}REPORT_CR_DR_LOAD_ACCESS_DATA;

typedef struct _REPORT_DTR_ACCESS_DATA {
    UINT64 qualification;
    UINT32 instruction_info;
    UINT32 padding;
}REPORT_DTR_ACCESS_DATA;

typedef struct _REPORT_MSR_WRITE_ACCESS_DATA {
    UINT32 msr_id;
}REPORT_MSR_WRITE_ACCESS_DATA;

#ifdef API_NOT_USED
typedef struct _REPORT_MSR_READ_ACCESS_DATA {
    UINT32 msr_id;
}REPORT_MSR_READ_ACCESS_DATA;
#endif

typedef struct _REPORT_SET_ACTIVE_EPTP_DATA {
    UINT64 eptp_list_index;
    BOOLEAN update_hw;
    UINT32 padding;
}REPORT_SET_ACTIVE_EPTP_DATA;

typedef struct _REPORT_INITIAL_VMEXIT_CHECK_DATA {
    UINT64 current_cpu_rip;
    UINT32 vmexit_reason;
    UINT32 padding;
}REPORT_INITIAL_VMEXIT_CHECK_DATA;

typedef struct _UVMM_LOG_EVENT_DATA {
    UINT32 vector;
    UINT32 padding;
}REPORT_VMM_LOG_EVENT_DATA;

typedef struct _REPORT_VMM_TEARDOWN_DATA {
    UINT64 nonce;
}REPORT_VMM_TEARDOWN_DATA;

typedef struct _REPORT_FAST_VIEW_SWITCH_DATA {
    UINT64 reg;
}REPORT_FAST_VIEW_SWITCH_DATA;

/* UVMM REPORTED EVENTS
 * This enumeration specify the supported events reported by uVMM to the
 * supporting modules.
 */
#ifndef UVMM_EVENT
typedef enum {
    // Initialization before the APs have started
    UVMM_EVENT_INITIALIZATION_BEFORE_APS_STARTED,

    // Initialization after the APs have launched the guest
    UVMM_EVENT_INITIALIZATION_AFTER_APS_STARTED,

    // EPT Violation
    UVMM_EVENT_EPT_VIOLATION,

    // MTF VMExit
    UVMM_EVENT_MTF_VMEXIT,

    // CR Access VMExit
    UVMM_EVENT_CR_ACCESS,

    // DR Load Access VMExit
    UVMM_EVENT_DR_LOAD_ACCESS,

    // LDTR Load Access VMExit
    UVMM_EVENT_LDTR_LOAD_ACCESS,

    // GDTR Load Access VMExit
    UVMM_EVENT_GDTR_IDTR_ACCESS,

    // MSR Read Access VMExit
    UVMM_EVENT_MSR_READ_ACCESS,

    // MSR Write Access VMExit
    UVMM_EVENT_MSR_WRITE_ACCESS,

    // Set Active View (for Fast View Switch)
    UVMM_EVENT_SET_ACTIVE_EPTP,

    // Check for MTF at the start of VMExit
    UVMM_EVENT_INITIAL_VMEXIT_CHECK,

    // Check for single stepping
    UVMM_EVENT_SINGLE_STEPPING_CHECK,

    // VMM Teardown VMExit
    UVMM_EVENT_VMM_TEARDOWN,

    // Fast View Switch Event
    UVMM_EVENT_INVALID_FAST_VIEW_SWITCH,

    // VMX Timer VMExit
    UVMM_EVENT_VMX_PREEMPTION_TIMER,

    // Halt Instruction VMExit
    UVMM_EVENT_HALT_INSTRUCTION,

    // IO Instruction VMExit
    UVMM_EVENT_IO_INSTRUCTION,

    // NMI event handling
    UVMM_EVENT_NMI,

    // Event log
    UVMM_EVENT_LOG,

    // Update active view
    UVMM_EVENT_UPDATE_ACTIVE_VIEW,

    // VMM_ASSERT handling
    UVMM_EVENT_VMM_ASSERT,

    UVMM_EVENT_MAX_COUNT
} UVMM_EVENT;
#endif

extern BOOLEAN report_uvmm_event(UVMM_EVENT event, VMM_IDENTIFICATION_DATA gcpu, const GUEST_VCPU *vcpu_id, void *event_specific_data);

#endif //_VMM_CALLBACK_H
