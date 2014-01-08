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

#ifndef _VMM_EVENTS_DATA_H_
#define _VMM_EVENTS_DATA_H_

#include "vmm_defs.h"
#include "event_mgr.h"

//*****************************************************************************
//*
//* Define specific per-event data for event manager
//*
//*****************************************************************************

// EVENT_EMULATOR_BEFORE_MEM_WRITE
// EVENT_EMULATOR_AFTER_MEM_WRITE
typedef struct _EVENT_EMULATOR_MEM_WRITE_DATA {
    GPA     gpa;
    UINT32  size;
    UINT8   padding[4];
} EVENT_EMULATOR_MEM_WRITE_DATA;

// EVENT_GCPU_BEFORE_GUEST_CR0_WRITE
// EVENT_GCPU_BEFORE_GUEST_CR3_WRITE
// EVENT_GCPU_BEFORE_GUEST_CR4_WRITE
// event is rased before any changes
typedef struct _EVENT_GCPU_GUEST_CR_WRITE_DATA {
    UINT64  new_guest_visible_value;
} EVENT_GCPU_GUEST_CR_WRITE_DATA;

// EVENT_GCPU_INVALIDATE_PAGE
typedef struct _EVENT_GCPU_INVALIDATE_PAGE_DATA {
    UINT64  invlpg_addr;
} EVENT_GCPU_INVALIDATE_PAGE_DATA;

// EVENT_GCPU_BEFORE_EFER_MSR_WRITE
// EVENT_GCPU_BEFORE_PAT_MSR_WRITE
// EVENT_GCPU_BEFORE_MTRR_MSR_WRITE
// event is rased before any changes
typedef struct _EVENT_GCPU_GUEST_MSR_WRITE_DATA {
    UINT64  new_guest_visible_value;
    MSR_ID  msr_index;
    UINT8   padding[4];
} EVENT_GCPU_GUEST_MSR_WRITE_DATA;

typedef struct _EVENT_GCPU_PAT_MSR_UPDATE_DATA {
    UINT64  guest_pat;
    UINT64  actual_pat;
} EVENT_GCPU_PAT_MSR_UPDATE_DATA;

// EVENT_GCPU_PAGE_FAULT
// NOTE: this callback must set processed to TRUE!
typedef struct _EVENT_GCPU_PAGE_FAULT_DATA {
    UINT64 pf_address;
    UINT64 pf_error_code;
    BOOLEAN pf_processed;
    UINT8   pad[4];
} EVENT_GCPU_PAGE_FAULT_DATA;

// EVENT_GCPU_BEFORE_ACTIVITY_STATE_CHANGE
// event is rased before the change
typedef struct _EVENT_GCPU_ACTIVITY_STATE_CHANGE_DATA {
    IA32_VMX_VMCS_GUEST_SLEEP_STATE  prev_state;
    IA32_VMX_VMCS_GUEST_SLEEP_STATE  new_state;
} EVENT_GCPU_ACTIVITY_STATE_CHANGE_DATA;

typedef struct _EVENT_GCPU_MTF_DATA {
    IA32_VMX_EXIT_QUALIFICATION qualification;
    UINT64 guest_linear_address;
    BOOLEAN processed;
    UINT8   pad[4];
} EVENT_GCPU_MTF_DATA;

typedef struct _EVENT_GCPU_EPT_VIOLATION_DATA {
    IA32_VMX_EXIT_QUALIFICATION qualification;
    UINT64 guest_linear_address;
    UINT64 guest_physical_address;
    BOOLEAN processed;
    UINT8   pad[4];
} EVENT_GCPU_EPT_VIOLATION_DATA;

typedef struct _EVENT_GCPU_EPT_MISCONFIGURATION_DATA {
    UINT64 guest_physical_address;
    BOOLEAN processed;
    UINT8   pad[4];
} EVENT_GCPU_EPT_MISCONFIGURATION_DATA;

typedef enum _VMM_MEM_OP
{
	VMM_MEM_OP_RECREATE = 1,
	VMM_MEM_OP_SWITCH,
	VMM_MEM_OP_UPDATE,
	VMM_MEM_OP_REMOVE,
} VMM_MEM_OP;

typedef struct _EVENT_GPM_MODIFICATION_DATA
{
    GUEST_ID guest_id;
    UINT16 padding;
    VMM_MEM_OP operation;
} EVENT_GPM_MODIFICATION_DATA;

typedef struct _EVENT_GUEST_MEMORY_WRITE
{
    GPA       gpa;
    BOOLEAN   vtlb_succeed;
    GUEST_ID  guest_id;
    UINT8     pad[2];
} EVENT_GUEST_MEMORY_WRITE;

typedef struct _EVENT_GUEST_CREATE_DATA {
    GUEST_ID guest_id;
} EVENT_GUEST_CREATE_DATA;

typedef struct _EVENT_GUEST_DESTROY_DATA {
    GUEST_ID guest_id;
} EVENT_GUEST_DESTROY_DATA;

#endif // _VMM_EVENTS_DATA_H_

