/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _GUEST_CPU_CONTROL_INTERNAL_H_
#define _GUEST_CPU_CONTROL_INTERNAL_H_

#include "vmm_defs.h"
#include "vmx_ctrl_msrs.h"
#include "lock.h"

typedef struct _GCPU_VMEXIT_CONTROL_FIELD_COUNTERS {
    UINT8   counters[64];
    UINT64  bit_field; // 1bit for each non-zero counter
    UINT64  minimal_1_settings; // one time calculated at boot; enforce 1 for each bit set
    UINT64  minimal_0_settings; // one time calculated at boot; enforce 0 or each bit cleared
} GCPU_VMEXIT_CONTROL_FIELD_COUNTERS;

typedef struct _GCPU_VMEXIT_CONTROLS {
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS cr0;
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS cr4;
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS pin_ctrls;
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS processor_ctrls;
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS processor_ctrls2;
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS exceptions_ctrls;
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS vm_entry_ctrls;
    GCPU_VMEXIT_CONTROL_FIELD_COUNTERS vm_exit_ctrls;
    VMM_LOCK                           lock;
} GCPU_VMEXIT_CONTROLS;

void guest_cpu_control_setup( GUEST_CPU_HANDLE gcpu );

typedef enum _GCPU_TEMP_EXCEPTIONS_SETUP {
    GCPU_TEMP_EXCEPTIONS_EXIT_ON_ALL,
    GCPU_TEMP_EXCEPTIONS_RESTORE_ALL,

    GCPU_TEMP_EXIT_ON_PF_AND_CR3,
    GCPU_TEMP_RESTORE_PF_AND_CR3,

    GCPU_TEMP_CR0_NO_EXIT_ON_WP,
    GCPU_TEMP_CR0_RESTORE_WP,

    GCPU_TEMP_EXIT_ON_INTR_UNBLOCK,
    GCPU_TEMP_NO_EXIT_ON_INTR_UNBLOCK,
} GCPU_TEMP_EXCEPTIONS_SETUP;

void gcpu_temp_exceptions_setup( GUEST_CPU_HANDLE gcpu,
                                 GCPU_TEMP_EXCEPTIONS_SETUP action );

BOOLEAN gcpu_cr3_virtualized(GUEST_CPU_HANDLE gcpu);

void gcpu_enforce_settings_on_hardware(GUEST_CPU_HANDLE gcpu,
                                       GCPU_TEMP_EXCEPTIONS_SETUP action);

#endif // _GUEST_CPU_CONTROL_INTERNAL_H_

