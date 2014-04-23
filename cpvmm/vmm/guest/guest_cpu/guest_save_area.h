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

#ifndef _GUEST_SAVE_AREA_H
#define _GUEST_SAVE_AREA_H

#include "vmm_defs.h"
#include "guest_cpu.h"
#include "guest_cpu_control.h"
#include <common_libc.h>
#include "vmcs_hierarchy.h"
#include "vmcs_actual.h"
#include "emulator_if.h"
#include "flat_page_tables.h"


// Guest CPU
#pragma PACK_ON

typedef struct _VMM_OTHER_MSRS {
    UINT64 pat;
    UINT64 padding; // not in use;
} VMM_OTHER_MSRS;

//JLM(FIX): duplicated
typedef struct _GUEST_CPU_SAVE_AREA {
    // the next 2 fields must be the first in this structure because they are
    // referenced in assembler
    VMM_GP_REGISTERS    gp;     // note: RSP, RIP and RFLAGS are not used - use VMCS
                                // RSP      entry is used for CR2
                                // RFLAGS   entry is used for CR3
                                // RIP      entry is used for CR8
    ALIGN16(VMM_XMM_REGISTERS,   xmm);    // restored AFTER FXRSTOR
    // not referenced in assembler
    VMM_DEBUG_REGISTERS debug;  // DR7 is not used - use VMCS
    // must be aligned on 16-byte boundary
    ALIGN16 (UINT8,       fxsave_area[512]);
    VMM_OTHER_MSRS temporary_cached_msrs;
} PACKED GUEST_CPU_SAVE_AREA;

#pragma PACK_OFF
#endif
