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

#ifndef _GUEST_INTERNAL_H_
#define _GUEST_INTERNAL_H_

#include "guest.h"
#include "list.h"
#include "vmexit_msr.h"
#include "vmx_ctrl_msrs.h"
#include "policy_manager.h"
#include "../memory/ept/fvs.h"

typedef struct _GUEST_DESCRIPTOR {
    GUEST_ID    id;
    UINT16      reserved_0;
    UINT32      magic_number;
    UINT32      physical_memory_size; // 0 for primary
    UINT16      flags;        // GUEST_FLAGS
    UINT16      cpu_count;
    UINT32      cpu_affinity; // 1 bit for each allocated host CPU
    UINT32      reserved_1;
    UINT64      physical_memory_base; // 0 for primary
    VMM_POLICY  guest_policy;
    // saved image descriptor - 0 for primary guest or guest that does not
    // support reloading
    const UINT8* saved_image;
    UINT32      saved_image_size;
    UINT32      image_load_GPA;
    GUEST_CPU_HANDLE*  cpus_array; // size of the array is cpu_count
    GPM_HANDLE  startup_gpm;
#ifdef FAST_VIEW_SWITCH
    FVS_OBJECT fvs_desc;
#endif
    LIST_ELEMENT        cpuid_filter_list[1];
    MSR_VMEXIT_CONTROL  msr_control[1];
    UINT32              padding2;
    BOOLEAN             is_initialization_finished;
    struct _GUEST_DESCRIPTOR *next_guest;
} GUEST_DESCRIPTOR;

#define GUEST_IS_PRIMARY_FLAG 1
#define GUEST_IS_NMI_OWNER_FLAG 2
#define GUEST_IS_ACPI_OWNER_FLAG 4
#define GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG 8
#define GUEST_BIOS_ACCESS_ENABLED_FLAG 16
#define GUEST_SAVED_IMAGE_IS_COMPRESSED_FLAG 32

#define GET_GUEST_IS_PRIMARY_FLAG(guest) ((guest)->flags&GUEST_IS_PRIMARY_FLAG)
#define GET_GUEST_IS_NMI_OWNER_FLAG(guest) ((guest)->flags&GUEST_IS_NMI_OWNER_FLAG)
#define GET_GUEST_IS_ACPI_OWNER_FLAG(guest) ((guest)->flags&GUEST_IS_ACPI_OWNER_FLAG)
#define GET_GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG(guest) ((guest)->flags&GUEST_IS_DEFAULT_DEVICE_OWNER_FLAG)
#define GET_GUEST_BIOS_ACCESS_ENABLED_FLAG(guest) ((guest)->flags&GUEST_BIOS_ACCESS_ENABLED_FLAG)
#define GET_GUEST_SAVED_IMAGE_IS_COMPRESSED_FLAG(guest) ((guest)->flags&GUEST_SAVED_IMAGE_IS_COMPRESSED_FLAG)
#endif // _GUEST_INTERNAL_H_

