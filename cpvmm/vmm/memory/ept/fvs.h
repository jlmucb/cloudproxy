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

#ifndef _FVS_H
#define _FVS_H


#ifdef FAST_VIEW_SWITCH
#define MAX_EPTP_ENTRIES 512
#define FVS_ENABLE_FLAG  1
#define FVS_DISABLE_FLAG 0

#define FAST_VIEW_SWITCH_LEAF      0x0 // EPTP-switching (VM function 0)

typedef struct _FVS_DESCRIPTOR {
    HPA *eptp_list_paddress;
    HVA *eptp_list_vaddress;
    UINT32 padding;
    UINT32 num_of_cpus; // Each CPU has its own eptp list
                        // Use cpu id as array index of
                        // eptp_list_paddress[] and
                        // eptp_list_vaddress[]
    HVA dummy_eptp_address;  // Allocated in guest
                             // Used by #VE ISR
} FVS_DESCRIPTOR;

typedef struct _FVS_DESCRIPTOR * FVS_OBJECT;

BOOLEAN fvs_is_eptp_switching_supported(void);
void fvs_guest_vmfunc_enable(GUEST_CPU_HANDLE gcpu);
HPA *fvs_get_all_eptp_list_paddress(GUEST_CPU_HANDLE gcpu);
BOOLEAN fvs_add_entry_to_eptp_list(GUEST_HANDLE guest,
		            HPA ept_root_hpa, UINT32 gaw, UINT64 index);
BOOLEAN fvs_delete_entry_from_eptp_list(GUEST_HANDLE guest, UINT64 index);
UINT64 fvs_get_eptp_entry(GUEST_CPU_HANDLE gcpu, UINT64 index);
void fvs_vmfunc_vmcs_init(GUEST_CPU_HANDLE gcpu);
void fvs_enable_fvs(GUEST_CPU_HANDLE gcpu);
void fvs_disable_fvs(GUEST_CPU_HANDLE gcpu);
BOOLEAN fvs_is_fvs_enabled(GUEST_CPU_HANDLE gcpu);
void fvs_vmexit_handler(GUEST_CPU_HANDLE gcpu);
void fvs_save_resumed_eptp(GUEST_CPU_HANDLE gcpu);
#endif

#endif
