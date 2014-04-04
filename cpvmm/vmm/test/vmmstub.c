/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bootstrap_types.h"
#include "vmm_defs.h"
#include "vmm_startup.h"


typedef struct VMM_INPUT_PARAMS_S {
    UINT64 local_apic_id;
    UINT64 startup_struct;
    UINT64 application_params_struct; // change name
} VMM_INPUT_PARAMS;


void vmm_main(UINT32 local_apic_id, UINT64 startup_struct_u, 
              UINT64 application_params_struct_u, UINT64 reserved UNUSED)
{
    bootstrap_partial_reset();
    bprint("***********************\n");
    bprint("vmm_main in 64 bit mode\n");
    bprint("local_apic_id %d, startup_struct_u %016lx\n", local_apic_id, startup_struct_u);
    bprint("application_params_struct_u %016lx, reserved  %016lx\n", 
            application_params_struct_u, reserved);
    LOOP_FOREVER
}

