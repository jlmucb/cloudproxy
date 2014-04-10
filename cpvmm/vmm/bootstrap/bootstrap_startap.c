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


#include "bootstrap_types.h"
#include "vmm_defs.h"
#include "x32_init64.h"
#include "bootstrap_ap_procs_init.h"
#include "vmm_startup.h"


typedef void (*LVMM_IMAGE_ENTRY_POINT) (uint32_t local_apic_id, 
                   void* any_data1, void* any_data2, void* any_data3); 

typedef struct {
    void*           any_data1;
    void*           any_data2;
    void*           any_data3;
    UINT64          ep;
} APPLICATION_PARAMS_STRUCT;

static APPLICATION_PARAMS_STRUCT application_params;
static INIT64_STRUCT *gp_init64= NULL;

static void start_application(uint32_t cpu_id, const APPLICATION_PARAMS_STRUCT *params);
extern uint32_t evmm_stack_pointers_array[];  // stack pointers


void startap_main(INIT32_STRUCT *p_init32, INIT64_STRUCT *p_init64,
                   VMM_STARTUP_STRUCT *p_startup, uint32_t entry_point)
{
    uint32_t application_procesors;
    
    if (NULL != p_init32) {
        //wakeup APs
        application_procesors = ap_procs_startup(p_init32, p_startup);
    }
    else {
        application_procesors = 0;
    }
#ifdef UNIPROC
    application_procesors = 0;
#endif
    gp_init64 = p_init64;

    if (BITMAP_GET(p_startup->flags, VMM_STARTUP_POST_OS_LAUNCH_MODE) == 0) {
        // update the number of processors in VMM_STARTUP_STRUCT for pre os launch
        p_startup->number_of_processors_at_boot_time = application_procesors + 1;
    }

    application_params.ep = entry_point;
    application_params.any_data1 = (void*) p_startup;
    application_params.any_data2 = NULL;
    application_params.any_data3 = NULL;

    // first launch application on AP cores
    if (application_procesors > 0) {
        ap_procs_run((FUNC_CONTINUE_AP_BOOT)start_application, &application_params);
    }
    // launch application on BSP
    // JLM: this is already done in bootstrap_entry
    // start_application(0, &application_params);
}


static void start_application(uint32_t cpu_id, const APPLICATION_PARAMS_STRUCT *params)
{
    // FIX(JLM): stack pointers seem to be set elsewhere
    uint32_t  stack_pointer= evmm_stack_pointers_array[cpu_id];

    if (NULL == gp_init64) {
        ((LVMM_IMAGE_ENTRY_POINT)((uint32_t)params->ep))
            (cpu_id, params->any_data1, params->any_data2, params->any_data3);
    }
    else {
        init64_on_aps(stack_pointer, gp_init64, (uint32_t)params->ep, (void *) cpu_id,
            params->any_data1, params->any_data2, params->any_data3);
    }
}

