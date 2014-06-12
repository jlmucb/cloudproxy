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
#include "bootstrap_print.h"
#include "vmm_defs.h"
#include "x32_init64.h"
#include "bootstrap_ap_procs_init.h"
#include "vmm_startup.h"

#define JLMDEBUG


int g_numstarted= 0;
int g_calls= 0;
extern int g_num_init64;


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
#ifdef JLMDEBUG
    bprint("startap_main %p %p\n", p_startup, entry_point);
#endif
    uint32_t application_processors;
    
    if(NULL!=p_init32) {
        // wakeup APs
        application_processors = ap_procs_startup(p_init32, p_startup);
    }
    else {
        application_processors = 0;
    }
#ifdef JLMDEBUG
    bprint("back from ap_procs_startup\n");
#endif

#ifdef UNIPROC
    application_processors = 0;
#endif
    gp_init64 = p_init64;

    if (BITMAP_GET(p_startup->flags, VMM_STARTUP_POST_OS_LAUNCH_MODE)==0) {
        // update the number of processors in VMM_STARTUP_STRUCT for pre os launch
        p_startup->number_of_processors_at_boot_time = application_processors+1;
    }

    application_params.ep = entry_point;
    application_params.any_data1 = (void*) p_startup;
    application_params.any_data2 = NULL;
    application_params.any_data3 = NULL;

#ifdef JLMDEBUG
    bprint("startap_main %d application processors\n", application_processors);
#endif
    // first launch application on AP cores
    if (application_processors>0) {
        g_calls++;
        ap_procs_run((FUNC_CONTINUE_AP_BOOT)start_application, &application_params);
    }
    // launch application on BSP
    // JLM: this is already done in bootstrap_entry
    // start_application(0, &application_params);
#ifdef JLMDEBUG
    bprint("returning from startap_main %d %d %d\n", g_numstarted, g_calls, g_num_init64);
    LOOP_FOREVER
#endif
}

extern void init64_on_aps(uint32_t stack_pointer, INIT64_STRUCT *p_init64_data, 
			  uint32_t start_address, void * arg1, void * arg2, 
			  void * arg3, void * arg4);


static void start_application(uint32_t cpu_id, 
                  const APPLICATION_PARAMS_STRUCT *params)
{
#ifdef JLMDEBUG1
    LOOP_FOREVER
    bprint("startap_application %d\n", cpu_id);
#endif
    // JLM: stack pointers were set elsewhere
    uint32_t  stack_pointer= evmm_stack_pointers_array[cpu_id];

    g_numstarted++;
    if (NULL == gp_init64) {
        ((LVMM_IMAGE_ENTRY_POINT)((uint32_t)params->ep))
            (cpu_id, params->any_data1, params->any_data2, params->any_data3);
    }
    else {
        init64_on_aps(stack_pointer, gp_init64, (uint32_t)params->ep, (void*) cpu_id,
            params->any_data1, params->any_data2, params->any_data3);
    }
}

