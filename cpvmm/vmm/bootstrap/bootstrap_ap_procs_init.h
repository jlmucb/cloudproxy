/*
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
 */

#ifndef _AP_PROCS_INIT_H_
#define _AP_PROCS_INIT_H_

#include "bootstrap_types.h"
#include "vmm_defs.h"
#include "vmm_startup.h"


// typedefs
typedef void *  (*FUNC_4K_PAGE_ALLOC)( uint32_t page_count );


// this is a callback that should be used to continue AP bootstrap
// this function MUST not return or return in the protected 32 mode.
// If it returns APs enter wait state once more.
// parameters:
//   Local Apic ID of the current processor (processor ID)
//   Any data to be passed to the function
typedef void  (*FUNC_CONTINUE_AP_BOOT)(uint32_t local_apic_id,
                                       void*  any_data);


// Start all APs in pre-os launch and only active APs in post-os launch and bring them to protected non-paged mode.
// Processors are left in the state were they wait for continuation signal
// Input:
//    p_init32_data - contains pointer to the free low memory page to be used
//                    for bootstap. After the return this memory is free
//    p_startup - contains local apic ids of active cpus to be used in post-os launch
//  Return:
//    number of processors that were init (not including BSP)
//    or -1 on errors
struct _INIT32_STRUCT           *p_init32_data; 
struct VMM_STARTUP_STRUCT       *p_startup;
uint32_t ap_procs_startup(struct _INIT32_STRUCT *p_init32_data, 
                        VMM_STARTUP_STRUCT  *p_startup);


// Run user specified function on all APs.
// If user function returns it should return in the protected 32bit mode. In this
// case APs enter the wait state once more.
// Input:
//  continue_ap_boot_func       - user given function to continue AP boot
//  any_data                    - data to be passed to the function
//  Return:
//    void or never returns - depending on continue_ap_boot_func
void ap_procs_run(FUNC_CONTINUE_AP_BOOT continue_ap_boot_func,
                  void* any_data);
#endif // _AP_PROCS_INIT_H_

