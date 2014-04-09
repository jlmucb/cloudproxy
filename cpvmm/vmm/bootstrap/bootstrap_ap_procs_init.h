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

struct _INIT32_STRUCT           *p_init32_data; 
struct VMM_STARTUP_STRUCT       *p_startup;
uint32_t ap_procs_startup(struct _INIT32_STRUCT *p_init32_data, 
                        VMM_STARTUP_STRUCT  *p_startup);


// Run user specified function on all APs.
// If user function returns it should return in the protected 32bit mode.
//  continue_ap_boot_func - user given function to continue AP boot
//  any_data - data to be passed to the function
void ap_procs_run(FUNC_CONTINUE_AP_BOOT continue_ap_boot_func,
                  void* any_data);
#endif // _AP_PROCS_INIT_H_

