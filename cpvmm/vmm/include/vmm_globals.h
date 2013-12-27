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

#ifndef _VMM_GLOBALS_H_
#define _VMM_GLOBALS_H_

#include "vmm_defs.h"

//******************************************************************************
//
// Set of global variables
//
//******************************************************************************

// VMM running state
typedef enum _VMM_STATE {
    VMM_STATE_UNINITIALIZED = 0,
    VMM_STATE_BOOT,         // initial boot state - only BSP is active and is in VMM
    VMM_STATE_WAIT_FOR_APs, // BSP waits for APs to finish initialization
    VMM_STATE_RUN           // All CPUs finished init and are in normal running state or
                            // in Wait-For-SIPI state on behalf of guest
} VMM_STATE;

extern VMM_STATE g_vmm_state;

INLINE
VMM_STATE vmm_get_state( void )
{
    return g_vmm_state;
}

INLINE
void vmm_set_state( VMM_STATE new_state )
{
    g_vmm_state = new_state;
}

void vmm_version_print( void );

extern CPU_ID g_num_of_cpus;

#endif // _VMM_GLOBALS_H_
