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

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#include "vmm_defs.h"
#include "x32_init64.h"
#include "ap_procs_init.h"
#include "vmm_startup.h"


typedef
void (_cdecl *LVMM_IMAGE_ENTRY_POINT) (
    UINT32 local_apic_id,
    void* any_data1,
    void* any_data2,
    void* any_data3
  );

typedef struct {
    void*           any_data1;
    void*           any_data2;
    void*           any_data3;
    UINT64          ep;
} APPLICATION_PARAMS_STRUCT;


static APPLICATION_PARAMS_STRUCT application_params;
static INIT64_STRUCT *gp_init64;



/*------------------Forward Declarations for Local Functions------------------*/
static void __cdecl start_application(UINT32 cpu_id, const APPLICATION_PARAMS_STRUCT *params);

void __cdecl startap_main
    (
    INIT32_STRUCT       *p_init32,
    INIT64_STRUCT       *p_init64,
    VMM_STARTUP_STRUCT  *p_startup,
    UINT32               entry_point
    )
    {
    UINT32 application_procesors;
    
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

    application_params.ep         = entry_point;
    application_params.any_data1  = (void*) p_startup;
    application_params.any_data2  = NULL;
    application_params.any_data3  = NULL;


    // first launch application on AP cores
    if (application_procesors > 0)
        {
        ap_procs_run((FUNC_CONTINUE_AP_BOOT)start_application, &application_params);
        }

    // and then launch application on BSP
    start_application(0, &application_params);

    }


static void __cdecl start_application
    (
    UINT32 cpu_id,
    const APPLICATION_PARAMS_STRUCT *params
    )
    {
    if (NULL == gp_init64)
        {
        ((LVMM_IMAGE_ENTRY_POINT)((UINT32)params->ep))
            (
            cpu_id,
            params->any_data1,
            params->any_data2,
            params->any_data3
            );
        }
    else
        {
        x32_init64_start
            (
            gp_init64,
            (UINT32)params->ep,
            (void *) cpu_id,
            params->any_data1,
            params->any_data2,
            params->any_data3
            );
        }
    }

