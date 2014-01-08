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

#ifndef _VMM_ADDONS_H_
#define _VMM_ADDONS_H_

#include "vmm_defs.h"
#include "vmm_startup.h"

//*****************************************************************************
//*
//* List of all known addons
//*
//*****************************************************************************

extern void init_vtlb_addon(UINT32 num_of_cpus);
extern void init_ept_addon(UINT32 num_of_cpus);
void init_guest_create_addon(void);
extern void gdb_stub_addon_initialize(UINT32  max_num_of_guest_cpus, const VMM_DEBUG_PORT_PARAMS  *p_params);



#endif // _VMM_ADDONS_H_

