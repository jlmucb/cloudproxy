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

#ifndef _STARTAP_H_
#define _STARTAP_H_

#include "x32_init64.h"
#include "ap_procs_init.h"
#include "vmm_startup.h"

typedef void (CDECL *STARTAP_IMAGE_ENTRY_POINT) (
    INIT32_STRUCT       *p_init32,
    INIT64_STRUCT       *p_init64,
    VMM_STARTUP_STRUCT  *p_startup,
    UINT32               entry_point
    );

#endif // _STARTAP_H_

