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

#ifndef _VMCALL_H_
#define _VMCALL_H_

#include "vmcall_api.h"
#include "vmm_objects.h"

typedef VMM_STATUS (*VMCALL_HANDLER)(GUEST_CPU_HANDLE gcpu, ADDRESS *arg1, ADDRESS *arg2, ADDRESS *arg3);

void vmcall_intialize(void);

void vmcall_guest_intialize(
    GUEST_ID    guest_id);

void vmcall_register(
    GUEST_ID        guest_id,
    VMCALL_ID       vmcall_id,
    VMCALL_HANDLER  handler,
    BOOLEAN         special_call
    );


#endif // _VMCALL_H_

