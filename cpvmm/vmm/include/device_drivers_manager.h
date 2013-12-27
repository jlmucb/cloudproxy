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

#ifndef DEVICE_DRIVERS_MANAGER_H
#define DEVICE_DRIVERS_MANAGER_H

#include <vmm_defs.h>
#include <guest.h>

void ddm_initialize(void);
void ddm_register_guest(GUEST_HANDLE guest_handle);
BOOLEAN ddm_notify_driver(UINT64 descriptor_handle, UINT32 component_id);

#endif
