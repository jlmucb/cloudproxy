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

#ifndef _VMCS_HIERARCHY_H_
#define _VMCS_HIERARCHY_H_

#include "list.h"
#include "vmcs_api.h"

typedef struct _VMCS_HIERARCHY {
    VMCS_OBJECT     *vmcs[VMCS_LEVELS];
    LIST_ELEMENT    vmcs_1_list[1];  // contains list of VMCS_1_DESCRIPTOR. empty means no layering
} VMCS_HIERARCHY;


INLINE BOOLEAN vmcs_hierarchy_is_layered(VMCS_HIERARCHY *obj)
{
    return obj->vmcs[VMCS_LEVEL_0] != obj->vmcs[VMCS_MERGED];
}


VMM_STATUS  vmcs_hierarchy_create(VMCS_HIERARCHY *obj, GUEST_CPU_HANDLE gcpu);
VMM_STATUS  vmcs_hierarchy_add_vmcs(VMCS_HIERARCHY * obj, GUEST_CPU_HANDLE gcpu, ADDRESS gpa);
VMM_STATUS  vmcs_hierarchy_remove_vmcs(VMCS_HIERARCHY *obj, VMCS_OBJECT *vmcs_1);
VMCS_OBJECT * vmcs_hierarchy_get_vmcs(VMCS_HIERARCHY *obj, VMCS_LEVEL level);
VMCS_OBJECT * vmcs_hierarchy_get_next_vmcs_1(VMCS_HIERARCHY *obj);
VMCS_OBJECT * vmcs_hierarchy_select_vmcs_1(VMCS_HIERARCHY *obj, VMCS_OBJECT *vmcs);


#endif // _VMCS_HIERARCHY_H_

