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

#include "vmm_defs.h"
#include "hw_utils.h"
#include "guest_cpu.h"
#include "vmexit.h"

VMEXIT_HANDLING_STATUS vmexit_invd(GUEST_CPU_HANDLE gcpu)
{
    // We can't invalidate caches without writing them to memory
    hw_wbinvd();
    gcpu_skip_guest_instruction(gcpu);
    return VMEXIT_HANDLED;
}
