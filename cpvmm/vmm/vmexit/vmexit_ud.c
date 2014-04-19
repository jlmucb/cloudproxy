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

#include "vmm_defs.h"
#include "isr.h"
#include "guest_cpu.h"
#include "guest_cpu_vmenter_event.h"


VMEXIT_HANDLING_STATUS vmexit_undefined_opcode(GUEST_CPU_HANDLE gcpu)
{
    VMENTER_EVENT ud_event;

    ud_event.interrupt_info.Bits.Valid           = 1;
    ud_event.interrupt_info.Bits.Vector          = IA32_EXCEPTION_VECTOR_UNDEFINED_OPCODE;
    ud_event.interrupt_info.Bits.InterruptType   = VmEnterInterruptTypeHardwareException;
    ud_event.interrupt_info.Bits.DeliverCode     = 0;    // no error code delivered
    gcpu_inject_event(gcpu, &ud_event);
    return VMEXIT_HANDLED;
}


