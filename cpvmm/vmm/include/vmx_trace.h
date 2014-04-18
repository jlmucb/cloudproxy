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

/*
  Trace mechanism
*/

#ifndef VMX_TRACE_H
#define VMX_TRACE_H

#include "vmm_defs.h"
#include "guest_cpu.h"

typedef enum {
    VMM_TRACE_DISABLED,
    VMM_TRACE_ENABLED_RECYCLED,
    VMM_TRACE_ENABLED_NON_RECYCLED
} VMM_TRACE_STATE;

BOOLEAN vmm_trace_init( UINT32 max_num_guests, UINT32 max_num_guest_cpus);
BOOLEAN vmm_trace( GUEST_CPU_HANDLE guest_cpu, const char *format, ...);
BOOLEAN vmm_trace_buffer( GUEST_CPU_HANDLE  guest_cpu, UINT8 buffer_index,
                 const char  *format, ...);
BOOLEAN vmm_trace_print_all( UINT32 guest_num, char *guest_names[]);
void vmm_trace_state_set( VMM_TRACE_STATE state);

#endif // VMX_TRACE_H

