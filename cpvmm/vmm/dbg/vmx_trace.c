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

#include "vmx_trace.h"
#include "trace.h"
#include "common_libc.h"
//#include "vmcs_object.h"
#include "vmcs_api.h"
#include "scheduler.h"
#include "hw_utils.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMX_TRACE_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMX_TRACE_C, __condition)

static VMM_TRACE_STATE vmm_trace_state = VMM_TRACE_DISABLED;

BOOLEAN
vmm_trace_init(
               UINT32 max_num_guests,
               UINT32 max_num_guest_cpus
               )
{
    static BOOLEAN called = FALSE;

    if ( ! called)
    {
        called = trace_init(max_num_guests, max_num_guest_cpus);
    }

    return called;
}

void vmm_trace_state_set(VMM_TRACE_STATE state)
{
    switch (state)
    {
        case VMM_TRACE_DISABLED:
        case VMM_TRACE_ENABLED_RECYCLED:
        case VMM_TRACE_ENABLED_NON_RECYCLED:
            trace_set_recyclable(VMM_TRACE_ENABLED_RECYCLED == state);
            vmm_trace_state = state;
            break;
        default:
            break;
    }
}


static size_t
vmm_trace_print_string(
                       const char    *format,
                       va_list		   marker,
                       char    *string
                       )
{
    char formatted_string[MAX_STRING_LENGTH];
    size_t max_index, length;

    if (VMM_TRACE_DISABLED == vmm_trace_state)
    {
        return 0;
    }

    max_index = vmm_strlen(format);
    if (max_index >= MAX_STRING_LENGTH) {
        VMM_DEADLOOP();
    }

    vmm_strcpy_s(formatted_string, MAX_STRING_LENGTH, format);
    formatted_string[max_index] = '\0';

    length = vmm_vsprintf_s(string, MAX_STRING_LENGTH, formatted_string, marker);
    if (length > MAX_STRING_LENGTH)
    {
        VMM_DEADLOOP();
    }

    return length;
}


BOOLEAN
vmm_trace_buffer(
                 GUEST_CPU_HANDLE   guest_cpu,
                 UINT8              buffer_index,
                 const char         *format,
                 ...
                 )
{
    va_list                    marker;
    TRACE_RECORD_DATA	       data;
    VMCS_OBJECT*		       vmcs_obj = 0;
    const VIRTUAL_CPU_ID       *virtual_cpu_id = 0;
    GUEST_ID                   guest_id = 0;
    CPU_ID                     gcpu_id = 0;

    if (VMM_TRACE_DISABLED == vmm_trace_state)
    {
        return FALSE;
    }

    if (guest_cpu == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"%a %d: Invalid parameter(s): guest_cpu 0x%x\n",
            __FUNCTION__, __LINE__, guest_cpu);
        VMM_DEADLOOP();
    }

    vmm_memset( &data, 0, sizeof( data ));

    va_start(marker, format);
    vmm_trace_print_string(format, marker, data.string);
    va_end(marker);

    vmcs_obj = gcpu_get_vmcs(guest_cpu);
    virtual_cpu_id = guest_vcpu(guest_cpu);

    if(vmcs_obj != NULL)
    {
        data.exit_reason = vmcs_read(vmcs_obj, VMCS_EXIT_INFO_REASON);
        data.guest_eip   = vmcs_read(vmcs_obj, VMCS_GUEST_RIP);
    }
    data.tsc        = (buffer_index == (MAX_TRACE_BUFFERS - 1))? hw_rdtsc(): 0;

    if(virtual_cpu_id != NULL)
    {
        guest_id = virtual_cpu_id->guest_id;
        gcpu_id = virtual_cpu_id->guest_cpu_id;
    }

    return trace_add_record(guest_id, gcpu_id, buffer_index, &data);
}


BOOLEAN
vmm_trace(
          GUEST_CPU_HANDLE  guest_cpu,
          const char       *format,
          ...
          )
{
    va_list                 marker;
    TRACE_RECORD_DATA       data;
    VMCS_OBJECT*		    vmcs_obj = 0;
    const VIRTUAL_CPU_ID    *virtual_cpu_id = 0;
    GUEST_ID                guest_id = 0;
    CPU_ID                  gcpu_id = 0;

    if (VMM_TRACE_DISABLED == vmm_trace_state)
    {
        return FALSE;
    }

    if (guest_cpu == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"%a %d: Invalid parameter(s): guest_cpu 0x%x\n",
            __FUNCTION__, __LINE__, guest_cpu);
        VMM_DEADLOOP();
    }

    vmm_memset( &data, 0, sizeof( data ));

    va_start(marker, format);
    vmm_trace_print_string(format, marker, data.string);
    va_end(marker);

    vmcs_obj = gcpu_get_vmcs(guest_cpu);
    virtual_cpu_id = guest_vcpu(guest_cpu);

    if(vmcs_obj != NULL)
    {
        data.exit_reason = vmcs_read(vmcs_obj, VMCS_EXIT_INFO_REASON);
        data.guest_eip   = vmcs_read(vmcs_obj, VMCS_GUEST_RIP);
        data.tsc         = 0;
//        data.tsc         = hw_rdtsc();
    }

    if(virtual_cpu_id != NULL)
    {
        guest_id = virtual_cpu_id->guest_id;
        gcpu_id = virtual_cpu_id->guest_cpu_id;
    }
    return trace_add_record(guest_id, gcpu_id, 0, &data);
}


BOOLEAN
vmm_trace_print_all(UINT32 guest_num, char *guest_names[])
{
    TRACE_RECORD_DATA record_data;
    UINT32 vm_index = 0, cpu_index = 0, buffer_index = 0, record_index = 0;
    int cnt = 0;


    if (VMM_TRACE_DISABLED == vmm_trace_state)
    {
        return FALSE;
    }
    trace_lock();

    VMM_LOG(mask_anonymous, level_trace,"\nTrace Events\n");

    while (trace_remove_oldest_record(&vm_index, &cpu_index, &buffer_index, &record_index, &record_data)) {
        char *vm_name;
        char buffer[5];

        if (0 == cnt++ % 0x1F)
        {
            VMM_LOG(mask_anonymous, level_trace,
                "Buf   Index    TSC           | VM CPU  Exit Guest       EIP    | Message\n"
                "-----------------------------+---------------------------------+---------------------\n");
        }

        if (vm_index < guest_num)
        {
            vm_name = guest_names[vm_index];

        }
        else
        {
            vmm_sprintf_s(buffer, sizeof(buffer), "%4d", vm_index);
            vm_name = buffer;
        }

        VMM_LOG(mask_anonymous, level_trace,"%2d %8d %016lx |%4s %1d  %4d  %018P | %s",
            buffer_index, record_index, record_data.tsc, vm_name, cpu_index,
            record_data.exit_reason, record_data.guest_eip, record_data.string);


    }

    trace_unlock();
    return TRUE;
}

