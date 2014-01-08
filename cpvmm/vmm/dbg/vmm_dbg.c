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

#include "guest_cpu.h"
#include "scheduler.h"
#include "common_libc.h"
#include "vmm_dbg.h"
#include "guest_cpu_vmenter_event.h"
#include "vmcs_api.h"
#include "isr.h"
#include "vmm_arch_defs.h"
#include "memory_dump.h"
#include "em64t_defs.h"
#include "vmm_stack_api.h"
#include "../memory/ept/fvs.h"
#include "vmm_callback.h"

UINT64  g_debug_gpa = 0;
UINT64  g_initial_vmcs[VMM_MAX_CPU_SUPPORTED] = {0};
ISR_PARAMETERS_ON_STACK *g_exception_stack = NULL;
VMM_GP_REGISTERS g_exception_gpr = {0};

extern BOOLEAN vmm_copy_to_guest_phy_addr(GUEST_CPU_HANDLE gcpu,
                                          void* gpa,
                                          UINT32 size,
                                          void* hva);

int CLI_active(void)
{
#ifdef CLI_INCLUDE
	return (VMM_MASK_CHECK(mask_cli)) ? 1 : 0;
#else
	return 0;
#endif
}


// Dump debug info to guest buffer
// To ensure only 1 signature string instance in memory dump
// 1. build signature one char at a time
// 2. no signature to serial output
// 3. clear signature in the string buffer after used
#define BUFFER_SIZE 256
void vmm_deadloop_internal(UINT32 file_code, UINT32 line_num, GUEST_CPU_HANDLE gcpu)
{
    static UINT32 dump_started = 0;
    char        buffer[BUFFER_SIZE], err_msg[BUFFER_SIZE];
    UINT64      rsp, stack_base;
    UINT32      size;
    CPU_ID      cpu_id;
    EXCEPT_INFO header;

    // skip dumping debug info if deadloop/assert happened before launch
    if (g_debug_gpa == 0)
        return;

    cpu_id = hw_cpu_id();
    if (cpu_id >= MAX_CPUS)
    	return;

    vmm_sprintf_s(err_msg, 128, "CPU%d: %s: Error: Could not copy deadloop message back to guest\n",
            cpu_id, __FUNCTION__);

    // send cpu id, file code, line number to serial port
    vmm_printf("%02d%04d%04d\n", cpu_id, file_code, line_num);

    // must match format defined in FILE_LINE_INFO
    size = vmm_sprintf_s(buffer, BUFFER_SIZE, "%04d%04d", file_code, line_num);

    // copy file code/line number to guest buffer at offset defined in DEADLOOP_DUMP
    // strlen(signature) + sizeof(cpu_id) + file_line[cpu]
    if (!vmm_copy_to_guest_phy_addr(gcpu,
                                   (void*)(g_debug_gpa+8+8+(cpu_id*size)),
                                   size,
                                   (void*)buffer)) {
        VMM_LOG(mask_uvmm, level_error, err_msg);
	}

    // only copy signature, VERSION, cpu_id, exception info, vmcs to guest
    // buffer once
    if (hw_interlocked_compare_exchange(&dump_started,0,1) == 0) {
        size = vmm_sprintf_s(buffer, BUFFER_SIZE, "%c%c%c%c%c%c%c%c%s%04d",
            DEADLOOP_SIGNATURE[0], DEADLOOP_SIGNATURE[1],
            DEADLOOP_SIGNATURE[2], DEADLOOP_SIGNATURE[3],
            DEADLOOP_SIGNATURE[4], DEADLOOP_SIGNATURE[5],
            DEADLOOP_SIGNATURE[6], DEADLOOP_SIGNATURE[7], VERSION, cpu_id);

        // copy signature and cpu_id to guest buffer
        if (!vmm_copy_to_guest_phy_addr(gcpu,
                                       (void*)(g_debug_gpa),
                                       size,
                                       (void*)buffer)) {
            VMM_LOG(mask_uvmm, level_error, err_msg);
        }

        // clear buffer erasing the signature or setting no exception flag
        vmm_zeromem(buffer, sizeof(UINT64));

        // copy exception info to guest buffer
        if (g_exception_stack != NULL) {
        	vmm_memcpy((void *)&header.exception_stack, g_exception_stack, sizeof(ISR_PARAMETERS_ON_STACK));
        	header.base_address = vmm_startup_data.vmm_memory_layout[uvmm_image].base_address;

            if (g_exception_stack->a.vector_id == IA32_EXCEPTION_VECTOR_PAGE_FAULT)
            	header.cr2 = hw_read_cr2();

            // copy exception info to guest buffer
            if (!vmm_copy_to_guest_phy_addr(gcpu,
                                           (void*)(g_debug_gpa+OFFSET_EXCEPTION),
                                           sizeof(EXCEPT_INFO),
                                           (void*)&header)) {
                VMM_LOG(mask_uvmm, level_error, err_msg);
            }

    		// copy GPRs to guest buffer
    		if (!vmm_copy_to_guest_phy_addr(gcpu,
                                           (void*)(g_debug_gpa+OFFSET_GPR),
                                           sizeof(VMM_GP_REGISTERS),
                                           (void*)&g_exception_gpr)) {
                VMM_LOG(mask_uvmm, level_error, err_msg);
            }

            // copy stack to guest buffer
            rsp = isr_error_code_required((VECTOR_ID)g_exception_stack->a.vector_id) ?
            		g_exception_stack->u.errcode_exception.sp :
            		g_exception_stack->u.exception.sp;

            vmm_stack_get_stack_pointer_for_cpu(cpu_id, &stack_base);

            size = sizeof(UINT64)*STACK_TRACE_SIZE;
            if ((rsp+size) > stack_base)
                size = (UINT32)(stack_base-rsp);

            if (!vmm_copy_to_guest_phy_addr(gcpu,
                                           (void*)(g_debug_gpa+OFFSET_STACK),
                                           size,
            		                       (void*)rsp)) {
                VMM_LOG(mask_uvmm, level_error, err_msg);
            }
        } else {
            // Clear base image address indicating exception did not happen
            if (!vmm_copy_to_guest_phy_addr(gcpu,
                                           (void*)(g_debug_gpa+OFFSET_EXCEPTION),
                                           sizeof(UINT64),
                                           (void*)buffer))
                VMM_LOG(mask_uvmm, level_error, err_msg);
        }

        // copy vmcs to guest buffer
        vmcs_dump_all(gcpu);
    }
}


void vmm_deadloop_dump(UINT32 file_code, UINT32 line_num)
{
#define DEFAULT_VIEW_HANDLE 0

    GUEST_CPU_HANDLE gcpu;
    EM64T_RFLAGS     rflags;
    IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY  interruptibility;

    gcpu = scheduler_current_gcpu();
    if(!gcpu)
    	VMM_UP_BREAKPOINT();

    report_uvmm_event(UVMM_EVENT_VMM_ASSERT, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), NULL);

    // send debug info to serial port and guest buffer
    vmm_deadloop_internal(file_code, line_num, gcpu);

	// clear interrupt flag
    rflags.Uint64 = gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);
    rflags.Bits.IFL = 0;
    gcpu_set_gp_reg(gcpu, IA32_REG_RFLAGS, rflags.Uint64);

    interruptibility.Uint32 = gcpu_get_interruptibility_state(gcpu);
    interruptibility.Bits.BlockNextInstruction = 0;
    gcpu_set_interruptibility_state(gcpu, interruptibility.Uint32);

    // generate BSOD
    gcpu_inject_gp0(gcpu);
    gcpu_resume(gcpu);
}


//
// Generic debug helper function
//
// returns TRUE 

#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter

BOOLEAN DeadloopHelper( const char* assert_condition,
                        const char* func_name,
                        const char* file_name,
                        UINT32      line_num,
                        UINT32		access_level)
{
    if (!assert_condition)
    {
        vmm_printf("Deadloop in %s() - %s:%d\n",
                      func_name, 
                      file_name, 
                      line_num);
    }
    else
    {
        vmm_printf("VMM assert (%s) failed\n\t in %s() at %s:%d\n",
                      assert_condition, 
                      func_name, 
                      file_name, 
                      line_num);
    }

    return TRUE;
}
#pragma warning( pop )



