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

#include <vmm_defs.h>
#include <vmm_startup.h>
#include <vmm_stack_api.h>
#include <vmm_stack.h>
#include <idt.h>
#include "vmm_dbg.h"
#include <libc.h>
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMM_STACK_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMM_STACK_C, __condition)

static VMM_STACKS_INFO g_stacks_infos_s;
static VMM_STACKS_INFO* const g_stacks_infos = &g_stacks_infos_s;



INLINE
UINT32 vmm_stack_get_stack_size_per_cpu(UINT32 num_of_requested_pages) {
    // adding one more page for exceptions stack
    return ((num_of_requested_pages + idt_get_extra_stacks_required()) * PAGE_4KB_SIZE);
}

INLINE
UINT64 vmm_stack_caclulate_stack_pointer_for_cpu(UINT64 vmm_stack_base_address,
                                                 UINT32 vmm_stack_size_per_cpu,
                                                 CPU_ID cpu_id) {
    UINT64 end_of_block = vmm_stack_base_address + (vmm_stack_size_per_cpu * (cpu_id + 1));
    return  (end_of_block - PAGE_4KB_SIZE); // leave one page to protect from underflow
}

INLINE
UINT64 vmm_stack_get_stacks_base(UINT64 vmm_base_address,
                                 UINT32 vmm_size) {
    return ((vmm_base_address + vmm_size) + PAGE_4KB_SIZE - 1) & (~((UINT64)PAGE_4KB_MASK));
}

INLINE
UINT64 vmm_stacks_retrieve_stacks_base_addr_from_startup_struct(const VMM_STARTUP_STRUCT* startup_struct) {
    UINT64 vmm_base_address = startup_struct->vmm_memory_layout[uvmm_image].base_address;
    UINT32 vmm_size = startup_struct->vmm_memory_layout[uvmm_image].image_size;

    return vmm_stack_get_stacks_base(vmm_base_address, vmm_size);
}

INLINE
UINT32 vmm_stack_retrieve_max_allowed_cpus_from_startup_struct(const VMM_STARTUP_STRUCT* startup_struct) {
    return startup_struct->number_of_processors_at_boot_time;
}

INLINE
UINT32 vmm_stacks_retrieve_stack_size_per_cpu_from_startup_struct(const VMM_STARTUP_STRUCT* startup_struct) {
    return vmm_stack_get_stack_size_per_cpu(startup_struct->size_of_vmm_stack);
}

/*
 * Function name: vmm_stack_calculate_stack_pointer
 * Parameters: Input validation for startup_struct is performed in caller functions. 
 * Function assumes valid input.
 */
BOOLEAN vmm_stack_caclulate_stack_pointer(IN const VMM_STARTUP_STRUCT* startup_struct,
                                          IN CPU_ID cpu_id,
                                          OUT HVA* stack_pointer) {
    UINT64 vmm_stack_base_address = vmm_stacks_retrieve_stacks_base_addr_from_startup_struct(startup_struct);
    UINT32 vmm_stack_size_per_cpu = vmm_stacks_retrieve_stack_size_per_cpu_from_startup_struct(startup_struct);
    UINT32 vmm_max_allowed_cpus = vmm_stack_retrieve_max_allowed_cpus_from_startup_struct(startup_struct);
    UINT64 stack_pointer_tmp;

    if (cpu_id >= vmm_max_allowed_cpus) {
        return FALSE;
    }

    stack_pointer_tmp = vmm_stack_caclulate_stack_pointer_for_cpu(vmm_stack_base_address, vmm_stack_size_per_cpu, cpu_id);
    *stack_pointer = *((HVA*)(&stack_pointer_tmp));
    return TRUE;
}


BOOLEAN vmm_stack_initialize(IN const VMM_STARTUP_STRUCT* startup_struct) {
    UINT64 vmm_stack_base_address;
    UINT32 vmm_stack_size_per_cpu;
    UINT32 vmm_max_allowed_cpus;

    if (startup_struct == NULL) {
        return FALSE;
    }

    vmm_memset( &g_stacks_infos_s, 0, sizeof(g_stacks_infos_s));

    vmm_stack_base_address = vmm_stacks_retrieve_stacks_base_addr_from_startup_struct(startup_struct);
    vmm_stack_size_per_cpu = vmm_stacks_retrieve_stack_size_per_cpu_from_startup_struct(startup_struct);
    vmm_max_allowed_cpus = vmm_stack_retrieve_max_allowed_cpus_from_startup_struct(startup_struct);

    vmm_stacks_info_set_stacks_base(g_stacks_infos, vmm_stack_base_address);
    vmm_stacks_info_set_size_of_single_stack(g_stacks_infos, vmm_stack_size_per_cpu);
    vmm_stacks_info_set_max_allowed_cpus(g_stacks_infos, vmm_max_allowed_cpus);
    vmm_stacks_info_set_num_of_exception_stacks(g_stacks_infos, idt_get_extra_stacks_required());
    vmm_stacks_set_initialized(g_stacks_infos);
    return TRUE;
}

BOOLEAN vmm_stack_is_initialized(void) {
    return vmm_stacks_is_initialized(g_stacks_infos);
}

BOOLEAN vmm_stack_get_stack_pointer_for_cpu(IN CPU_ID cpu_id, OUT HVA* stack_pointer) {
    UINT64 vmm_stack_base_address;
    UINT32 vmm_stack_size_per_cpu;
    UINT64 stack_pointer_tmp;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(vmm_stack_is_initialized());

    if (cpu_id >= vmm_stacks_info_get_max_allowed_cpus(g_stacks_infos)) {
        return FALSE;
    }

    vmm_stack_base_address = vmm_stacks_info_get_stacks_base(g_stacks_infos);
    vmm_stack_size_per_cpu = vmm_stacks_info_get_size_of_single_stack(g_stacks_infos);

    stack_pointer_tmp = vmm_stack_caclulate_stack_pointer_for_cpu(vmm_stack_base_address, vmm_stack_size_per_cpu, cpu_id);
    *stack_pointer = *((HVA*)(&stack_pointer_tmp));
    return TRUE;
}

void vmm_stacks_get_details(OUT HVA* lowest_addr_used, OUT UINT32* size) {
    UINT64 base;
    UINT32 single_size;
    UINT32 num_of_cpus;
    VMM_ASSERT(vmm_stack_is_initialized());

    base = vmm_stacks_info_get_stacks_base(g_stacks_infos);
    single_size = vmm_stacks_info_get_size_of_single_stack(g_stacks_infos);
    num_of_cpus = vmm_stacks_info_get_max_allowed_cpus(g_stacks_infos);

    *lowest_addr_used = *((HVA*)(&base));
    *size = num_of_cpus * single_size;
}

/*
 * Function Name: vmm_stacks_get_exception_stack_for_cpu
 * Parameters: Validation for cpu_id is performed by caller function. Function assumes valid input.
 */
BOOLEAN vmm_stacks_get_exception_stack_for_cpu(IN CPU_ID cpu_id,
                                               IN UINT32 stack_num, OUT HVA* page_addr) {
    UINT64 base;
    UINT32 single_size;

    // BEFORE_VMLAUNCH
    VMM_ASSERT(vmm_stack_is_initialized());

    if (stack_num >= vmm_stacks_info_get_num_of_exception_stacks(g_stacks_infos)) {
        return FALSE;
    }

    base = vmm_stacks_info_get_stacks_base(g_stacks_infos);
    single_size = vmm_stacks_info_get_size_of_single_stack(g_stacks_infos);
    if (stack_num == (vmm_stacks_info_get_num_of_exception_stacks(g_stacks_infos) - 1)) {
        // The last page of the range
        *page_addr = vmm_stack_caclulate_stack_pointer_for_cpu(base, single_size, cpu_id);
    }
    else {
        UINT64 base_for_cpu = base + (single_size * cpu_id);
        *page_addr = base_for_cpu + (PAGE_4KB_SIZE * stack_num);
    }
    return TRUE;
}

#ifdef DEBUG
void vmm_stacks_print(void) {
    CPU_ID cpu_id;

    VMM_LOG(mask_anonymous, level_trace,"\nVMM STACKS:\n");
    VMM_LOG(mask_anonymous, level_trace,  "=================\n");
    for (cpu_id = 0; cpu_id < vmm_stacks_info_get_max_allowed_cpus(g_stacks_infos); cpu_id++) {
        UINT32 regular_stack_size;
        HVA rsp;
        HVA page;
        BOOLEAN res;
        UINT32 stack_id;

        VMM_LOG(mask_anonymous, level_trace,"\tCPU%d:\n", cpu_id);
        for (stack_id = 0; stack_id < vmm_stacks_info_get_num_of_exception_stacks(g_stacks_infos) - 1; stack_id++) {

            res = vmm_stacks_get_exception_stack_for_cpu(cpu_id, stack_id, &page);
            VMM_ASSERT(res);

            VMM_LOG(mask_anonymous, level_trace,"\t[%P - %P] : exception stack #%d \n", page, page + PAGE_4KB_SIZE, stack_id);
        }

        res = vmm_stack_get_stack_pointer_for_cpu(cpu_id, &rsp);
        VMM_ASSERT(res);

        regular_stack_size = vmm_stacks_info_get_size_of_single_stack(g_stacks_infos) - (vmm_stacks_info_get_num_of_exception_stacks(g_stacks_infos) * PAGE_4KB_SIZE);
        VMM_LOG(mask_anonymous, level_trace,"\t[%P - %P] : regular stack - initial RSP = %P\n", rsp - regular_stack_size, rsp, rsp);

        stack_id = vmm_stacks_info_get_num_of_exception_stacks(g_stacks_infos) - 1;
        res = vmm_stacks_get_exception_stack_for_cpu(cpu_id, stack_id, &page);
        VMM_ASSERT(res);

        VMM_LOG(mask_anonymous, level_trace,"\t[%P - %P] : exception stack #%d \n", page, page + PAGE_4KB_SIZE, stack_id);
        VMM_LOG(mask_anonymous, level_trace,"\t-----------------\n");
    }
    VMM_LOG(mask_anonymous, level_trace,"\n");

}
#endif
