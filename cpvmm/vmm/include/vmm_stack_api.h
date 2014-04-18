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

#ifndef VMM_STACK_API_H
#define VMM_STACK_API_H

#include <vmm_defs.h>
#include <vmm_startup.h>

/* Function: vmm_stack_caclulate_stack_pointer
*  Description: This function may be called at the first stages of the boot, when
*               the vmm_stack object is not initialized at all. It calculates the stack
*               pointer of requested cpu.
*  Input: 
*         startup_struct - pointer to startup structure
*         cpu_id - index of the cpu
*  Output:
*         stack_pointer - value (virtual address) that should be put into ESP/RSP
*  Return Value: TRUE in case the calculation is successful.
*/
BOOLEAN vmm_stack_caclulate_stack_pointer(IN const VMM_STARTUP_STRUCT* startup_struct, 
                            IN CPU_ID cpu_id, OUT HVA* stack_pointer);


/* Function: vmm_stack_initialize
*  Description: This function is called in order to initialize internal data structures.
*  Input: 
*         startup_struct - pointer to startup structure
*  Return Value: TRUE in case the initialization is successful.
*/
BOOLEAN vmm_stack_initialize(IN const VMM_STARTUP_STRUCT* startup_struct);


/* Function: vmm_stack_is_initialized
*  Description: Query whether the component is initialized.
*  Return Value: TRUE in case the component was successfully initialized.
*/
BOOLEAN vmm_stack_is_initialized(void);


/* Function: vmm_stack_get_stack_pointer_for_cpu
*  Description: This function is called in order to retrieve the initial value
*               of stack pointer of specific cpu.
*  Input: 
*         cpu_id - index of cpu
*  Output:
*         stack_pointer - value (virtual address) that should be put into ESP/RSP;
*  Return Value: TRUE in case the query is successful.
*                FALSE will be returned when the component wasn't initialized or
*                      cpu_id has invalid value.
*/
BOOLEAN vmm_stack_get_stack_pointer_for_cpu(IN CPU_ID cpu_id, OUT HVA* stack_pointer);

/* Function: vmm_stacks_get_details
*  Description: This function return details of allocated memory for stacks.
*  Output:
*          lowest_addr_used - Host Virtual Address (pointer) of lowest used address
*          size - size allocated for all stacks;
*  Return Value: Host Virtual Address (pointer) of the address
*/
void vmm_stacks_get_details(OUT HVA* lowest_addr_used, OUT UINT32* size);


/* Function: vmm_stacks_get_exception_stack_for_cpu
*  Description: This function return the initial page of the stack that must be unmapped
*               in vmm page tables and re-mapped to higher addresses.
*  Input:
*          cpu_id - cpu number
*          stack_num - number of exception stack
*  Output:
*          page_addr - HVA of the page to guard;
*  Return Value: TRUE in case of success.
*                FALSE will be returned in cpu_id has invalid value
*/
BOOLEAN vmm_stacks_get_exception_stack_for_cpu(IN CPU_ID cpu_id,
                             IN UINT32 stack_num, OUT HVA* page_addr);

#ifdef DEBUG
/* Function: vmm_stacks_print
*  Description: Prints inner map of stacks area.
*/
void vmm_stacks_print(void);
#endif // DEBUG
 
#endif
