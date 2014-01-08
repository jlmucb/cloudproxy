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

#ifndef E820_ABSTRACTION_H
#define E820_ABSTRACTION_H

#include <vmm_arch_defs.h>
#ifdef ENABLE_INT15_VIRTUALIZATION
#include <vmm_objects.h>
#endif
typedef void* E820_ABSTRACTION_RANGE_ITERATOR;
#define E820_ABSTRACTION_NULL_ITERATOR ((E820_ABSTRACTION_RANGE_ITERATOR)NULL)

typedef void* E820_HANDLE;
#define E820_ORIGINAL_MAP ((E820_HANDLE)NULL)


/* Function: e820_abstraction_initialize
*  Description: This function will copy the e820_memory_map to internal data
*               structures.
*  Return Value: TRUE in case the initialization is successful.
*/
BOOLEAN e820_abstraction_initialize(IN const INT15_E820_MEMORY_MAP* e820_memory_map);


/* Function: e820_abstraction_is_initialized
*  Description: Using this function the other components can receive the information,
*               whether the component was successfully initialized.
*  Return Value: TRUE in case the component was initialized.
*/
BOOLEAN e820_abstraction_is_initialized(void);


/* Function: e820_abstraction_get_map
*  Description: The function returns the e820. This function may be called if
*               work with iterator is inconvenient.
*  Input:
*        e820_handle - handle returned by "e820_abstraction_create_new_map" 
*                      or E820_ORIGINAL_MAP if iteration over original map is required
*  Return Value: Pointer to e820 map
*/
const INT15_E820_MEMORY_MAP* e820_abstraction_get_map(E820_HANDLE e820_handle);


/* Function: e820_abstraction_iterator_get_first
*  Description: The function returns the iterator for existing memory ranges.
*               It is possible to retrieve information of all existing ranges
*               using this iterator.
*  Input:
*        e820_handle - handle returned by "e820_abstraction_create_new_map" 
*                      or E820_ORIGINAL_MAP if iteration over original map is required
*  Return Value: Iterator. Null iterator is: E820_ABSTRACTION_NULL_ITERATOR.
*/
E820_ABSTRACTION_RANGE_ITERATOR e820_abstraction_iterator_get_first(E820_HANDLE e820_handle);

/* Function: e820_abstraction_iterator_get_next
*  Description: The function moves the iterator to the next range.
*  Input: 
*         e820_handle - handle returned by "e820_abstraction_create_new_map" 
*                       or E820_ORIGINAL_MAP if iteration over original map is required
*         iter - current iterator.
*  Return Value: new value of iterator. In case there is no next element the
*                E820_ABSTRACTION_NULL_ITERATOR value will be returned.
*/
E820_ABSTRACTION_RANGE_ITERATOR e820_abstraction_iterator_get_next(E820_HANDLE e820_handle, E820_ABSTRACTION_RANGE_ITERATOR iter);


/* Function: e820_abstraction_iterator_get_range_details
*  Description: This function provided the details of current memory range. Please,
*               see the content of "INT15_E820_MEMORY_MAP_ENTRY_EXT" structure.
*               Node, that the structure cannot be updated.
*  Input: iter - current iterator.
*  Return Value: pointer to memory region details. In iterator is invalid, NULL
*                will be returned.
*/
const INT15_E820_MEMORY_MAP_ENTRY_EXT*
e820_abstraction_iterator_get_range_details(IN E820_ABSTRACTION_RANGE_ITERATOR iter);


/* Function: e820_abstraction_create_new_map
*  Description: This function is used to create new e820 map for filling.
*  Output: handle - new e820 handle. It may be used as parameter for other function
*  Return Value: TRUE in case when memory allocation succeeded.
*                FALSE in case when memory allocation failed.
*/
BOOLEAN e820_abstraction_create_new_map(OUT E820_HANDLE* handle);


/* Function: e820_abstraction_create_new_map
*  Description: This function is used to destroy created e820 map.
*  Input: handle - handle returned by "e820_abstraction_create_new_map" function.
*                  It is forbidden to pass E820_ORIGINAL_MAP as parameter.
*/
void e820_abstraction_destroy_map(IN E820_HANDLE handle);


/* Function: e820_abstraction_add_new_range
*  Description: This function is used add new range for created e820 map.
*               The range mustn't intersect with already inseted ones and must be
*               in chronological order.
*  Input: handle - handle returned by "e820_abstraction_create_new_map" function.
*                  It is forbidden to pass E820_ORIGINAL_MAP as parameter.
*         base_address - base address to be recorded
*         length - length of range to be recorded.
*         address_range_type - type of range to be recorded
*         extended_attributes - extended attributes to be recorded.
*/
BOOLEAN e820_abstraction_add_new_range(IN E820_HANDLE handle,
                                       IN UINT64 base_address,
                                       IN UINT64 length,
                                       IN INT15_E820_RANGE_TYPE  address_range_type,
                                       IN INT15_E820_MEMORY_MAP_EXT_ATTRIBUTES    extended_attributes);

#ifdef ENABLE_INT15_VIRTUALIZATION
#pragma PACK_ON
typedef struct _E820_GUEST_STATE
{
	UINT16      		em_es;
	UINT64      		es_base;
	UINT32      		es_lim;
	UINT32      		es_attr;
	UINT16      		em_ss;
	UINT64      		ss_base;
	UINT32      		ss_lim;
	UINT32      		ss_attr;
	UINT64              em_rip;
	UINT64              em_rflags;
	UINT64              em_rax;
	UINT64              em_rbx;
	UINT64              em_rcx;
	UINT64              em_rdx;
    UINT64              em_rdi;
    UINT64              em_rsp;
} E820_GUEST_STATE;

typedef struct _E820MAP_STATE
{
	E820_GUEST_STATE		e820_guest_state;
	E820_HANDLE             emu_e820_handle;
	const INT15_E820_MEMORY_MAP_ENTRY_EXT *emu_e820_memory_map;
	UINT16                  emu_e820_memory_map_size;       // in entries
	UINT16                  emu_e820_continuation_value;    // entry no
    GUEST_HANDLE 			guest_handle;
    GPM_HANDLE              guest_phy_memory;
} E820MAP_STATE;
#pragma PACK_OFF

/* re-used for INT15 handling in VMM using vmcall */
// use 4 vectors at F8h, F9h, FA, FBh for our code at segment 0x0
#define INT15_HANDLER_ADDR			0x000003E0
#define ORIG_HANDLER_OFFSET				6
#define VMCALL_OFFSET					0xA //this is derived from update_int15_handling()
											// assumption: vmcall is at this offset from
											// start of the interrupt handling routine
#define INT15_VECTOR_LOCATION		 	(0x15 * 4)

#define SEGMENT_OFFSET_TO_LINEAR(__seg, __ofs) ((((__seg) & 0xffff) << 4) + ((__ofs) & 0xffff))
#define RFLAGS_CARRY					1


void e820_save_guest_state(GUEST_CPU_HANDLE gcpu, E820MAP_STATE *emap);
void e820_restore_guest_state(GUEST_CPU_HANDLE gcpu, E820MAP_STATE *emap);
BOOLEAN e820_int15_handler(E820MAP_STATE *emap);
extern BOOLEAN gpm_create_e820_map(IN GPM_HANDLE gpm_handle,
                            OUT E820_HANDLE* e820_handle);
extern void gpm_destroy_e820_map(IN E820_HANDLE e820_handle);
#endif // ENABLE_INT15_VIRTUALIZATION

#ifdef DEBUG

/* Function: e820_abstraction_print_memory_map
*  Description: This function is used to print the memory map
*  Input: handle - handle returned by "e820_abstraction_create_new_map" function.
*                  or E820_ORIGINAL_MAP.
*/
void e820_abstraction_print_memory_map(IN E820_HANDLE handle);
#endif

#endif


