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

#ifndef _HEAP_H_
#define _HEAP_H_

//#ifdef __cplusplus
//extern "C" {
//#endif

#include "vmm_defs.h"

//typedef UINT32 HEAP_PAGE_INT;
#define HEAP_PAGE_INT UINT32

typedef struct {
    HEAP_PAGE_INT number_of_pages:31; // When in_use=1, this represents the number of allocated pages
                                      // When in_use=0, represents the number of contiguos pages from this address
    HEAP_PAGE_INT in_use:1;           // 1=InUse

#ifdef DEBUG
    INT32 line_number;
    char  *file_name;
#endif
} HEAP_PAGE_DESCRIPTOR;


// FUNCTION : vmm_heap_get_max_used_pages()
// PURPOSE  : Returns the max amount of uVmm heap pages used
//            from post-launch vmm
// ARGUMENTS:
// RETURNS  : HEAP max heap used in pages
HEAP_PAGE_INT vmm_heap_get_max_used_pages(void);


// FUNCTION : vmm_heap_initialize()
// PURPOSE  : Format memory block for memory allocation / free services.
//          : Calculate actual number of pages.
// ARGUMENTS:IN ADDRESS heap_base_address - address at which the heap is located
//          : size_t    heap_size - in bytes
// RETURNS  : Last occupied address
ADDRESS vmm_heap_initialize(IN ADDRESS heap_base_address, IN size_t heap_size);


// FUNCTION : vmm_heap_extend()
// PURPOSE  : Extend the heap to an additional memory block 
//		: update actual number of pages.
// ARGUMENTS:IN ADDRESS ex_heap_base_address - address at which the heap is located
//          : size_t    ex_heap_size - in bytes
// RETURNS  : Last occupied address
ADDRESS vmm_heap_extend(IN ADDRESS ex_heap_buffer_address, IN size_t  ex_heap_buffer_size);


/*-------------------------------------------------------*
*  FUNCTION : vmm_head_get_details()
*  PURPOSE  : Retrieve information about heap area.
*  ARGUMENTS: OUT HVA* base_addr - address at which the heap is located
*           : UINT32   size - in bytes
*-------------------------------------------------------*/
void vmm_heap_get_details(OUT HVA* base_addr, OUT UINT32* size);

/*-------------------------------------------------------*
*  FUNCTION : vmm_page_alloc()
*  PURPOSE  : Allocates contiguous buffer of given size
*  ARGUMENTS: IN HEAP_PAGE_INT number_of_pages - size of the buffer in 4K pages
*  RETURNS  : void*  address of allocted buffer if OK, NULL if failed
*-------------------------------------------------------*/
void* vmm_page_allocate(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    HEAP_PAGE_INT number_of_pages
    );

/*-------------------------------------------------------*
*  FUNCTION : vmm_page_alloc_scattered()
*  PURPOSE  : Fills given array with addresses of allocated 4K pages
*  ARGUMENTS: IN HEAP_PAGE_INT number_of_pages - number of 4K pages
*           : OUT void * p_page_array[] - contains the addresses of allocated pages
*  RETURNS  : number of successfully allocated pages
*-------------------------------------------------------*/
HEAP_PAGE_INT vmm_page_allocate_scattered(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    IN HEAP_PAGE_INT number_of_pages,
    OUT void *p_page_array[]
    );

/*-------------------------------------------------------*
*  FUNCTION : vmm_page_free()
*  PURPOSE  : Release previously allocated buffer
*  ARGUMENTS: IN void *p_buffer - buffer to be released
*  RETURNS  : void
*-------------------------------------------------------*/
void vmm_page_free(IN void *p_buffer);

/*-------------------------------------------------------*
*  FUNCTION : vmm_page_buff_size()
*  PURPOSE  : Identify number of pages in previously allocated buffer
*  ARGUMENTS: IN void *p_buffer - the buffer
*  RETURNS  : UINT32 - Num pages this buffer is using
*-------------------------------------------------------*/
UINT32 vmm_page_buff_size(IN void *p_buffer);

HEAP_PAGE_INT vmm_heap_get_total_pages(void);

/*-------------------------------------------------------*
*  FUNCTION : vmm_memory_allocate()
*  PURPOSE  : Allocates contiguous buffer of given size, filled with zeroes
*  ARGUMENTS: IN UINT32 size - size of the buffer in bytes
*  RETURNS  : void*  address of allocted buffer if OK, NULL if failed
*             returned buffer is always 4K page alinged
*-------------------------------------------------------*/
void* vmm_memory_allocate(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    IN UINT32 size
    );

/*-------------------------------------------------------*
*  FUNCTION : vmm_memory_free()
*  PURPOSE  : Release previously allocated buffer
*  ARGUMENTS: IN void *p_buffer - buffer to be released
*  RETURNS  : void
*-------------------------------------------------------*/
#define vmm_memory_free( p_buffer ) vmm_page_free( p_buffer )


typedef void (*VMM_FREE_MEM_CALLBACK_FUNC)(IN void* context);
typedef UINT32 HEAP_ALLOC_HANDLE;
#define HEAP_INVALID_ALLOC_HANDLE ((HEAP_ALLOC_HANDLE)(~0))


/*-------------------------------------------------------*
*  FUNCTION : vmm_heap_register_free_mem_callback()
*  PURPOSE  : Provides an opportunity for some module to register
*             memory deallocation callback. In case when some other
*             component requires more memory and the request cannot
*             be fulfilled due to a low memory, this callback function
*             will be called.
*  ARGUMENTS: IN VMM_FREE_MEM_CALLBACK_FUNC callback_func - pointer to callback function
*             IN void* context - context which will be passed to callback function upon call.
*  RETURNS  : HEAP_ALLOC_HANDLE - handle which can be used for allocation. In case of failure
*             "HEAP_INVALID_ALLOC_HANDLE" will be returned.
*-------------------------------------------------------*/
HEAP_ALLOC_HANDLE vmm_heap_register_free_mem_callback(IN VMM_FREE_MEM_CALLBACK_FUNC callback_func, IN void* context);


/*-------------------------------------------------------*
*  FUNCTION : vmm_memory_allocate_must_succeed()
*  PURPOSE  : The function tries to allocate requested memory. In case of insufficient
*             memory, the heap will call all the registered deallocation functions except
*             the one which was recorded under the passed HEAP_ALLOC_HANDLE.
*  ARGUMENTS: IN HEAP_ALLOC_HANDLE handle - handle returned by "vmm_heap_register_free_mem_callback".
*                                           It is possible to pass HEAP_INVALID_ALLOC_HANDLE, but
*                                           in this case all the recorded callbacks will be called, no exceptions.
*             IN UINT32 size - requested size.
*  RETURNS  : void* - allocated memory.
*-------------------------------------------------------*/
void* vmm_memory_allocate_must_succeed(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    HEAP_ALLOC_HANDLE handle,
    UINT32 size
    );


#ifdef DEBUG

#define vmm_page_alloc(__num_of_pages)                                         \
        vmm_page_allocate(__FILE__, __LINE__, __num_of_pages)

#define vmm_memory_alloc(__size)                                               \
        vmm_memory_allocate(__FILE__, __LINE__, __size)

#define vmm_page_alloc_scattered(__num_of_pages, __p_page_array)               \
        vmm_page_allocate_scattered(__FILE__, __LINE__, __num_of_pages, __p_page_array)

#define vmm_memory_alloc_must_succeed(__handle, __size)                        \
    vmm_memory_allocate_must_succeed(__FILE__, __LINE__, __handle, __size)


void vmm_heap_show(void);

#else

#define vmm_page_alloc                  vmm_page_allocate
#define vmm_memory_alloc                vmm_memory_allocate
#define vmm_page_alloc_scattered        vmm_page_allocate_scattered
#define vmm_memory_alloc_must_succeed   vmm_memory_allocate_must_succeed


#define vmm_heap_show()

#endif


//#ifdef __cplusplus
//}
//#endif

#endif // _HEAP_H_

