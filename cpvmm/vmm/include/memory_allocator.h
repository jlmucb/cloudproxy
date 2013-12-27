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

#ifndef _MEMORY_ALLOCATOR_H
#define _MEMORY_ALLOCATOR_H

#include "vmm_defs.h"
#include "heap.h"

/*-------------------------------------------------------*
*  FUNCTION : vmm_memory_allocate()
*  PURPOSE  : Allocates contiguous buffer of given size, filled with zeroes
*  ARGUMENTS: IN UINT32 size - size of the buffer in bytes
*  RETURNS  : void*  address of allocted buffer if OK, NULL if failed
*-------------------------------------------------------*/
void* vmm_mem_allocate(
    char    *file_name,
    INT32   line_number,
    IN UINT32 size);

/*-------------------------------------------------------*
*  FUNCTION : vmm_memory_free()
*  PURPOSE  : Release previously allocated buffer
*  ARGUMENTS: IN void *p_buffer - buffer to be released
*  RETURNS  : void
*-------------------------------------------------------*/
void vmm_mem_free(
    char    *file_name,
    INT32   line_number,
    IN void *buff);

void* vmm_mem_allocate_aligned(
    char    *file_name,
    INT32   line_number,
    IN UINT32 size,
    IN UINT32 alignment);

/*-------------------------------------------------------*
*  FUNCTION : vmm_mem_buff_size()
*  PURPOSE  : Get size of buff
*  ARGUMENTS: IN void *p_buffer - the buffer
*  RETURNS  : UINT32 - size
*-------------------------------------------------------*/
UINT32 vmm_mem_buff_size(
      char    *file_name,
      INT32   line_number,
      IN void *buff);

/*-------------------------------------------------------*
*  FUNCTION : vmm_mem_pool_size()
*  PURPOSE  : Get the size of pool that will be needed to alloc a buff of given size
*  ARGUMENTS: IN UINT32 size - size
*  RETURNS  : UINT32 - pool size
*-------------------------------------------------------*/
UINT32 vmm_mem_pool_size(
      char    *file_name,
      INT32   line_number,
      IN UINT32 size);

#if defined DEBUG || defined ENABLE_RELEASE_VMM_LOG
// This is done to remove out the file name and line number (present in strings)
// from the release build
#define vmm_malloc(__size)                                               \
        vmm_mem_allocate(__FILE__, __LINE__, __size)

#define vmm_malloc_aligned(__size, __alignment)                          \
        vmm_mem_allocate_aligned(__FILE__, __LINE__, __size, __alignment)

#define vmm_mfree(__buff)                                                \
        vmm_mem_free(__FILE__, __LINE__, __buff)

#define vmm_mem_alloc_size(__size)                                       \
        vmm_mem_pool_size(__FILE__, __LINE__, __size)

#define vmm_mem_free_size(__buff)                                        \
        vmm_mem_buff_size(__FILE__, __LINE__, __buff)
#else
#define vmm_malloc(__size)                                               \
        vmm_mem_allocate(NULL, 0, __size)

#define vmm_malloc_aligned(__size, __alignment)                          \
        vmm_mem_allocate_aligned(NULL, 0, __size, __alignment)

#define vmm_mfree(__buff)                                                \
        vmm_mem_free(NULL, 0, __buff)

#define vmm_mem_alloc_size(__size)                                       \
        vmm_mem_pool_size(NULL, 0, __size)

#define vmm_mem_free_size(__buff)                                        \
        vmm_mem_buff_size(NULL, 0, __buff)
#endif

void memory_allocator_print(void);

#endif
