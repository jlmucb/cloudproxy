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

#include "memory_allocator.h"
#include "pool_api.h"
#include "hw_utils.h"
#include "vmm_dbg.h"
#include "common_libc.h"
#include "lock.h"
#include "file_codes.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#ifndef VMM_DEADLOOP
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(MEMORY_ALLOCATOR_C)
#endif

#ifndef VMM_ASSERT
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(MEMORY_ALLOCATOR_C, __condition)
#endif

typedef struct {
    UINT32 size;
    UINT32 offset;
} MEM_ALLOCATION_INFO;

// pool per element size (2^x bytes, x = 0, 1,...11)
#define NUMBER_OF_POOLS     12

// pool per element size (2^x bytes, x = 0, 1,...11)
static POOL_HANDLE pools[NUMBER_OF_POOLS] = {POOL_INVALID_HANDLE};
static VMM_LOCK lock = LOCK_INIT_STATE;

static UINT32 buffer_size_to_pool_index(UINT32 size)
{
    UINT32 pool_index = 0;
    UINT32 pool_element_size = 0;

    VMM_ASSERT(size != 0);
    hw_scan_bit_backward((UINT32 *)&pool_index, size);
    pool_element_size = 1 << pool_index;
    if(pool_element_size < size) {
        pool_element_size = pool_element_size << 1;
        pool_index++;
    }
    return pool_index;
}

#pragma warning (push)
#pragma warning (disable : 4100)

static void* vmm_mem_allocate_internal( char *file_name,
            INT32 line_number, IN UINT32 size, IN UINT32 alignment)
{
    POOL_HANDLE pool = NULL;
    UINT32 pool_index = 0;
    UINT32 pool_element_size = 0;
    void* ptr;
    UINT64 allocated_addr;
    MEM_ALLOCATION_INFO *alloc_info;
    UINT32 size_to_request;
#ifdef JLMDEBUG1
    bprint("In vmm_mem_allocate_internal size: %d, align: %08x\n", size, alignment);
#endif

    // starting from 2KB+1 need a full page
    if(size > ((2 KILOBYTE) - sizeof(MEM_ALLOCATION_INFO))) { 
        VMM_LOG(mask_anonymous, level_trace,"%s: WARNING: Memory allocator supports allocations of sizes up to 2040 bytes (requested size = 0x%x from %s:%d)\n", __FUNCTION__, size, file_name, line_number);
        VMM_ASSERT(0); 
        return NULL;
    }

    if (alignment >= PAGE_4KB_SIZE) {
        VMM_LOG(mask_anonymous, level_trace,"%s: WARNING: Requested alignment is 4K or more, use full page allocation (requested alignment = 0x%x)\n", __FUNCTION__, alignment);
        VMM_ASSERT(0); 
        return NULL;
    }

    VMM_ASSERT(IS_POW_OF_2(alignment));
    VMM_ASSERT(alignment >= sizeof(MEM_ALLOCATION_INFO));

    if (alignment > sizeof(MEM_ALLOCATION_INFO)) {
        UINT32 adjusted_size = (size < alignment) ? alignment : size;
        size_to_request = adjusted_size * 2;
    }
    else {
        size_to_request = size + sizeof(MEM_ALLOCATION_INFO);
    }

    pool_index = buffer_size_to_pool_index(size_to_request);
    pool_element_size = 1 << pool_index;

    lock_acquire(&lock);
#ifdef JLMDEBUG1
    bprint("pool_index: %d, pools: 0x%016x,\nval = %p, expected = %p\n",
            pool_index, pools, pools[pool_index], pools[0]);
#endif
    pool = pools[pool_index];
    if(NULL == pool) {
        pool = pools[pool_index] = assync_pool_create((UINT32)pool_element_size);
        VMM_ASSERT(pool);
    }

    ptr = pool_allocate(pool);
    lock_release(&lock);
    if(NULL == ptr) {
        return NULL;
    }

    vmm_zeromem(ptr, pool_element_size);
    allocated_addr = (UINT64)ptr;

    // Check alignment
    VMM_ASSERT(ALIGN_BACKWARD(allocated_addr, (UINT64)alignment) == allocated_addr);
    alloc_info = (MEM_ALLOCATION_INFO*)
                    (allocated_addr + alignment - sizeof(MEM_ALLOCATION_INFO));
    alloc_info->size = pool_element_size;
    alloc_info->offset = alignment;
    return (void *)(allocated_addr + alignment);
}


// vmm_mem_allocate() and vmm_mem_free() have allocation limit of 2048 bytes
// and need to be extended. vmm_page_alloc() and vmm_page_free() are
// a temporary solution for more than 2040 bytes using page alignment of 
// buffer differentiating between vmm_malloc allocation() and vmm_page_alloc(). 
void* vmm_mem_allocate( char *file_name, INT32 line_number, IN UINT32 size)
{
    return vmm_mem_allocate_internal( file_name, line_number,
            size, sizeof(MEM_ALLOCATION_INFO));
}

void vmm_mem_free( char *file_name, INT32 line_number, IN void *buff)
{
    MEM_ALLOCATION_INFO *alloc_info;
    void* allocated_buffer;
    UINT32 pool_element_size = 0;
    UINT32 pool_index = 0;
    POOL_HANDLE pool = NULL;

    if (buff == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"In %s#%d try to free NULL\n", file_name, line_number);
        return;
    }

    alloc_info = (MEM_ALLOCATION_INFO*)((UINT64)buff - sizeof(MEM_ALLOCATION_INFO));
    pool_element_size = alloc_info->size;
    VMM_ASSERT(IS_POW_OF_2(pool_element_size));

    pool_index = buffer_size_to_pool_index(pool_element_size);
    allocated_buffer = (void*)((UINT64)buff - alloc_info->offset);

    lock_acquire(&lock);
    pool = pools[pool_index];
    VMM_ASSERT(pool != NULL);

    pool_free(pool, allocated_buffer);
    lock_release(&lock);
}

void* vmm_mem_allocate_aligned( char *file_name, INT32 line_number,
    IN UINT32 size, IN UINT32 alignment) {

    if (!IS_POW_OF_2(alignment)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: WARNING: Requested alignment is not power of 2\n", __FUNCTION__);
        return NULL;
    }
    return vmm_mem_allocate_internal( file_name, line_number, size, alignment);
}

UINT32 vmm_mem_buff_size( char *file_name, INT32 line_number, IN void *buff)
{
    MEM_ALLOCATION_INFO *alloc_info;
    UINT32 pool_element_size = 0;

    if (buff == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"In %s#%d try to access NULL\n", file_name, line_number);
        return 0;
    }
    alloc_info = (MEM_ALLOCATION_INFO*)((UINT64)buff - sizeof(MEM_ALLOCATION_INFO));
    pool_element_size = alloc_info->size;
    VMM_ASSERT(IS_POW_OF_2(pool_element_size));
    return pool_element_size;
}

static UINT32 vmm_mem_pool_size_internal( char *file_name, INT32 line_number,
    IN UINT32 size, IN UINT32 alignment)
{
    UINT32 pool_index = 0;
    UINT32 pool_element_size = 0;
    UINT32 size_to_request;

    if (alignment > sizeof(MEM_ALLOCATION_INFO)) {
        UINT32 adjusted_size = (size < alignment) ? alignment : size;

        size_to_request = adjusted_size * 2;
    }
    else {
        size_to_request = size + sizeof(MEM_ALLOCATION_INFO);
    }

    pool_index = buffer_size_to_pool_index(size_to_request);
    pool_element_size = 1 << pool_index;
    return pool_element_size;
}

UINT32 vmm_mem_pool_size( char *file_name, INT32 line_number, IN UINT32 size)
{
    return vmm_mem_pool_size_internal( file_name, line_number,
            size, sizeof(MEM_ALLOCATION_INFO));
}

#pragma warning (pop)

#ifdef INCLUDE_UNUSED_CODE
void memory_allocator_print(void)
{
    UINT32 i;

    for(i = 0; i < NUMBER_OF_POOLS; i++) {
        if(POOL_INVALID_HANDLE == pools[i]) {
            VMM_LOG(mask_anonymous, level_trace,"\r\nPool #%d nor int use\r\n", i);
        }
        else {
            pool_print(pools[i]);
        }
    }
}
#endif
