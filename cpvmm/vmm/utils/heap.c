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
#include "common_libc.h"
#include "lock.h"
#include "heap.h"
#include "vmm_dbg.h"
#include "file_codes.h"
#include "profiling.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(HEAP_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(HEAP_C, __condition)

#define CHECK_ADDRESS_IN_RANGE(addr, range_start, size) \
    (((UINT64)addr) >= ((UINT64)range_start) && ((UINT64)addr) <= ((UINT64)range_start) + (size))

#define HEAP_PAGE_TO_POINTER(__page_no) \
    (__page_no >= ex_heap_start_page)?\
        (void *) (ADDRESS) (ex_heap_base + ((__page_no - ex_heap_start_page - 1) * PAGE_4KB_SIZE)): \
        (void *) (ADDRESS) (heap_base + (__page_no * PAGE_4KB_SIZE))
#define HEAP_POINTER_TO_PAGE(__pointer) \
    (CHECK_ADDRESS_IN_RANGE(__pointer, ex_heap_base, ex_heap_pages * PAGE_4KB_SIZE))? \
        (HEAP_PAGE_INT) ((((ADDRESS)(__pointer) - ex_heap_base)) / PAGE_4KB_SIZE) + ex_heap_start_page + 1:\
        (HEAP_PAGE_INT) ((((ADDRESS)(__pointer) - heap_base)) / PAGE_4KB_SIZE)
    

typedef struct {
    VMM_FREE_MEM_CALLBACK_FUNC callback_func;
    void* context;
} FREE_MEM_CALLBACK_DESC;

#define HEAP_MAX_NUM_OF_RECORDED_CALLBACKS 20

static HEAP_PAGE_DESCRIPTOR *heap_array;
static ADDRESS              heap_base;    // address at which the heap is located
static HEAP_PAGE_INT        heap_total_pages;  // actual number of pages
static UINT32               heap_total_size = 0;
static VMM_LOCK             heap_lock;
static FREE_MEM_CALLBACK_DESC free_mem_callbacks[HEAP_MAX_NUM_OF_RECORDED_CALLBACKS];
static UINT32 num_of_registered_callbacks = 0;

static HEAP_PAGE_INT        heap_pages = 0;
static ADDRESS              ex_heap_base = 0;
static HEAP_PAGE_INT        ex_heap_pages = 0;
static HEAP_PAGE_INT        ex_heap_start_page = 0;
static HEAP_PAGE_INT        max_used_pages = 0;

extern UINT32 g_heap_pa_num;

HEAP_PAGE_INT vmm_heap_get_total_pages(void)
{
    return heap_total_pages;
}


// FUNCTION : vmm_heap_get_max_used_pages()
// PURPOSE  : Returns the max amount of uVmm heap pages used
//            from post-launch vmm
// ARGUMENTS:
// RETURNS  : HEAP max heap used in pages
HEAP_PAGE_INT vmm_heap_get_max_used_pages(void)
{
    return max_used_pages;
}


// FUNCTION : vmm_heap_initialize()
// PURPOSE  : Partition memory for memory allocation / free services.
//          : Calculate actual number of pages.
// ARGUMENTS: IN ADDRESS heap_buffer_address - address at which the heap is located
//          : IN size_t    heap_buffer_size - in bytes
// RETURNS  : Last occupied address
ADDRESS vmm_heap_initialize(
    IN ADDRESS heap_buffer_address,
    IN size_t  heap_buffer_size)
{
    ADDRESS unaligned_heap_base;
    HEAP_PAGE_INT number_of_pages;
    HEAP_PAGE_INT i;

    // to be on the safe side
    heap_buffer_address = ALIGN_FORWARD(heap_buffer_address, sizeof(ADDRESS));

    // record total size of whole heap area
    heap_total_size = (UINT32)ALIGN_FORWARD(heap_buffer_size, PAGE_4KB_SIZE);

    // heap descriptors placed at the beginning
    heap_array = (HEAP_PAGE_DESCRIPTOR *) heap_buffer_address;

    // calculate how many unaligned pages we can support
    number_of_pages = (HEAP_PAGE_INT) ((heap_buffer_size + (g_heap_pa_num * PAGE_4KB_SIZE))
                              / (PAGE_4KB_SIZE + sizeof(HEAP_PAGE_DESCRIPTOR)));
    ex_heap_start_page = number_of_pages + 1;
    VMM_LOG(mask_anonymous, level_trace,"HEAP INIT: number_of_pages = %d\n", number_of_pages);

    // heap_base can start immediately after the end of heap_array
    unaligned_heap_base = (ADDRESS) &heap_array[number_of_pages];

    // but on the 1st 4K boundary address
    heap_base = ALIGN_FORWARD(unaligned_heap_base, PAGE_4KB_SIZE);    // here 4K pages start
    //VMM_LOG(mask_anonymous, level_trace,"HEAP INIT: heap_base is at %P\n", heap_base);

    // decrement heap size, due to descriptor allocation and alignment
    heap_buffer_size -= heap_base - heap_buffer_address;

    //VMM_LOG(mask_anonymous, level_trace,"HEAP INIT: heap_buffer_size = %P\n", heap_buffer_size);

    // now we can get actual number of available 4K pages
    heap_total_pages = (HEAP_PAGE_INT) (heap_buffer_size / PAGE_4KB_SIZE);
    heap_pages = heap_total_pages;
    VMM_LOG(mask_anonymous, level_trace,"HEAP INIT: heap_total_pages = %P\n", heap_total_pages);

    // BEFORE_VMLAUNCH. Can't hit this condition in POSTLAUNCH. Keep the
    // ASSERT for now.
    VMM_ASSERT(heap_total_pages > 0);

    for (i = 0; i < heap_total_pages ; ++i) {
        heap_array[i].in_use = 0;
        heap_array[i].number_of_pages = (heap_total_pages - i);
    }

    //VMM_DEBUG_CODE(vmm_heap_show());
    lock_initialize(&heap_lock);
    return heap_base + (heap_total_pages * PAGE_4KB_SIZE);

}


// FUNCTION : vmm_heap_extend()
// PURPOSE  : Extend the heap to an additional memory block 
//                      : update actual number of pages.
// ARGUMENTS:IN ADDRESS ex_heap_base_address - address at which the heap is located
//          : size_t    ex_heap_size - in bytes
// RETURNS  : Last occupied address
ADDRESS vmm_heap_extend( IN ADDRESS ex_heap_buffer_address,
    IN size_t  ex_heap_buffer_size)
{
    size_t  heap_buffer_size;
    HEAP_PAGE_INT i;

    lock_acquire(&heap_lock);

    VMM_LOG(mask_anonymous, level_print_always,"HEAP EXT: Max Used Initial Memory %dKB\n", (max_used_pages * 4));    
    // extend can be called only once.
    // BEFORE_VMLAUNCH
    VMM_ASSERT(ex_heap_base == 0);
    
    // extended heap cannot overlap with previous heap 
    // BEFORE_VMLAUNCH
    VMM_ASSERT(!CHECK_ADDRESS_IN_RANGE(ex_heap_buffer_address, heap_array, heap_total_size));
    // BEFORE_VMLAUNCH
    VMM_ASSERT(!CHECK_ADDRESS_IN_RANGE(heap_array, ex_heap_buffer_address, ex_heap_buffer_size));

    ex_heap_base = ALIGN_FORWARD(ex_heap_buffer_address, sizeof(ADDRESS));

    // record total size of whole heap area
    heap_total_size += (UINT32)ALIGN_FORWARD(ex_heap_buffer_size, PAGE_4KB_SIZE);

    heap_buffer_size = ex_heap_buffer_size - (ex_heap_base - ex_heap_buffer_address);
    
    // leave one dummy page for boundry which is always marked as used.
    ex_heap_pages = (HEAP_PAGE_INT) (heap_buffer_size / PAGE_4KB_SIZE) + 1;
    
    ex_heap_start_page = heap_total_pages;
    heap_total_pages += ex_heap_pages;

    // BEFORE_VMLAUNCH
    VMM_ASSERT(heap_total_pages > 0);

    heap_array[ex_heap_start_page].in_use = 1;
    heap_array[ex_heap_start_page].number_of_pages = 1;

    for (i = ex_heap_start_page + 1; i < heap_total_pages ; ++i) {
        heap_array[i].in_use = 0;
        heap_array[i].number_of_pages = (heap_total_pages - i);
    }
    
    lock_release(&heap_lock);
    return ex_heap_base + (ex_heap_pages * PAGE_4KB_SIZE);

}

#if defined ENABLE_VTD_KEEP_CODE && defined ENABLE_VTD || defined DEBUG
void vmm_heap_get_details(OUT HVA* base_addr, OUT UINT32* size) {
    *base_addr = (HVA)heap_array;
    *size = heap_total_size;
}
#endif

static void * page_alloc_unprotected(
#ifdef DEBUG
    char *file_name,
    INT32 line_number,
#endif
    HEAP_PAGE_INT number_of_pages)
{
    HEAP_PAGE_INT i;
    HEAP_PAGE_INT allocated_page_no;
    void *p_buffer = NULL;

    if (number_of_pages == 0) {
        return NULL;
    }

    for (i = 0; i < heap_total_pages ; ++i) {
        if ((0 == heap_array[i].in_use) && (number_of_pages <= heap_array[i].number_of_pages)) {
            VMM_ASSERT((i + heap_array[i].number_of_pages) <= heap_total_pages); // validity check

            // found the suitable buffer
            allocated_page_no = i;
            p_buffer = HEAP_PAGE_TO_POINTER(allocated_page_no);
            heap_array[allocated_page_no].in_use = 1;
            heap_array[allocated_page_no].number_of_pages = number_of_pages;
#ifdef DEBUG
            heap_array[i].file_name = file_name;
            heap_array[i].line_number = line_number;
#endif
            // mark next number_of_pages-1 pages as in_use
            for (i = allocated_page_no + 1; i < (allocated_page_no + number_of_pages); ++i) {
                heap_array[i].in_use = 1;
                heap_array[i].number_of_pages = 0;
            }
           
            if (max_used_pages < (allocated_page_no + number_of_pages))  
                max_used_pages = allocated_page_no + number_of_pages;
            break;    // leave the outer loop
        }
    }

    if (NULL == p_buffer) {
        VMM_LOG(mask_anonymous, level_trace,"ERROR: (%s %d)  Failed to allocate %d pages\n", __FILE__, __LINE__, number_of_pages );
    }

    TMSL_PROFILING_MEMORY_ALLOC((UINT64)p_buffer, number_of_pages * PAGE_4KB_SIZE, PROF_MEM_CONTEXT_TMSL);
    return p_buffer;
}


// FUNCTION : vmm_page_allocate()
// PURPOSE  : Allocates contiguous buffer of given size, and fill it with zeroes
// ARGUMENTS: IN HEAP_PAGE_INT number_of_pages - size of the buffer in 4K pages
// RETURNS  : void*  address of allocted buffer if OK, NULL if failed
void* vmm_page_allocate(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    IN HEAP_PAGE_INT number_of_pages)
{
    void *p_buffer = NULL;

    lock_acquire(&heap_lock);
    p_buffer = page_alloc_unprotected(
#ifdef DEBUG
                     file_name, line_number,
#endif
                     number_of_pages);
    lock_release(&heap_lock);
    return p_buffer;
}


// FUNCTION : vmm_page_allocate_scattered()
// PURPOSE  : Fills given array with addresses of allocated 4K pages
// ARGUMENTS: IN HEAP_PAGE_INT number_of_pages - number of 4K pages
//          : OUT void * p_page_array[] - contains the addresses of allocated pages
// RETURNS  : number of successfully allocated pages
HEAP_PAGE_INT vmm_page_allocate_scattered(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    IN HEAP_PAGE_INT number_of_pages,
    OUT void * p_page_array[])
{
    HEAP_PAGE_INT i;
    HEAP_PAGE_INT number_of_allocated_pages;

    lock_acquire(&heap_lock);

    for (i = 0; i < number_of_pages; ++i) {
        p_page_array[i] = page_alloc_unprotected(
            #ifdef DEBUG
                                     file_name, line_number,
            #endif
                                     1);
        if (NULL == p_page_array[i]) {
            VMM_LOG(mask_anonymous, level_trace,"ERROR: (%s %d)  Failed to allocate pages %d..%d\n", __FILE__, __LINE__, i+1, number_of_pages);
            break;    // leave the loop
        }
    }
    lock_release(&heap_lock);

    number_of_allocated_pages = i;

    // fill the pages which failed to be allocated with NULLs
    for ( ; i < number_of_pages; ++i) {
        p_page_array[i] = NULL;
    }
    return number_of_allocated_pages;
}


static void vmm_mark_pages_free(
    HEAP_PAGE_INT page_from,
    HEAP_PAGE_INT page_to,
    HEAP_PAGE_INT pages_to_release)
{
    HEAP_PAGE_INT i;

    for (i = page_from; i < page_to; ++i) {
        heap_array[i].in_use = 0;
        heap_array[i].number_of_pages = pages_to_release - (i - page_from);
    }
}


// FUNCTION : vmm_page_free()
// PURPOSE  : Release previously allocated buffer
// ARGUMENTS: IN void *p_buffer - buffer to be released
// RETURNS  : void
void vmm_page_free(IN void *p_buffer)
{
    HEAP_PAGE_INT release_from_page_id;    // first page to release
    HEAP_PAGE_INT release_to_page_id;      // page next to last to release
    HEAP_PAGE_INT pages_to_release;        // num of pages, to be released
    ADDRESS address;

    address = (ADDRESS) (size_t) p_buffer;

    if (!(CHECK_ADDRESS_IN_RANGE(address, heap_base, heap_pages * PAGE_4KB_SIZE) ||
         CHECK_ADDRESS_IN_RANGE(address, ex_heap_base, ex_heap_pages * PAGE_4KB_SIZE)) ||
        (address & PAGE_4KB_MASK) != 0)
    {
        VMM_LOG(mask_anonymous, level_trace,"ERROR: (%s %d)  Buffer %p is out of heap space\n", __FILE__, __LINE__, p_buffer);
        // BEFORE_VMLAUNCH. MALLOC should not fail.
        VMM_DEADLOOP();
        return;
    }
    lock_acquire(&heap_lock);

    release_from_page_id = HEAP_POINTER_TO_PAGE(p_buffer);

    //VMM_LOG(mask_anonymous, level_trace,"HEAP: trying to free page_id %d\n", release_from_page_id);

    if (0 == heap_array[release_from_page_id].in_use ||
        0 == heap_array[release_from_page_id].number_of_pages) {
        VMM_LOG(mask_anonymous, level_trace,"ERROR: (%s %d)  Page %d is not in use\n", __FILE__, __LINE__, release_from_page_id);
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_DEADLOOP();
        return;
    }

    pages_to_release = heap_array[release_from_page_id].number_of_pages;

    // check if the next to the last released page is free
    // and if so merge both regions

    release_to_page_id = release_from_page_id + pages_to_release;

    if (release_to_page_id < heap_total_pages &&
        0 == heap_array[release_to_page_id].in_use  &&
        (release_to_page_id + heap_array[release_to_page_id].number_of_pages) <= heap_total_pages) {
        pages_to_release += heap_array[release_to_page_id].number_of_pages;
    }

    // move backward, to grab all free pages, trying to prevent fragmentation
    while (release_from_page_id > 0  &&
           0 == heap_array[release_from_page_id - 1].in_use &&
           0 != heap_array[release_from_page_id - 1].number_of_pages) // 3rd check is for sanity only
    {
        release_from_page_id--;
        pages_to_release++;
    }

    vmm_mark_pages_free(release_from_page_id, release_to_page_id, pages_to_release);

    lock_release(&heap_lock);
    TMSL_PROFILING_MEMORY_FREE((UINT64)p_buffer, PROF_MEM_CONTEXT_TMSL);
}

// FUNCTION : vmm_page_buff_size()
// PURPOSE  : Identify number of pages in previously allocated buffer
// ARGUMENTS: IN void *p_buffer - the buffer
// RETURNS  : UINT32 - Num pages this buffer is using
UINT32 vmm_page_buff_size(IN void *p_buffer)
{
    HEAP_PAGE_INT release_from_page_id;    // first page to release
    UINT32 num_pages;        // num of pages, to be released
    ADDRESS address;

    address = (ADDRESS) (size_t) p_buffer;

    if (!(CHECK_ADDRESS_IN_RANGE(address, heap_base, heap_pages * PAGE_4KB_SIZE) ||
         CHECK_ADDRESS_IN_RANGE(address, ex_heap_base, ex_heap_pages * PAGE_4KB_SIZE)) ||
        (address & PAGE_4KB_MASK) != 0) {
        VMM_LOG(mask_anonymous, level_trace,"ERROR: (%s %d)  Buffer %p is out of heap space\n", __FILE__, __LINE__, p_buffer);
        VMM_DEADLOOP();
        return 0;
    }

    release_from_page_id = HEAP_POINTER_TO_PAGE(p_buffer);

    //VMM_LOG(mask_anonymous, level_trace,"HEAP: trying to free page_id %d\n", release_from_page_id);

    if (0 == heap_array[release_from_page_id].in_use ||
        0 == heap_array[release_from_page_id].number_of_pages) {
        VMM_LOG(mask_anonymous, level_trace,"ERROR: (%s %d)  Page %d is not in use\n", __FILE__, __LINE__, release_from_page_id);
        VMM_DEADLOOP();
        return 0;
    }

    num_pages = (UINT32) heap_array[release_from_page_id].number_of_pages;
    return num_pages;
}


// FUNCTION : vmm_memory_allocate()
// PURPOSE  : Allocates contiguous buffer of given size, filled with zeroes
// ARGUMENTS: IN UINT32 size - size of the buffer in bytes
// RETURNS  : void*  address of allocted buffer if OK, NULL if failed
void* vmm_memory_allocate(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    IN UINT32 size)
{
    void *p_buffer = NULL;

    if (size == 0) {
        return NULL;
    }
    size = (UINT32) ALIGN_FORWARD(size, PAGE_4KB_SIZE);
    p_buffer = vmm_page_allocate(
#ifdef DEBUG
                            file_name,
                            line_number,
#endif
                            (HEAP_PAGE_INT) (size / PAGE_4KB_SIZE));
    if (NULL != p_buffer) {
        vmm_memset(p_buffer, 0, size);
    }
    return p_buffer;
}

#ifdef ENABLE_VTLB
HEAP_ALLOC_HANDLE vmm_heap_register_free_mem_callback(VMM_FREE_MEM_CALLBACK_FUNC callback_func, void* context) {
    UINT32 free_index;
    if (num_of_registered_callbacks == HEAP_MAX_NUM_OF_RECORDED_CALLBACKS) {
        return HEAP_INVALID_ALLOC_HANDLE;
    }

    free_index = num_of_registered_callbacks;
    num_of_registered_callbacks++;

    free_mem_callbacks[free_index].callback_func = callback_func;
    free_mem_callbacks[free_index].context = context;
    return (HEAP_ALLOC_HANDLE)free_index;
}
#endif

void* vmm_memory_allocate_must_succeed(
#ifdef DEBUG
    char    *file_name,
    INT32   line_number,
#endif
    HEAP_ALLOC_HANDLE handle,
    UINT32 size) {
    void* allcated_mem = vmm_memory_allocate(
    #ifdef DEBUG
                                          file_name,
                                          line_number,
    #endif
                                          size);
    UINT32 request_owner = (UINT32)handle;

    if (allcated_mem == NULL) {
        UINT32 i;

        for (i = 0; i < num_of_registered_callbacks; i++) {
            if (i == request_owner) {
                continue;
            }

            free_mem_callbacks[i].callback_func(free_mem_callbacks[i].context);
        }

        allcated_mem = vmm_memory_allocate(
#ifdef DEBUG
                                           file_name,
                                           line_number,
#endif
                                           size);
        // BEFORE_VMLAUNCH. Must succeed.
        VMM_ASSERT(allcated_mem != NULL);
    }
    return allcated_mem;
}



#ifdef DEBUG

void vmm_heap_show(void)
{
    HEAP_PAGE_INT i;

    VMM_LOG(mask_anonymous, level_trace,"Heap Show: total_pages=%d\n", heap_total_pages);
    VMM_LOG(mask_anonymous, level_trace,"---------------------\n");

    for (i = 0; i < heap_total_pages; ) {
        VMM_LOG(mask_anonymous, level_trace,"Pages %d..%d ", i, i + heap_array[i].number_of_pages - 1);

        if (heap_array[i].in_use) {
            VMM_LOG(mask_anonymous, level_trace,"allocated in %s line=%d\n", heap_array[i].file_name, heap_array[i].line_number);
        }
        else {
            VMM_LOG(mask_anonymous, level_trace,"free\n");
        }

        i += heap_array[i].number_of_pages;
    }
    VMM_LOG(mask_anonymous, level_trace,"---------------------\n");
}
#endif

