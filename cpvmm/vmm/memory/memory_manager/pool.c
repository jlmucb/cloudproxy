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

#include <pool_api.h>
#include <hash64_api.h>
#include <heap.h>
#include <common_libc.h>
#include "pool.h"
#include "vmm_dbg.h"
#include "file_codes.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(POOL_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(POOL_C, __condition)

#pragma warning(disable : 4710)
#pragma warning (disable : 4101 4189)

// Get Release Mutual exclussion lock macros.
#define POOL_AQUIRE_LOCK(_pool_)             \
do                                           \
{                                            \
    if ((_pool_)->mutex_flag)                \
        lock_acquire(&(_pool_)->access_lock); \
} while(0)


#define POOL_RELEASE_LOCK(_pool_)            \
do                                           \
{                                            \
    if ((_pool_)->mutex_flag)                \
        lock_release(&(_pool_)->access_lock); \
} while(0)


static void pool_insert_node_into_list(POOL_LIST_HEAD* list_head, 
                    POOL_LIST_ELEMENT* element);


INLINE UINT64 pool_ptr_to_uint64(void* ptr) {
    return (UINT64)ptr;
}

INLINE void* pool_uint64_to_ptr(UINT64 value) {
    return (void*)value;
}

INLINE void pool_init_list_head(POOL_LIST_HEAD* list_head) {
    pool_list_head_set_first_element(list_head, NULL);
    pool_list_head_set_last_element(list_head, NULL);
    pool_list_head_set_num_of_elements(list_head, 0);
}

INLINE BOOLEAN pool_is_list_empty(const POOL_LIST_HEAD* list_head) {
    BOOLEAN res = (pool_list_head_get_num_of_elements(list_head) == 0);
    VMM_ASSERT((!res) || (pool_list_head_get_first_element(list_head) == NULL));
    VMM_ASSERT((!res) || (pool_list_head_get_last_element(list_head) == NULL));
    return res;
}

INLINE void pool_allocate_single_page_from_heap(POOL* pool) {
    void* page = vmm_page_alloc(1);
    UINT32 num_of_allocated_pages = pool_get_num_of_allocated_pages(pool);
    POOL_LIST_HEAD* free_pages_list = pool_get_free_pages_list(pool);

    if (page != NULL) {
        num_of_allocated_pages++;
        pool_set_num_of_allocated_pages(pool, num_of_allocated_pages);

        pool_insert_node_into_list(free_pages_list, (POOL_LIST_ELEMENT*)page);
    }
}


INLINE UINT32 pool_calculate_number_of_new_pages_to_allocate(POOL* pool) {
    UINT32 num_of_allocated_pages = pool_get_num_of_allocated_pages(pool);
    UINT32 num = (num_of_allocated_pages / POOL_PAGES_TO_ALLOCATE_THRESHOLD);

    if (num > POOL_MAX_NUM_OF_PAGES_TO_ALLOCATE) {
        num = POOL_MAX_NUM_OF_PAGES_TO_ALLOCATE;
    }
    else if (num == 0) {
        num = POOL_PAGES_TO_KEEP_THRESHOLD;
    }
    return num;
}


#ifdef INCLUDE_UNUSED_CODE
static BOOLEAN pool_is_element_in_list(POOL_LIST_HEAD* list_head, 
                POOL_LIST_ELEMENT* element) {
    POOL_LIST_ELEMENT* curr_elem = pool_list_head_get_first_element(list_head);

    while (curr_elem != NULL) {
        if (curr_elem == element) {
            return TRUE;
        }
        curr_elem = pool_list_element_get_next(curr_elem);
    }
    return FALSE;
}

static BOOLEAN pool_is_list_consistent(POOL_LIST_HEAD* list_head) {
    UINT32 counter = 0;
    POOL_LIST_ELEMENT* element = pool_list_head_get_first_element(list_head);
    BOOLEAN all_remaining_must_be_aligned = FALSE;

    while (element != NULL) {
        UINT64 element_addr = pool_ptr_to_uint64(element);

        if (ALIGN_BACKWARD(element_addr, PAGE_4KB_SIZE) == element_addr) {
            all_remaining_must_be_aligned = TRUE;
        }
        else if (all_remaining_must_be_aligned) {
            return FALSE;
        }
        counter++;
        element = pool_list_element_get_next(element);
    }
    return (counter == pool_list_head_get_num_of_elements(list_head));
}
#endif

static BOOLEAN pool_is_allocation_counters_ok(POOL* pool) {
    UINT32 allocated_num;
    allocated_num = pool_get_num_of_pages_used_for_hash_nodes(pool) +
                    pool_get_num_of_pages_used_for_pool_elements(pool) +
                    pool_list_head_get_num_of_elements(pool_get_free_pages_list(pool));
    return (pool_get_num_of_allocated_pages(pool) == allocated_num);
}


static POOL_LIST_ELEMENT* pool_allocate_node_from_list(POOL_LIST_HEAD* list_head) {
    POOL_LIST_ELEMENT* first_element;
    POOL_LIST_ELEMENT* second_element;
    UINT32 num_of_elements;

    VMM_ASSERT(!pool_is_list_empty(list_head));
    first_element = pool_list_head_get_first_element(list_head);
    VMM_ASSERT(first_element != NULL);
    second_element = pool_list_element_get_next(first_element);
    if (second_element != NULL) {
        pool_list_element_set_prev(second_element, NULL);
    }

    pool_list_head_set_first_element(list_head, second_element);
    if (second_element == NULL) {
        pool_list_head_set_last_element(list_head, NULL);
    }
    num_of_elements = pool_list_head_get_num_of_elements(list_head);
    pool_list_head_set_num_of_elements(list_head, num_of_elements - 1);
    return first_element;

}

static void pool_insert_node_into_list_at_tail(POOL_LIST_HEAD* list_head, 
            POOL_LIST_ELEMENT* element) {
    UINT32 num_of_elements;
    POOL_LIST_ELEMENT* curr_last_element;

    curr_last_element = pool_list_head_get_last_element(list_head);
    if (curr_last_element != NULL) {
        pool_list_element_set_next(curr_last_element, element);
    }
    else {
        VMM_ASSERT(pool_list_head_get_first_element(list_head) == NULL);
        pool_list_head_set_first_element(list_head, element);
    }

    pool_list_element_set_prev(element, curr_last_element);
    pool_list_element_set_next(element, NULL);
    pool_list_head_set_last_element(list_head, element);

    num_of_elements = pool_list_head_get_num_of_elements(list_head);
    num_of_elements++;
    pool_list_head_set_num_of_elements(list_head, num_of_elements);

    VMM_ASSERT(pool_list_head_get_last_element(list_head) == element);
}

static void pool_insert_node_into_list(POOL_LIST_HEAD* list_head, 
            POOL_LIST_ELEMENT* element) {
    UINT32 num_of_elements;
    POOL_LIST_ELEMENT* curr_first_element;

    curr_first_element = pool_list_head_get_first_element(list_head);
    if (curr_first_element != NULL) {
        pool_list_element_set_prev(curr_first_element, element);
    }
    else {
        VMM_ASSERT(pool_list_head_get_last_element(list_head) == NULL);
        pool_list_head_set_last_element(list_head, element);
    }

    pool_list_element_set_next(element, curr_first_element);
    pool_list_element_set_prev(element, NULL);
    pool_list_head_set_first_element(list_head, element);
    num_of_elements = pool_list_head_get_num_of_elements(list_head);
    num_of_elements++;
    pool_list_head_set_num_of_elements(list_head, num_of_elements);
    VMM_ASSERT(pool_list_head_get_first_element(list_head) == element);
}

static void pool_remove_element_from_the_list(POOL_LIST_HEAD* list_head,
                                       POOL_LIST_ELEMENT* element) {
    UINT32 num_of_elements;

    VMM_ASSERT(!pool_is_list_empty(list_head));
    if (pool_list_head_get_first_element(list_head) == element) {
        POOL_LIST_ELEMENT* next_element = pool_list_element_get_next(element);
        if (next_element != NULL) {
            pool_list_element_set_prev(next_element, NULL);
        }
        else {
            VMM_ASSERT(pool_list_head_get_last_element(list_head) == element);
            pool_list_head_set_last_element(list_head , NULL);
        }
        pool_list_head_set_first_element(list_head, next_element);
    }
    else if (pool_list_head_get_last_element(list_head) == element) {
        POOL_LIST_ELEMENT* prev_element = pool_list_element_get_prev(element);
        VMM_ASSERT(prev_element != NULL);
        pool_list_element_set_next(prev_element, NULL);
        pool_list_head_set_last_element(list_head, prev_element);
    }
    else {
        POOL_LIST_ELEMENT* prev_element = pool_list_element_get_prev(element);
        POOL_LIST_ELEMENT* next_element = pool_list_element_get_next(element);

        VMM_ASSERT(prev_element != NULL);
        VMM_ASSERT(next_element != NULL);
        pool_list_element_set_next(prev_element, next_element);
        pool_list_element_set_prev(next_element, prev_element);
    }
    num_of_elements = pool_list_head_get_num_of_elements(list_head);
    num_of_elements--;
    pool_list_head_set_num_of_elements(list_head, num_of_elements);
}

static void pool_free_nodes_in_page_from_list(POOL_LIST_HEAD* list_head,
                        UINT32 size_of_element, void* page) {
    UINT64 page_addr = (UINT64)page;
    UINT32 covered_size;
    UINT32 counter = 0;

    for (covered_size = 0; covered_size < (PAGE_4KB_SIZE - size_of_element + 1); 
                           covered_size += size_of_element) {
        UINT64 curr_element_addr = page_addr + covered_size;
        POOL_LIST_ELEMENT* element = (POOL_LIST_ELEMENT*)
                                pool_uint64_to_ptr(curr_element_addr);
        pool_remove_element_from_the_list(list_head, element);
        counter++;
    }
}

static void pool_allocate_several_pages_from_heap(POOL* pool) {
    void* pages[POOL_MAX_NUM_OF_PAGES_TO_ALLOCATE];
    POOL_LIST_HEAD* free_pages_list = pool_get_free_pages_list(pool);
    UINT32 i;
    UINT32 requested_num_of_pages = pool_calculate_number_of_new_pages_to_allocate(pool);
    UINT32 num_of_pages;
    UINT32 num_of_allocated_pages;

    VMM_ASSERT(requested_num_of_pages <= POOL_MAX_NUM_OF_PAGES_TO_ALLOCATE);
    num_of_pages = vmm_page_alloc_scattered(requested_num_of_pages, pages);
    VMM_ASSERT(num_of_pages <= requested_num_of_pages);

    for (i = 0; i < num_of_pages; i++) {
        void* curr_page = pages[i];

        pool_insert_node_into_list(free_pages_list, (POOL_LIST_ELEMENT*)curr_page);
    }

    num_of_allocated_pages = pool_get_num_of_allocated_pages(pool);
    num_of_allocated_pages += num_of_pages;
    pool_set_num_of_allocated_pages(pool, num_of_allocated_pages);
}

static void pool_free_several_pages_into_heap(POOL* pool, 
                    UINT32 num_of_pages_to_free) {
    POOL_LIST_HEAD* free_pages_list = pool_get_free_pages_list(pool);
    UINT32 num_of_freed_pages = 0;
    UINT32 num_of_allocated_pages;

    while ((!pool_is_list_empty(free_pages_list)) &&
            (num_of_pages_to_free > 0)) {

        void* page = (void*)pool_allocate_node_from_list(free_pages_list);
        vmm_page_free(page);
        num_of_freed_pages++;
        num_of_pages_to_free--;
    }

    num_of_allocated_pages = pool_get_num_of_allocated_pages(pool);
    VMM_ASSERT(num_of_allocated_pages >= num_of_freed_pages);
    num_of_allocated_pages -= num_of_freed_pages;
    pool_set_num_of_allocated_pages(pool, num_of_allocated_pages);
}

static BOOLEAN pool_is_power_of_2(UINT32 value)
{
    return (value > 1 && IS_POW_OF_2(value)) ? TRUE : FALSE;
}


static void pool_split_page_to_elements(POOL_LIST_HEAD* list_head,
                     UINT32 size_of_element, void* page) {
    UINT32 covered_size = size_of_element; // start from the second element
    UINT32 num_of_elements = PAGE_4KB_SIZE / size_of_element;
    UINT64 page_addr = (UINT64)page;
    POOL_LIST_ELEMENT* first_element = (POOL_LIST_ELEMENT*)page;
    UINT64 last_element_addr;
    POOL_LIST_ELEMENT* last_element;
    UINT32 i;
    UINT32 num_of_elements_in_list;

    VMM_ASSERT(num_of_elements > 0);
    pool_list_element_set_prev(first_element, NULL);
    for (i = 1; i < num_of_elements; i++) {
        UINT64 curr_element_addr = page_addr + covered_size;
        UINT64 prev_element_addr = curr_element_addr - size_of_element;
        POOL_LIST_ELEMENT* curr_element = (POOL_LIST_ELEMENT*)pool_uint64_to_ptr(curr_element_addr);
        POOL_LIST_ELEMENT* prev_element = (POOL_LIST_ELEMENT*)pool_uint64_to_ptr(prev_element_addr);
        pool_list_element_set_next(prev_element, curr_element);
        pool_list_element_set_prev(curr_element, prev_element);
        covered_size += size_of_element;
    }

    last_element_addr = page_addr + covered_size - size_of_element;
    last_element = (POOL_LIST_ELEMENT*)pool_uint64_to_ptr(last_element_addr);

    if (pool_is_list_empty(list_head)) {
        pool_list_head_set_last_element(list_head, last_element);
    }
    pool_list_element_set_next(last_element, pool_list_head_get_first_element(list_head));
    pool_list_head_set_first_element(list_head, first_element);

    num_of_elements_in_list = pool_list_head_get_num_of_elements(list_head);
    num_of_elements_in_list += num_of_elements;
    pool_list_head_set_num_of_elements(list_head, num_of_elements_in_list);
}


static UINT32 pool_hash_func(UINT64 key, UINT32 size) {
    UINT32 hash_mask = (size - 1);
    UINT64 index_tmp;

    VMM_ASSERT(pool_is_power_of_2(size));
    VMM_ASSERT(ALIGN_BACKWARD(key, PAGE_4KB_SIZE) == key);
    index_tmp = ((key >> 12) & hash_mask);
    return (UINT32)index_tmp;
}


static void pool_allocate_single_page_from_heap_with_must_succeed(POOL* pool) {
    void* page;
    UINT32 num_of_allocated_pages;
    POOL_LIST_HEAD* free_pages_list = pool_get_free_pages_list(pool);

    page = vmm_memory_alloc_must_succeed(pool_get_must_succeed_alloc_handle(pool), PAGE_4KB_SIZE);
    if (page == NULL) {
        return;
    }
    pool_insert_node_into_list(free_pages_list, (POOL_LIST_ELEMENT*)page);
    num_of_allocated_pages = pool_get_num_of_allocated_pages(pool);
    num_of_allocated_pages++;
    pool_set_num_of_allocated_pages(pool, num_of_allocated_pages);
}

static void pool_try_to_free_unused_page_from_elements_list(POOL* pool, 
                BOOLEAN full_clean) {
    POOL_LIST_HEAD* free_pages_list = pool_get_free_pages_list(pool);
    POOL_LIST_HEAD* free_pool_elements_list = pool_get_free_pool_elements_list(pool);
    HASH64_HANDLE hash = pool_get_hash(pool);
    POOL_LIST_ELEMENT* node;
    UINT32 size_of_element = pool_get_size_of_single_element(pool);
    UINT32 num_of_elements_per_page = pool_get_num_of_elements_per_page(pool);

    node = pool_list_head_get_last_element(free_pool_elements_list);
    while (node != NULL) {
        POOL_LIST_ELEMENT* prev_node = pool_list_element_get_prev(node);
        UINT64 node_addr = pool_ptr_to_uint64(node);
        UINT64 num_of_elements;
        BOOLEAN res;

        if (ALIGN_BACKWARD(node_addr, PAGE_4KB_SIZE) != node_addr) {
            // arrived to non aligned elements;
            break;
        }
        res = (BOOLEAN)hash64_lookup(hash, node_addr, &num_of_elements);
        VMM_ASSERT(res);
        if (num_of_elements == num_of_elements_per_page) {
            res = (BOOLEAN)hash64_remove(hash, node_addr);
            VMM_ASSERT(res);
            pool_free_nodes_in_page_from_list(free_pool_elements_list, size_of_element, node);
            pool_insert_node_into_list(free_pages_list, node);
            pool_dec_num_of_pages_used_for_pool_elements(pool);
            if (!full_clean) {
                break;
            }
        }
        node = prev_node;
    }
}

static void* pool_allocate_hash_node(void* context) {
    POOL* pool = (POOL*)context;
    HASH64_HANDLE hash = pool_get_hash(pool);
    POOL_LIST_HEAD* hash_elements_list_head = pool_get_free_hash_elements_list(pool);

    if (pool_get_hash_element_to_allocate(pool) != NULL) {
        POOL_LIST_ELEMENT* free_element = pool_get_hash_element_to_allocate(pool);
        pool_set_hash_element_to_allocate(pool, NULL);
        return free_element;
    }

    if (!pool_is_list_empty(hash_elements_list_head)) {
        POOL_LIST_ELEMENT* free_element;
        UINT64 free_element_u64;
        UINT64 page_addr;
        UINT64 element_counter;
        BOOLEAN res;

        free_element = pool_allocate_node_from_list(hash_elements_list_head);
        VMM_ASSERT(free_element != NULL);
        free_element_u64 = (UINT64)free_element;
        page_addr = ALIGN_BACKWARD(free_element_u64, PAGE_4KB_SIZE);

        res = hash64_lookup(hash, page_addr, &element_counter);
        VMM_ASSERT(res);

        VMM_ASSERT(element_counter > 0);
        element_counter--;

        if (!hash64_update(hash, page_addr, element_counter)) {
            VMM_ASSERT(0);
            return NULL;
        }
        return free_element;
    }
    else {
        // Pool is empty
        POOL_LIST_HEAD* free_pages_list_head = pool_get_free_pages_list(pool);
        void* free_page = NULL;
        UINT64 free_page_addr;
        UINT32 num_of_hash_elements;
        UINT32 size_of_hash_element;
        POOL_LIST_ELEMENT* free_element;
        UINT64 element_counter_tmp;

        if (pool_is_list_empty(free_pages_list_head)) {
            pool_try_to_free_unused_page_from_elements_list(pool, FALSE);
            if (pool_is_list_empty(free_pages_list_head)) {
                pool_allocate_single_page_from_heap(pool);
                if (pool_is_list_empty(free_pages_list_head)) {
                    if (!pool_is_must_succeed_allocation(pool)) {
                        return NULL;
                    }
                    pool_allocate_single_page_from_heap_with_must_succeed(pool);
                    if (pool_is_list_empty(free_pages_list_head)) {
                        VMM_ASSERT(0);
                        return NULL;
                    }
                }
            }
        }

        free_page = pool_allocate_node_from_list(free_pages_list_head);
        pool_inc_num_of_pages_used_for_hash_nodes(pool);
        VMM_ASSERT(free_page != NULL);

        free_page_addr = (UINT64)free_page;
        VMM_ASSERT(ALIGN_BACKWARD(free_page_addr, PAGE_4KB_SIZE) == free_page_addr);
        VMM_ASSERT(!hash64_lookup(hash, free_page_addr, &element_counter_tmp));
        size_of_hash_element = pool_get_size_of_hash_element(pool);
        pool_split_page_to_elements(hash_elements_list_head, size_of_hash_element, free_page);
        VMM_ASSERT(!pool_is_list_empty(hash_elements_list_head));

        // number of elements currently in the list
        num_of_hash_elements = pool_list_head_get_num_of_elements(hash_elements_list_head);
        VMM_ASSERT(num_of_hash_elements > 2);

        // Allocating 2 elements: first in order to record current page and second
        // in order to return the requested element
        num_of_hash_elements -= 2;

        // Allocate element for allocated page
        free_element = pool_allocate_node_from_list(hash_elements_list_head);

        // Must be first element of the page
        VMM_ASSERT((UINT64)free_element == free_page_addr);

        // Cache this element for the following insert into hash
        pool_set_hash_element_to_allocate(pool, free_element);

        // Record the page
        if (!hash64_insert(hash, free_page_addr, num_of_hash_elements)) {
            VMM_ASSERT(0); // should not be here
            return NULL;
        }
        VMM_ASSERT(pool_get_hash_element_to_allocate(pool) == NULL);

        // Allocate the requested element
        free_element = pool_allocate_node_from_list(hash_elements_list_head);
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
        return free_element;
    }
}

static void pool_free_hash_node(void* context, void* element) {
    POOL* pool = (POOL*)context;
    HASH64_HANDLE hash = pool_get_hash(pool);
    POOL_LIST_HEAD* hash_elements_list_head = pool_get_free_hash_elements_list(pool);
    POOL_LIST_ELEMENT* hash_element = (POOL_LIST_ELEMENT*)element;
    UINT64 num_of_elements = 0;
    UINT64 element_addr = pool_ptr_to_uint64(element);
    UINT64 page_addr = ALIGN_BACKWARD(element_addr, PAGE_4KB_SIZE);
    BOOLEAN res;

    if (page_addr == element_addr) {
        // The first node always describes the page of hash nodes
        UINT64 num_of_elements_tmp;
        // insert first node in the page to the tail
        pool_insert_node_into_list_at_tail(hash_elements_list_head, hash_element);

        // Make sure that hash doesn't contain node for the page
        VMM_ASSERT(!hash64_lookup(hash, page_addr, &num_of_elements_tmp));
        return;
    }

    pool_insert_node_into_list(hash_elements_list_head, hash_element);
    res = (BOOLEAN)hash64_lookup(hash, page_addr, &num_of_elements);
    VMM_ASSERT(res);
    num_of_elements++;

    if (num_of_elements < (pool_get_num_of_hash_elements_per_page(pool) - 1)) {
        res = hash64_update(hash, page_addr, num_of_elements);
        VMM_ASSERT(res);
    }
    else {
        void* page = pool_uint64_to_ptr(page_addr);

        res = hash64_remove(hash, page_addr);
        VMM_ASSERT(res);

        pool_free_nodes_in_page_from_list(pool_get_free_hash_elements_list(pool),
                                          pool_get_size_of_hash_element(pool),
                                          page);
        pool_insert_node_into_list(pool_get_free_pages_list(pool), page);
        pool_dec_num_of_pages_used_for_hash_nodes(pool);
    }
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
}

static UINT32 pool_get_num_of_pages_to_free_to_heap(POOL* pool) {
    UINT32 num_of_allocated_pages = pool_get_num_of_allocated_pages(pool);
    POOL_LIST_HEAD* free_pages_list = pool_get_free_pages_list(pool);
    UINT32 num_of_free_pages = pool_list_head_get_num_of_elements(free_pages_list);
    UINT32 num_of_pages_to_free = 0;

    if ((num_of_free_pages >= (num_of_allocated_pages / POOL_PAGES_TO_FREE_THRESHOLD)) &&
        (num_of_allocated_pages >= POOL_MIN_NUMBER_OF_FREE_PAGES)) {

        num_of_pages_to_free = (num_of_allocated_pages / POOL_PAGES_TO_FREE_THRESHOLD);
    }
    if ((num_of_free_pages - num_of_pages_to_free) > POOL_MAX_NUM_OF_PAGES_TO_ALLOCATE) {
        num_of_pages_to_free = num_of_free_pages - POOL_MAX_NUM_OF_PAGES_TO_ALLOCATE;
    }
    return num_of_pages_to_free;
}

static void pool_report_alloc_free_op(POOL* pool) {
    pool_inc_alloc_free_ops_counter(pool);
    if (pool_get_alloc_free_ops_counter(pool) >= POOL_FREE_UNUSED_PAGES_THRESHOLD) {
        UINT32 num_of_pages_to_free;

        pool_clear_alloc_free_ops_counter(pool);
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
        pool_try_to_free_unused_page_from_elements_list(pool, FALSE);
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
        num_of_pages_to_free = pool_get_num_of_pages_to_free_to_heap(pool);
        if (num_of_pages_to_free > 0) {
            pool_free_several_pages_into_heap(pool, num_of_pages_to_free);
        }
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    }
}

static void* pool_allocate_internal(POOL* pool) {
    HASH64_HANDLE   hash = pool_get_hash(pool);
    POOL_LIST_HEAD* free_pool_elements_list = pool_get_free_pool_elements_list(pool);
    POOL_LIST_HEAD* free_pages_list;
    void*           page;
    UINT64          page_addr;
    void*           element;
    UINT64          num_of_elements;
    BOOLEAN         res;
    UINT64          num_of_elements_tmp;

#ifdef JLMDEBUG1
    bprint("pool_allocate_internal\n");
#endif
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    pool_report_alloc_free_op(pool);
    if (!pool_is_list_empty(free_pool_elements_list)) {
        UINT64 elem_addr;

        element = (void*)pool_allocate_node_from_list(free_pool_elements_list);
        VMM_ASSERT(element != NULL);
        elem_addr = (UINT64)element;
        page_addr = ALIGN_BACKWARD(elem_addr, PAGE_4KB_SIZE);

        res = (BOOLEAN)hash64_lookup(hash, page_addr, &num_of_elements);
        VMM_ASSERT(res);
        VMM_ASSERT(num_of_elements > 0);
        num_of_elements--;
        res = (BOOLEAN)hash64_update(hash, page_addr, num_of_elements);
        VMM_ASSERT(res);
        pool_inc_num_of_allocated_elements(pool);
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
        return element;
    }

    free_pages_list = pool_get_free_pages_list(pool);
    if (pool_is_list_empty(free_pages_list)) {
        pool_allocate_several_pages_from_heap(pool);
    }
    if (pool_is_list_empty(free_pages_list)) {
        if (!pool_is_must_succeed_allocation(pool)) {
            VMM_ASSERT(pool_is_allocation_counters_ok(pool));
            return NULL;
        }
        pool_allocate_single_page_from_heap_with_must_succeed(pool);
        if (pool_is_list_empty(free_pages_list)) {
            return NULL;
        }
    }

    page = (void*)pool_allocate_node_from_list(free_pages_list);
    pool_inc_num_of_pages_used_for_pool_elements(pool);

    page_addr = (UINT64)page;
    VMM_ASSERT(page != NULL);
    VMM_ASSERT(ALIGN_BACKWARD(page_addr, PAGE_4KB_SIZE) == page_addr);

    pool_split_page_to_elements(free_pool_elements_list, 
                        pool_get_size_of_single_element(pool), page);
    VMM_ASSERT(pool_list_head_get_num_of_elements(free_pool_elements_list) > 0);
    element = (void*)pool_allocate_node_from_list(free_pool_elements_list);
    VMM_ASSERT(element != NULL);
    VMM_ASSERT(pool_ptr_to_uint64(element) == page_addr);

    num_of_elements = pool_list_head_get_num_of_elements(free_pool_elements_list);
    VMM_ASSERT(num_of_elements < pool_get_num_of_elements_per_page(pool));
    VMM_ASSERT(!hash64_lookup(hash, page_addr, &num_of_elements_tmp));
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    res = hash64_insert(hash, page_addr, num_of_elements);

    if (!res) {
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
        // Failed to insert page into hash
        pool_insert_node_into_list(free_pool_elements_list, element);
        pool_free_nodes_in_page_from_list(free_pool_elements_list, 
                        pool_get_size_of_single_element(pool), page);
        pool_dec_num_of_pages_used_for_pool_elements(pool);
        pool_insert_node_into_list(free_pages_list, (POOL_LIST_ELEMENT*)page);
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
        return NULL;
    }

    if (hash64_get_num_of_elements(hash) >= (pool_get_current_hash_size(pool) * POOL_REHASH_THRESHOLD)) {
        UINT32 new_size = (pool_get_current_hash_size(pool) * POOL_REHASH_THRESHOLD);
        BOOLEAN res = hash64_change_size_and_rehash(hash, new_size);

        if (res) {
            pool_set_current_hash_size(pool, new_size);
            VMM_LOG(mask_anonymous, level_trace,"POOL: Changed size of pool's hash to %d\n", new_size);
        }
        else {
            VMM_LOG(mask_anonymous, level_trace,"POOL: Failed to change size of pool's hash to %d\n", new_size);
        }
    }
    pool_inc_num_of_allocated_elements(pool);
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    return element;
}


POOL_HANDLE pool_create_internal(UINT32 size_of_single_element, BOOLEAN  mutex_flag)
{
    POOL*           pool = vmm_memory_alloc(sizeof(POOL));
    UINT32          final_size_of_single_element;
    UINT32          size_of_hash_element;
    UINT32          final_size_of_hash_element;
    HASH64_HANDLE   hash;

#ifdef JLMDEBUG1
    bprint("pool_create_internal\n");
#endif
    if (pool == NULL) {
        return POOL_INVALID_HANDLE;
    }
    pool_init_list_head(pool_get_free_hash_elements_list(pool));
    pool_init_list_head(pool_get_free_pool_elements_list(pool));
    pool_init_list_head(pool_get_free_pages_list(pool));
    pool_set_hash_element_to_allocate(pool, NULL);

    final_size_of_single_element = (size_of_single_element >= sizeof(POOL_LIST_ELEMENT))
                 ? size_of_single_element : sizeof(POOL_LIST_ELEMENT);
    pool_set_size_of_single_element(pool, final_size_of_single_element);
    pool_set_num_of_elements_per_page(pool, PAGE_4KB_SIZE/final_size_of_single_element);

    size_of_hash_element = hash64_get_node_size();
    final_size_of_hash_element = (size_of_hash_element >= sizeof(POOL_LIST_ELEMENT)) 
                ? size_of_hash_element : sizeof(POOL_LIST_ELEMENT);
    pool_set_size_of_hash_element(pool, final_size_of_hash_element);
    pool_set_num_of_hash_elements_per_page(pool, PAGE_4KB_SIZE/final_size_of_hash_element);

    hash = hash64_create_hash(pool_hash_func, NULL, NULL, pool_allocate_hash_node,
                              pool_free_hash_node, pool, POOL_HASH_NUM_OF_CELLS);
    if (hash == HASH64_INVALID_HANDLE) {
        vmm_memory_free(pool);
        pool = (POOL *) POOL_INVALID_HANDLE;
    }
    else {
        pool->mutex_flag = mutex_flag;;
        if (mutex_flag)
            lock_initialize(&pool->access_lock);
        pool_set_num_of_allocated_pages(pool, 0);
        pool_clear_num_of_allocated_elements(pool);
        pool_clear_num_of_pages_used_for_hash_nodes(pool);
        pool_clear_num_of_pages_used_for_pool_elements(pool);
        pool_set_hash(pool, hash);
        pool_set_current_hash_size(pool, POOL_HASH_NUM_OF_CELLS);
        pool_set_must_succeed_alloc_handle(pool, HEAP_INVALID_ALLOC_HANDLE);
        pool_clear_must_succeed_allocation(pool);
        pool_clear_alloc_free_ops_counter(pool);
        VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    }
    return (POOL_HANDLE)pool;
}


#ifdef INCLUDE_UNUSED_CODE
// Create regular pool with mutual exclussion guard.
POOL_HANDLE pool_create(UINT32 size_of_single_element)
{
    return pool_create_internal(size_of_single_element, TRUE);
}
#endif


// Create pool with no by mutual exclussion guard.
POOL_HANDLE assync_pool_create(UINT32 size_of_single_element)
{
    return pool_create_internal(size_of_single_element, FALSE);
}


#ifdef ENABLE_VTLB
void pool_destroy(POOL_HANDLE pool_handle) {
    POOL* pool = (POOL_HANDLE)pool_handle;
    POOL_LIST_ELEMENT* curr_page_elem;

    if (pool == NULL)
        return;
    POOL_AQUIRE_LOCK(pool);
    pool_try_to_free_unused_page_from_elements_list(pool, TRUE);
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    hash64_destroy_hash(pool_get_hash(pool));
    curr_page_elem = pool_list_head_get_first_element(pool_get_free_pages_list(pool));
    while (curr_page_elem != NULL) {
        POOL_LIST_ELEMENT* next_page_elem = pool_list_element_get_next(curr_page_elem);
        void* page = (void*)curr_page_elem;

        vmm_memory_free(page);
        curr_page_elem = next_page_elem;
    }
    POOL_RELEASE_LOCK(pool);
    vmm_memory_free(pool);
}
#endif

void* pool_allocate(POOL_HANDLE pool_handle) {
    POOL* pool = (POOL*)pool_handle;
    void  *tmp;

    if (pool == NULL) {
        return NULL;
    }
    POOL_AQUIRE_LOCK(pool);
    tmp = pool_allocate_internal(pool);
    POOL_RELEASE_LOCK(pool);
    return tmp;
}

#ifdef ENABLE_VTLB
void* pool_allocate_must_succeed(POOL_HANDLE pool_handle, HEAP_ALLOC_HANDLE must_succeed_handle) {
    POOL* pool = (POOL*)pool_handle;
    void* res;
    HEAP_ALLOC_HANDLE curr_handle;

    if (pool == NULL) {
        return NULL;
    }
    POOL_AQUIRE_LOCK(pool);
    curr_handle = pool_get_must_succeed_alloc_handle(pool);
    pool_set_must_succeed_alloc_handle(pool, must_succeed_handle);
    pool_set_must_succeed_allocation(pool);
    res = pool_allocate_internal(pool);
    pool_clear_must_succeed_allocation(pool);
    pool_set_must_succeed_alloc_handle(pool, curr_handle);
    POOL_RELEASE_LOCK(pool);
    return res;
}
#endif

void pool_free(POOL_HANDLE pool_handle, void* data) {
    POOL* pool = (POOL*)pool_handle;
    POOL_LIST_ELEMENT* element = (POOL_LIST_ELEMENT*)data;
    UINT64 element_addr = (UINT64)element;
    UINT64 page_addr = ALIGN_BACKWARD(element_addr, PAGE_4KB_SIZE);
    POOL_LIST_HEAD* free_elements_list;
    HASH64_HANDLE hash;
    BOOLEAN res;
    UINT64 num_of_elements;

    if (pool == NULL)
        return;
    POOL_AQUIRE_LOCK(pool);
    free_elements_list = pool_get_free_pool_elements_list(pool);
    hash = pool_get_hash(pool);
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    pool_dec_num_of_allocated_elements(pool);
    VMM_ASSERT(pool != NULL);
    if (element_addr == page_addr) {
        pool_insert_node_into_list_at_tail(free_elements_list, element);
    }
    else {
        pool_insert_node_into_list(free_elements_list, element);
    }
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    VMM_ASSERT(!pool_is_list_empty(free_elements_list));
    res = (BOOLEAN)hash64_lookup(hash, page_addr, &num_of_elements);
    VMM_ASSERT(res);
    num_of_elements++;
    res = (BOOLEAN)hash64_update(hash, page_addr, num_of_elements);
    VMM_ASSERT(res);
    VMM_ASSERT(pool_is_allocation_counters_ok(pool));
    pool_report_alloc_free_op(pool);
    POOL_RELEASE_LOCK(pool);
}

#ifdef ENABLE_VTLB
void pool_release_all_free_pages(POOL_HANDLE pool_handle) {
    POOL* pool = (POOL*)pool_handle;
    POOL_LIST_HEAD* free_pages_list;
    POOL_LIST_ELEMENT* curr_page;
    UINT32 num_of_allocated_pages;
    UINT32 num_of_freed_pages = 0;

    if (pool == NULL)
        return;
    POOL_AQUIRE_LOCK(pool);
    free_pages_list = pool_get_free_pages_list(pool);
    curr_page = pool_list_head_get_first_element(free_pages_list);
    pool_try_to_free_unused_page_from_elements_list(pool, TRUE);
    while (curr_page != NULL) {
        POOL_LIST_ELEMENT* next_page = pool_list_element_get_next(curr_page);
        vmm_memory_free((void*)curr_page);
        curr_page = next_page;
        num_of_freed_pages++;
    }

    pool_list_head_set_first_element(free_pages_list, NULL);
    pool_list_head_set_num_of_elements(free_pages_list, 0);
    if (pool_get_size_of_single_element(pool) > PAGE_4KB_SIZE) {
        POOL_LIST_HEAD* free_elements_list = pool_get_free_pool_elements_list(pool);
        POOL_LIST_ELEMENT* curr_element = pool_list_head_get_first_element(free_elements_list);

        while (curr_element != NULL) {
            POOL_LIST_ELEMENT* next_element = pool_list_element_get_next(curr_element);
            vmm_memory_free((void*)curr_element);
            curr_element = next_element;
        }

        pool_list_head_set_first_element(free_elements_list, NULL);
        pool_list_head_set_num_of_elements(free_elements_list, 0);
    }

    num_of_allocated_pages = pool_get_num_of_allocated_pages(pool);
    num_of_allocated_pages-= num_of_freed_pages;
    pool_set_num_of_allocated_pages(pool, num_of_allocated_pages);
    POOL_RELEASE_LOCK(pool);
}
#endif

#pragma warning (disable : 4100)
#ifdef INCLUDE_UNUSED_CODE
void pool_print(POOL_HANDLE pool_handle USED_IN_DEBUG_ONLY)
{
VMM_DEBUG_CODE
    (
    POOL* pool = (POOL*)pool_handle;
    POOL_AQUIRE_LOCK(pool);
    VMM_LOG(mask_anonymous, level_trace,"\r\nPool handle=%p element size=%d #allocated pages=%d #allocated elements=%d\r\n",
            pool_handle, pool->size_of_single_element, pool->num_of_allocated_pages, pool->num_of_allocated_elements);
    hash64_print(pool_get_hash(pool));
    POOL_RELEASE_LOCK(pool);
    )
}
#endif

#pragma warning(default : 4710)
#pragma warning (default : 4101 4189)

