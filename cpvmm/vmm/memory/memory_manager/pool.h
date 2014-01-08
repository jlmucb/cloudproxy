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


#ifndef POOL_H
#define POOL_H

#include <vmm_defs.h>
#include <pool_api.h>
#include <hash64_api.h>
#include <lock.h>

typedef struct POOL_LIST_ELEMENT_S {
    struct POOL_LIST_ELEMENT_S* prev;
    struct POOL_LIST_ELEMENT_S* next;
} POOL_LIST_ELEMENT;

/* POOL_LIST_ELEMENT* pool_list_element_get_prev(POOL_LIST_ELEMENT* element)  */
#define pool_list_element_get_prev(element_) (element_->prev)

/* void pool_list_element_set_prev(POOL_LIST_ELEMENT* element, POOL_LIST_ELEMENT* prev) */
#define pool_list_element_set_prev(element_, prev_) {element_->prev = prev_;}

/* POOL_LIST_ELEMENT* pool_list_element_get_next(POOL_LIST_ELEMENT* element) */
#define pool_list_element_get_next(element_) (element_->next)

/* void pool_list_element_set_next(POOL_LIST_ELEMENT* element, POOL_LIST_ELEMENT* next) */
#define pool_list_element_set_next(element_, next_) {element_->next = next_;}

/*----------------------------------------------------------*/
typedef struct POOL_LIST_HEAD_S {
    POOL_LIST_ELEMENT* first_element;
    POOL_LIST_ELEMENT* last_element;
    UINT32 num_of_elements;
    UINT32 padding; // not for use
} POOL_LIST_HEAD;

/* POOL_LIST_ELEMENT* pool_list_head_get_first_element(const POOL_LIST_HEAD* list_head) */
#define pool_list_head_get_first_element(list_head_) (list_head_->first_element)

/* void pool_list_head_set_first_element (POOL_LIST_HEAD* list_head, POOL_LIST_ELEMENT* first_element) */
#define pool_list_head_set_first_element(list_head_, first_element_) {list_head_->first_element = first_element_;}

/* POOL_LIST_ELEMENT* pool_list_head_get_last_element(const POOL_LIST_HEAD* list_head) */
#define pool_list_head_get_last_element(list_head_) (list_head_->last_element)

/* void pool_list_head_set_last_element (POOL_LIST_HEAD* list_head, POOL_LIST_ELEMENT* last_element) */
#define pool_list_head_set_last_element(list_head_, last_element_) {list_head_->last_element = last_element_;}

/* UINT32 pool_list_head_get_num_of_elements(const POOL_LIST_HEAD* list_head) */
#define pool_list_head_get_num_of_elements(list_head_) (list_head_->num_of_elements)

/* void pool_list_head_set_num_of_elements (POOL_LIST_HEAD* list_head, UINT32 num_of_elements) */
#define pool_list_head_set_num_of_elements(list_head_, num_of_elements_) {list_head_->num_of_elements = num_of_elements_;}

/*----------------------------------------------------------*/
typedef struct POOL_S {
    POOL_LIST_HEAD free_hash_elements;
    POOL_LIST_HEAD free_pool_elements;
    POOL_LIST_HEAD free_pages;
    POOL_LIST_ELEMENT* hash_element_to_allocate;
    HASH64_HANDLE hash;
    HEAP_ALLOC_HANDLE must_succeed_alloc_handle;
    UINT32 size_of_single_element;
    UINT32 num_of_elements_per_page;
    UINT32 size_of_hash_element;
    UINT32 num_of_hash_elements_per_page;
    UINT32 num_of_allocated_pages;
    UINT32 current_hash_size;
    BOOLEAN must_succeed_allocation;
    UINT32 alloc_free_ops_counter;
    UINT32 num_of_allocated_elements;
    UINT32 num_of_pages_used_for_hash_nodes;
    UINT32 num_of_pages_used_for_pool_elements;
    VMM_LOCK access_lock;
    BOOLEAN mutex_flag;
    UINT32  pad0;
} POOL;

/* POOL_LIST_HEAD* pool_get_free_hash_elements_list(POOL* pool) */
#define pool_get_free_hash_elements_list(pool_) (&(pool_->free_hash_elements))
 
/* POOL_LIST_HEAD* pool_get_free_pool_elements_list(POOL* pool) */
#define pool_get_free_pool_elements_list(pool_) (&(pool_->free_pool_elements))

/* POOL_LIST_HEAD* pool_get_free_pages_list(POOL* pool) */
#define pool_get_free_pages_list(pool_) (&(pool_->free_pages))

/* UINT32 pool_get_size_of_single_element(const POOL* pool) */
#define pool_get_size_of_single_element(pool_) (pool_->size_of_single_element)

/* void pool_set_size_of_single_element(POOL* pool, UINT32 size) */
#define pool_set_size_of_single_element(pool_, size_) {pool_->size_of_single_element = size_;}

/* POOL_LIST_ELEMENT* pool_get_hash_element_to_allocate(POOL* pool) */
#define pool_get_hash_element_to_allocate(pool_) (pool_->hash_element_to_allocate)

/* void pool_set_hash_element_to_allocate(POOL* pool, POOL_LIST_ELEMENT* element) */
#define pool_set_hash_element_to_allocate(pool_, element_) {pool_->hash_element_to_allocate = element_;}

/* UINT32 pool_get_num_of_elements_per_page(const POOL* pool) */
#define pool_get_num_of_elements_per_page(pool_) (pool_->num_of_elements_per_page)

/* void pool_set_num_of_elements_per_page(POOL* pool, UINT32 num) */
#define pool_set_num_of_elements_per_page(pool_, num_) {pool_->num_of_elements_per_page = num_;}

/* UINT32 pool_get_size_of_hash_element(const POOL* pool) */
#define pool_get_size_of_hash_element(pool_) (pool_->size_of_hash_element)

/* void pool_set_size_of_hash_element(POOL* pool, UINT32 size) */
#define pool_set_size_of_hash_element(pool_, size_) {pool_->size_of_hash_element = size_;}

/* UINT32 pool_get_num_of_hash_elements_per_page(const POOL* pool) */
#define pool_get_num_of_hash_elements_per_page(pool_) (pool_->num_of_hash_elements_per_page)

/* void pool_set_num_of_hash_elements_per_page(POOL* pool, UINT32 num) */
#define pool_set_num_of_hash_elements_per_page(pool_, num_) {pool_->num_of_hash_elements_per_page = num_;}

/* HASH64_HANDLE pool_get_hash(const POOL* pool) */
#define pool_get_hash(pool_) (pool_->hash)

/* void pool_set_hash(POOL* pool, HASH64_HANDLE hash) */
#define pool_set_hash(pool_, hash_) {pool_->hash = hash_;}

/* UINT32 pool_get_current_hash_size(const POOL* pool) */
#define pool_get_current_hash_size(pool_) (pool_->current_hash_size)

/* void pool_set_current_hash_size(POOL* pool, UINT32 new_size) */
#define pool_set_current_hash_size(pool_, new_size_) {pool_->current_hash_size = new_size_;}

/* UINT32 pool_get_num_of_allocated_pages(const POOL* pool) */
#define pool_get_num_of_allocated_pages(pool_) (pool_->num_of_allocated_pages)

/* void pool_set_num_of_allocated_pages(POOL* pool, UINT32 num) */
#define pool_set_num_of_allocated_pages(pool_, num_) {pool_->num_of_allocated_pages = num_;}

/* HEAP_ALLOC_HANDLE pool_get_must_succeed_alloc_handle(const POOL* pool) */
#define pool_get_must_succeed_alloc_handle(pool_) (pool_->must_succeed_alloc_handle)

/* void pool_set_must_succeed_alloc_handle(POOL* pool, HEAP_ALLOC_HANDLE handle) */
#define pool_set_must_succeed_alloc_handle(pool_, handle_) {pool_->must_succeed_alloc_handle = handle_;}

/* BOOLEAN pool_is_must_succeed_allocation(const POOL* pool) */
#define pool_is_must_succeed_allocation(pool_) (pool_->must_succeed_allocation)

/* void pool_set_must_succeed_allocation(POOL* pool) */
#define pool_set_must_succeed_allocation(pool_) {pool_->must_succeed_allocation = TRUE;}

/* void pool_clear_must_succeed_allocation(POOL* pool) */
#define pool_clear_must_succeed_allocation(pool_) {pool_->must_succeed_allocation = FALSE;}

/* UINT32 pool_get_alloc_free_ops_counter(const POOL* pool) */
#define pool_get_alloc_free_ops_counter(pool_) (pool_->alloc_free_ops_counter)

/* void pool_clear_alloc_free_ops_counter(POOL* pool) */
#define pool_clear_alloc_free_ops_counter(pool_) {pool_->alloc_free_ops_counter = 0;}

/* void pool_inc_alloc_free_ops_counter(POOL* pool) */
#define pool_inc_alloc_free_ops_counter(pool_) {pool_->alloc_free_ops_counter += 1;}


/* UINT32 pool_get_num_of_allocated_elements(const POOL* pool) */
#define pool_get_num_of_allocated_elements(pool_) (pool_->num_of_allocated_elements)

/* void pool_clear_num_of_allocated_elements(POOL* pool) */
#define pool_clear_num_of_allocated_elements(pool_) {pool_->num_of_allocated_elements = 0;}

/* void pool_inc_num_of_allocated_elements(POOL* pool) */
#define pool_inc_num_of_allocated_elements(pool_) {pool_->num_of_allocated_elements += 1;}

/* void pool_dec_num_of_allocated_elements(POOL* pool) */
#define pool_dec_num_of_allocated_elements(pool_) {pool_->num_of_allocated_elements -= 1;}

/* UINT32 pool_get_num_of_pages_used_for_hash_nodes(POOL* pool) */
#define pool_get_num_of_pages_used_for_hash_nodes(pool_) (pool_->num_of_pages_used_for_hash_nodes)

/* void pool_clear_num_of_pages_used_for_hash_nodes(POOL* pool) */
#define pool_clear_num_of_pages_used_for_hash_nodes(pool_) {pool_->num_of_pages_used_for_hash_nodes = 0;}

/* void pool_inc_num_of_pages_used_for_hash_nodes(POOL* pool) */
#define pool_inc_num_of_pages_used_for_hash_nodes(pool_) {pool_->num_of_pages_used_for_hash_nodes += 1;}

/* void pool_dec_num_of_pages_used_for_hash_nodes(POOL* pool) */
#define pool_dec_num_of_pages_used_for_hash_nodes(pool_) {pool_->num_of_pages_used_for_hash_nodes -= 1;}

/* UINT32 pool_get_num_of_pages_used_for_pool_elements(POOL* pool) */
#define pool_get_num_of_pages_used_for_pool_elements(pool_) (pool_->num_of_pages_used_for_pool_elements)

/* void pool_clear_num_of_pages_used_for_pool_elements(POOL* pool) */
#define pool_clear_num_of_pages_used_for_pool_elements(pool_) {pool_->num_of_pages_used_for_pool_elements = 0;}

/* void pool_inc_num_of_pages_used_for_pool_elements(POOL* pool) */
#define pool_inc_num_of_pages_used_for_pool_elements(pool_) {pool_->num_of_pages_used_for_pool_elements += 1;}

/* void pool_dec_num_of_pages_used_for_pool_elements(POOL* pool) */
#define pool_dec_num_of_pages_used_for_pool_elements(pool_) {pool_->num_of_pages_used_for_pool_elements -= 1;}


/*----------------------------------------------------------*/

#define POOL_HASH_NUM_OF_CELLS 512
#define POOL_PAGES_TO_FREE_THRESHOLD 4
#define POOL_PAGES_TO_KEEP_THRESHOLD 4
#define POOL_PAGES_TO_ALLOCATE_THRESHOLD 8
#define POOL_MAX_NUM_OF_PAGES_TO_ALLOCATE 100
#define POOL_MIN_NUMBER_OF_FREE_PAGES 4
#define POOL_MIN_NUMBER_OF_PAGES_TO_FREE 6
#define POOL_REHASH_THRESHOLD 4
#define POOL_FREE_UNUSED_PAGES_THRESHOLD 5000

#endif
