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

#ifndef _HASH64_H_
#define _HASH64_H_

#include <vmm_defs.h>
#include <hash64_api.h>


typedef struct HASH64_NODE_S
{
  struct HASH64_NODE_S *next;
  UINT64              key;
  UINT64              value;
} HASH64_NODE;

INLINE
HASH64_NODE* hash64_node_get_next(HASH64_NODE* cell) {
    return cell->next;
}

INLINE
void hash64_node_set_next(HASH64_NODE* cell, HASH64_NODE* next) {
    cell->next = next;
}

INLINE
UINT64 hash64_node_get_key(HASH64_NODE* cell) {
    return cell->key;
}

INLINE
void hash64_node_set_key(HASH64_NODE* cell, UINT64 key) {
    cell->key = key;
}

INLINE
UINT64 hash64_node_get_value(HASH64_NODE* cell) {
    return cell->value;
}

INLINE
void hash64_node_set_value(HASH64_NODE* cell, UINT64 value) {
    cell->value = value;
}

typedef	struct HASH64_TABLE_S {
  HASH64_NODE** array;
  HASH64_FUNC hash_func;
  HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func;
  HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func;
  HASH64_NODE_ALLOCATION_FUNC node_alloc_func;
  HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func;
  void* node_allocation_deallocation_context;
  UINT32 size;
  UINT32 element_count;
  BOOLEAN is_multiple_values_hash;
  UINT32 padding; // not in use
} HASH64_TABLE;

INLINE
UINT32 hash64_get_hash_size(HASH64_TABLE* hash) {
    return hash->size;
}

INLINE
void hash64_set_hash_size(HASH64_TABLE* hash, UINT32 size) {
    hash->size = size;
}

INLINE
HASH64_NODE** hash64_get_array(HASH64_TABLE* hash) {
    return hash->array;
}

INLINE
void hash64_set_array(HASH64_TABLE* hash, HASH64_NODE** array) {
    hash->array = array;
}

INLINE
HASH64_FUNC hash64_get_hash_func(HASH64_TABLE* hash) {
    return hash->hash_func;
}

INLINE
void hash64_set_hash_func(HASH64_TABLE* hash, HASH64_FUNC hash_func) {
    hash->hash_func = hash_func;
}

INLINE
HASH64_INTERNAL_MEM_ALLOCATION_FUNC hash64_get_mem_alloc_func(HASH64_TABLE* hash) {
    return hash->mem_alloc_func;
}

INLINE
void hash64_set_mem_alloc_func(HASH64_TABLE* hash, HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func) {
    hash->mem_alloc_func = mem_alloc_func;
}

INLINE
HASH64_INTERNAL_MEM_DEALLOCATION_FUNC hash64_get_mem_dealloc_func(HASH64_TABLE* hash) {
    return hash->mem_dealloc_func;
}

INLINE
void hash64_set_mem_dealloc_func(HASH64_TABLE* hash, HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func) {
    hash->mem_dealloc_func = mem_dealloc_func;
}

INLINE
HASH64_NODE_ALLOCATION_FUNC hash64_get_node_alloc_func(HASH64_TABLE* hash) {
    return hash->node_alloc_func;
}

INLINE
void hash64_set_node_alloc_func(HASH64_TABLE* hash, HASH64_NODE_ALLOCATION_FUNC node_alloc_func) {
    hash->node_alloc_func = node_alloc_func;
}

INLINE
HASH64_NODE_DEALLOCATION_FUNC hash64_get_node_dealloc_func(HASH64_TABLE* hash) {
    return hash->node_dealloc_func;
}

INLINE
void hash64_set_node_dealloc_func(HASH64_TABLE* hash, HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func) {
    hash->node_dealloc_func = node_dealloc_func;
}

INLINE
void* hash64_get_allocation_deallocation_context(HASH64_TABLE* hash) {
    return hash->node_allocation_deallocation_context;
}

INLINE
void hash64_set_allocation_deallocation_context(HASH64_TABLE* hash, void* context) {
    hash->node_allocation_deallocation_context = context;
}


INLINE
UINT32 hash64_get_element_count(HASH64_TABLE* hash) {
    return hash->element_count;
}

INLINE
void hash64_clear_element_count(HASH64_TABLE* hash) {
    hash->element_count = 0;
}

INLINE
void hash64_inc_element_count(HASH64_TABLE* hash) {
    hash->element_count += 1;
}

INLINE
void hash64_dec_element_count(HASH64_TABLE* hash) {
    hash->element_count -= 1;
}

INLINE
BOOLEAN hash64_is_multiple_values_hash(HASH64_TABLE* hash) {
    return hash->is_multiple_values_hash;
}

INLINE
void hash64_set_multiple_values_hash(HASH64_TABLE* hash) {
    hash->is_multiple_values_hash = TRUE;
}

INLINE
void hash64_set_single_value_hash(HASH64_TABLE* hash) {
    hash->is_multiple_values_hash = FALSE;
}

#endif
