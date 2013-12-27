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

#include <vmm_defs.h>
#include <heap.h>
#include <hash64_api.h>
#include <common_libc.h>
#include <vmm_dbg.h>
#include "hash64.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(HASH64_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(HASH64_C, __condition)

INLINE
void* hash64_uint64_to_ptr(UINT64 value) {
    return (void*)(value);
}

INLINE
UINT64 hash64_ptr_to_uint64(void* ptr) {
    return (UINT64)ptr;
}

INLINE
void* hash64_allocate_node(HASH64_TABLE* hash) {
    HASH64_NODE_ALLOCATION_FUNC node_alloc_func = hash64_get_node_alloc_func(hash);
    void* context = hash64_get_allocation_deallocation_context(hash);

    return node_alloc_func(context);
}

INLINE
void hash64_free_node(HASH64_TABLE* hash, void* data) {
    HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func = hash64_get_node_dealloc_func(hash);
    void* context = hash64_get_allocation_deallocation_context(hash);

    node_dealloc_func(context, data);
}

INLINE
void* hash64_mem_alloc(HASH64_TABLE* hash, UINT32 size) {
    HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func = hash64_get_mem_alloc_func(hash);
    if (mem_alloc_func == NULL) {
        return vmm_memory_alloc(size);
    }
    else {
        return mem_alloc_func(size);
    }
}

INLINE
void hash64_mem_free(HASH64_TABLE* hash, void* data) {
    HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func = hash64_get_mem_dealloc_func(hash);
    if (mem_dealloc_func == NULL) {
        vmm_memory_free(data);
    }
    else {
        mem_dealloc_func(data);
    }
}

static
HASH64_NODE** hash64_retrieve_appropriate_array_cell(HASH64_TABLE* hash,
                                                     UINT64 key) {
    HASH64_FUNC hash_func;
    UINT32 cell_index;
    HASH64_NODE** array;

    hash_func = hash64_get_hash_func(hash);
    cell_index = hash_func(key, hash64_get_hash_size(hash));
    array = hash64_get_array(hash);
    return &(array[cell_index]);
}

static
HASH64_NODE* hash64_find(HASH64_TABLE* hash,
                         UINT64 key) {
    HASH64_NODE** cell;
    HASH64_NODE* node;

    cell = hash64_retrieve_appropriate_array_cell(hash, key);
    node = *cell;

    while (node != NULL) {
        if (hash64_node_get_key(node) == key) {
            break;
        }
        node = hash64_node_get_next(node);
    }
    return node;
}

static
BOOLEAN hash64_insert_internal(HASH64_TABLE* hash,
                              UINT64 key,
                              UINT64 value,
                              BOOLEAN update_when_found) {
    HASH64_NODE* node = NULL;

    if (update_when_found) {
        node = hash64_find(hash, key);
    }
    else {
        // The key should not exist
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT(hash64_find(hash, key) == NULL);
    }

    if (node == NULL) {
        HASH64_NODE** cell;

        node = hash64_allocate_node(hash);
        if (node == NULL) {
           return FALSE;
        }
        cell = hash64_retrieve_appropriate_array_cell(hash, key);

        hash64_node_set_next(node, *cell);
        *cell = node;

        hash64_node_set_key(node, key);

        hash64_inc_element_count(hash);
    }
    else {
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT(hash64_node_get_key(node) == key);
    }

    hash64_node_set_value(node, value);

    VMM_ASSERT(hash64_find(hash, key) != NULL);

    return TRUE;
}

static
HASH64_HANDLE hash64_create_hash_internal(HASH64_FUNC hash_func,
                                          HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func,
                                          HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func,
                                          HASH64_NODE_ALLOCATION_FUNC node_alloc_func,
                                          HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func,
                                          void* node_allocation_deallocation_context,
                                          UINT32 hash_size,
                                          BOOLEAN is_multiple_values_hash) {
    HASH64_TABLE* hash;
    HASH64_NODE** array;
    UINT32 index;

    if (mem_alloc_func == NULL) {
        hash = (HASH64_TABLE*)vmm_memory_alloc(sizeof(HASH64_TABLE));
    }
    else {
        hash = (HASH64_TABLE*)mem_alloc_func(sizeof(HASH64_TABLE));
    }

    if (hash == NULL) {
        goto hash_allocation_failed;
    }

    if (mem_alloc_func == NULL) {
        array = (HASH64_NODE**)vmm_memory_alloc(sizeof(HASH64_NODE*) * hash_size);
    }
    else {
        array = (HASH64_NODE**)mem_alloc_func(sizeof(HASH64_NODE*) * hash_size);
    }

    if (array == NULL) {
        goto array_allocation_failed;
    }
    for (index = 0; index < hash_size; index++) {
        array[index] = NULL;
    }

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(node_alloc_func != NULL);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(node_dealloc_func != NULL);

    hash64_set_hash_size(hash, hash_size);
    hash64_set_array(hash, array);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(hash_func != NULL);
    hash64_set_hash_func(hash, hash_func);
    hash64_set_mem_alloc_func(hash, mem_alloc_func);
    hash64_set_mem_dealloc_func(hash, mem_dealloc_func);
    hash64_set_node_alloc_func(hash, node_alloc_func);
    hash64_set_node_dealloc_func(hash, node_dealloc_func);
    hash64_set_allocation_deallocation_context(hash, node_allocation_deallocation_context);
    hash64_clear_element_count(hash);
    if (is_multiple_values_hash) {
        hash64_set_multiple_values_hash(hash);
    }
    else {
        hash64_set_single_value_hash(hash);
    }
    return (HASH64_HANDLE)hash;

array_allocation_failed:
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(hash != NULL);
    if (mem_dealloc_func == NULL) {
        vmm_memory_free(hash);
    }
    else {
        mem_dealloc_func(hash);
    }
hash_allocation_failed:
    return HASH64_INVALID_HANDLE;
}

static
void hash64_destroy_hash_internal(HASH64_TABLE* hash) {
    HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func;
	HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func;
    HASH64_NODE** array;
	UINT32 i;

    array = hash64_get_array(hash);
    mem_dealloc_func = hash64_get_mem_dealloc_func(hash);
	node_dealloc_func = hash64_get_node_dealloc_func(hash);
	for (i = 0; i < hash64_get_hash_size(hash); i++) {
		HASH64_NODE* node = array[i];

		if (hash64_get_element_count(hash) == 0) {
			VMM_ASSERT(node == NULL);
			break;
		}

		while (node != NULL) {
			HASH64_NODE* next_node = hash64_node_get_next(node);

			VMM_ASSERT(hash64_get_element_count(hash) != 0);

			if (hash64_is_multiple_values_hash(hash)) {
				UINT64 node_value = hash64_node_get_value(node);
				HASH64_NODE* internal_node = (HASH64_NODE*)hash64_uint64_to_ptr(node_value);
				while (internal_node != NULL) {
					HASH64_NODE* next_internal_node = hash64_node_get_next(internal_node);
					node_dealloc_func(hash64_get_allocation_deallocation_context(hash), internal_node);
					internal_node = next_internal_node;
				}
			}
			node_dealloc_func(hash64_get_allocation_deallocation_context(hash), node);
			hash64_dec_element_count(hash);
			node = next_node;
		}
	}

	VMM_ASSERT(hash64_get_element_count(hash) == 0);

    if (mem_dealloc_func == NULL) {
        vmm_memory_free(array);
        vmm_memory_free(hash);
    }
    else {
        mem_dealloc_func(array);
        mem_dealloc_func(hash);
    }
}

/*-----------------------------------------------------*/

UINT32 hash64_get_node_size(void) {
    return sizeof(HASH64_NODE);
}

HASH64_HANDLE hash64_create_hash(HASH64_FUNC hash_func,
                                 HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func,
                                 HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func,
                                 HASH64_NODE_ALLOCATION_FUNC node_alloc_func,
                                 HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func,
                                 void* node_allocation_deallocation_context,
                                 UINT32 hash_size) {
    return hash64_create_hash_internal(hash_func,
                                       mem_alloc_func,
                                       mem_dealloc_func,
                                       node_alloc_func,
                                       node_dealloc_func,
                                       node_allocation_deallocation_context,
                                       hash_size,
                                       FALSE);
}

void hash64_destroy_hash(HASH64_HANDLE hash_handle) {
	HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

	VMM_ASSERT(!hash64_is_multiple_values_hash(hash));
    hash64_destroy_hash_internal(hash);
}

UINT32 hash64_default_hash_func(UINT64 key, UINT32 size)
{
    return (UINT32)(key % size);
}

#pragma warning (push)
#pragma warning (disable : 4100)

void* hash64_default_node_alloc_func(void* context UNUSED)
{
    return vmm_memory_alloc(hash64_get_node_size());
}

void hash64_default_node_dealloc_func(void* context UNUSED, void* data)
{
    vmm_memory_free(data);
}

#pragma warning (pop)


HASH64_HANDLE hash64_create_default_hash(UINT32 hash_size)
{
    return hash64_create_hash(hash64_default_hash_func,
                              NULL,
                              NULL,
                              hash64_default_node_alloc_func,
                              hash64_default_node_dealloc_func,
                              NULL,
                              hash_size);
}

BOOLEAN hash64_lookup(HASH64_HANDLE hash_handle,
                     UINT64 key,
                     UINT64* value) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE* node;

    if (hash == NULL) {
        return FALSE;
    }

    node = hash64_find(hash, key);
    if (node != NULL) {
        VMM_ASSERT(hash64_node_get_key(node) == key);
        *value = hash64_node_get_value(node);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN hash64_insert(HASH64_HANDLE hash_handle,
                     UINT64 key,
                     UINT64 value) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

    if (hash == NULL) {
        return FALSE;
    }

    return hash64_insert_internal(hash, key, value, FALSE);
}

BOOLEAN hash64_update(HASH64_HANDLE hash_handle,
                     UINT64 key,
                     UINT64 value) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

    if (hash == NULL) {
        return FALSE;
    }

    return hash64_insert_internal(hash, key, value, TRUE);
}

BOOLEAN hash64_remove(HASH64_HANDLE hash_handle,
                     UINT64 key) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE* node;
    HASH64_NODE** cell;

    if (hash == NULL) {
        return FALSE;
    }

    VMM_ASSERT(hash64_find(hash, key) != NULL);

    cell = hash64_retrieve_appropriate_array_cell(hash, key);
    node = *cell;
    if (node == NULL) {
        return FALSE;
    }

    if (hash64_node_get_key(node) == key) {
        *cell = hash64_node_get_next(node);
        VMM_ASSERT(hash64_find(hash, key) == NULL);
        hash64_free_node(hash, node);
        VMM_ASSERT(hash64_get_element_count(hash) > 0);
        hash64_dec_element_count(hash);
        return TRUE;
    }


    while(node != NULL) {
        HASH64_NODE* prev_node = node;
        node = hash64_node_get_next(node);

        if ((node != NULL) &&
            (hash64_node_get_key(node) == key)) {
            hash64_node_set_next(prev_node, hash64_node_get_next(node));
            VMM_ASSERT(hash64_find(hash, key) == NULL);
            hash64_free_node(hash, node);
            VMM_ASSERT(hash64_get_element_count(hash) > 0);
            hash64_dec_element_count(hash);
            return TRUE;
        }

    }

    return FALSE;
}

BOOLEAN hash64_is_empty(HASH64_HANDLE hash_handle) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

    if (hash == NULL) {
        return FALSE;
    }

    return (hash64_get_element_count(hash) == 0);
}

BOOLEAN hash64_change_size_and_rehash(HASH64_HANDLE hash_handle,
                                      UINT32 hash_size) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE** old_array;
    HASH64_NODE** new_array;
    UINT32 old_hash_size;
    UINT32 i;

    if (hash == NULL) {
        return FALSE;
    }

    new_array = (HASH64_NODE**)hash64_mem_alloc(hash, sizeof(HASH64_NODE*) * hash_size);

    if (new_array == NULL) {
        return FALSE;
    }

    vmm_zeromem(new_array, sizeof(HASH64_NODE*) * hash_size);

    old_array = hash64_get_array(hash);
    old_hash_size = hash64_get_hash_size(hash);

    hash64_set_array(hash, new_array);
    hash64_set_hash_size(hash, hash_size);

    for (i = 0; i < old_hash_size; i++) {
        HASH64_NODE* node = old_array[i];
        while (node != NULL) {
            HASH64_NODE* next_node = hash64_node_get_next(node);
            UINT64 key;
            HASH64_NODE** new_cell;

            key = hash64_node_get_key(node);
            new_cell = hash64_retrieve_appropriate_array_cell(hash, key);
            hash64_node_set_next(node, *new_cell);
            *new_cell = node;

            node = next_node;
        }
        old_array[i] = NULL;
    }

    hash64_mem_free(hash, old_array);
    return TRUE;
}

UINT32 hash64_get_num_of_elements(HASH64_HANDLE hash_handle) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

    VMM_ASSERT(hash != NULL);
    return hash64_get_element_count(hash);
}
#ifdef ENABLE_VTLB
UINT32 hash64_get_current_size(HASH64_HANDLE hash_handle) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

    VMM_ASSERT(hash != NULL);
    return hash64_get_hash_size(hash);
}

HASH64_HANDLE hash64_create_multiple_values_hash(HASH64_FUNC hash_func,
                                                 HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func,
                                                 HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func,
                                                 HASH64_NODE_ALLOCATION_FUNC node_alloc_func,
                                                 HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func,
                                                 void* node_allocation_deallocation_context,
                                                 UINT32 hash_size) {
    return hash64_create_hash_internal(hash_func,
                                       mem_alloc_func,
                                       mem_dealloc_func,
                                       node_alloc_func,
                                       node_dealloc_func,
                                       node_allocation_deallocation_context,
                                       hash_size,
                                       TRUE);
}
#endif


void hash64_destroy_multiple_values_hash(HASH64_HANDLE hash_handle) {
	HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

	VMM_ASSERT(hash64_is_multiple_values_hash(hash));
    hash64_destroy_hash_internal(hash);
}

#ifdef ENABLE_VTLB
BOOLEAN hash64_lookup_in_multiple_values_hash(HASH64_HANDLE hash_handle,
                                             UINT64 key,
                                             HASH64_MULTIPLE_VALUES_HASH_ITERATOR* iter) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE* top_node;
    UINT64 top_node_value;

    if (hash == NULL) {
        return FALSE;
    }

    VMM_ASSERT(hash64_is_multiple_values_hash(hash));

    top_node = hash64_find(hash, key);

    if (top_node == NULL) {
        return FALSE;
    }

    top_node_value = hash64_node_get_value(top_node);

    *iter = (HASH64_MULTIPLE_VALUES_HASH_ITERATOR)hash64_uint64_to_ptr(top_node_value);

    return TRUE;
}

HASH64_MULTIPLE_VALUES_HASH_ITERATOR
hash64_multiple_values_hash_iterator_get_next(HASH64_MULTIPLE_VALUES_HASH_ITERATOR iter) {
    HASH64_NODE* node = (HASH64_NODE*)iter;
    return (HASH64_MULTIPLE_VALUES_HASH_ITERATOR)hash64_node_get_next(node);
}

UINT64 hash64_multiple_values_hash_iterator_get_value(HASH64_MULTIPLE_VALUES_HASH_ITERATOR iter) {
    HASH64_NODE* node = (HASH64_NODE*)iter;
    return hash64_node_get_value(node);
}

BOOLEAN hash64_insert_into_multiple_values_hash(HASH64_HANDLE hash_handle,
                                               UINT64 key,
                                               UINT64 value) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE* top_node;
    UINT64 top_node_value;
    HASH64_NODE* node;
    HASH64_NODE* node_tmp;

    if (hash == NULL) {
        return FALSE;
    }

    VMM_ASSERT(hash64_is_multiple_values_hash(hash));

    top_node = hash64_find(hash, key);


    if (top_node == NULL) {
        HASH64_NODE** cell;
        top_node = hash64_allocate_node(hash);
        if (top_node == NULL) {
            return FALSE;
        }
        hash64_node_set_key(top_node, key);
        hash64_node_set_value(top_node, hash64_ptr_to_uint64(NULL));
        cell = hash64_retrieve_appropriate_array_cell(hash, key);
        hash64_node_set_next(top_node, *cell);
        *cell = top_node;
        hash64_inc_element_count(hash);
    }

    node = hash64_allocate_node(hash);
    if (node == NULL) {
        return FALSE;
    }

    hash64_node_set_key(node, key);
    hash64_node_set_value(node, value);

    top_node_value = hash64_node_get_value(top_node);
    node_tmp = (HASH64_NODE*)hash64_uint64_to_ptr(top_node_value);
    if ((node_tmp == NULL) ||
        (hash64_node_get_value(node_tmp) >= value)) {
        hash64_node_set_next(node, node_tmp);
        hash64_node_set_value(top_node, hash64_ptr_to_uint64(node));
        return TRUE;
    }

    while (1) {
        HASH64_NODE* next_node_tmp = hash64_node_get_next(node_tmp);
        if ((next_node_tmp == NULL) ||
            (hash64_node_get_value(next_node_tmp) >= value)) {
            break;
        }
        node_tmp = next_node_tmp;
    }

    hash64_node_set_next(node, hash64_node_get_next(node_tmp));
    hash64_node_set_next(node_tmp, node);

    return TRUE;
}

BOOLEAN hash64_remove_from_multiple_values_hash(HASH64_HANDLE hash_handle,
                                               UINT64 key,
                                               UINT64 value) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE* top_node;
    UINT64 top_node_value;
    HASH64_NODE* node;

    if (hash == NULL) {
        return FALSE;
    }

    VMM_ASSERT(hash64_is_multiple_values_hash(hash));

    top_node = hash64_find(hash, key);

    if (top_node == NULL) {
        return FALSE;
    }

    top_node_value = hash64_node_get_value(top_node);
    node = (HASH64_NODE*)hash64_uint64_to_ptr(top_node_value);

    if (hash64_node_get_value(node) == value) {
        HASH64_NODE* next_node = hash64_node_get_next(node);
        hash64_free_node(hash, node);
        top_node_value = hash64_ptr_to_uint64(next_node);
        hash64_node_set_value(top_node, top_node_value);
        if (next_node == NULL) {
            BOOLEAN res;
            // There is only one value
            res = hash64_remove(hash_handle, key);
            VMM_ASSERT(res);
        }
        return TRUE;
    }

    while (node != NULL) {
        HASH64_NODE* prev_node = node;

        node = hash64_node_get_next(node);
        if (node != NULL) {
            if (hash64_node_get_value(node) == value) {
                hash64_node_set_next(prev_node, hash64_node_get_next(node));
                hash64_free_node(hash, node);
                return TRUE;
            }
            else if (hash64_node_get_value(node) > value) {
                break; // no point to search in sorted list
            }
        }
    }
    return FALSE;
}

BOOLEAN hash64_is_value_in_multiple_values_hash(HASH64_HANDLE hash_handle,
                                               UINT64 key,
                                               UINT64 value) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_MULTIPLE_VALUES_HASH_ITERATOR iter;

    if (hash == NULL) {
        return FALSE;
    }

    VMM_ASSERT(hash64_is_multiple_values_hash(hash));

    if (!hash64_lookup_in_multiple_values_hash(hash_handle, key, &iter)) {
        return FALSE;
    }

    while (iter != HASH64_NULL_ITERATOR) {
        UINT64 iter_value = hash64_multiple_values_hash_iterator_get_value(iter);
        if (iter_value == value) {
            return TRUE;
        }
        iter = hash64_multiple_values_hash_iterator_get_next(iter);
    }
    return FALSE;
}

BOOLEAN hash64_remove_range_from_multiple_values_hash(HASH64_HANDLE hash_handle,
                                                     UINT64 key,
                                                     UINT64 value_from,
                                                     UINT64 value_to) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE* top_node;
    HASH64_NODE* node;
    UINT64 top_node_value;
    BOOLEAN removed_any_value = FALSE;

    if (hash == NULL) {
        return FALSE;
    }

    VMM_ASSERT(hash64_is_multiple_values_hash(hash));

    top_node = hash64_find(hash, key);

    if (top_node == NULL) {
        return FALSE;
    }

    top_node_value = hash64_node_get_value(top_node);
    node = (HASH64_NODE*)hash64_uint64_to_ptr(top_node_value);

    VMM_ASSERT(node != NULL);
    VMM_ASSERT(value_from <= value_to);

    if (hash64_node_get_value(node) > value_to) {
        return FALSE;
    }

    if (hash64_node_get_value(node) >= value_from) {
        while ((node != NULL) &&
               (hash64_node_get_value(node) <= value_to)) {
            // remove from the beginning of the list
            HASH64_NODE* node_to_remove = node;
            node = hash64_node_get_next(node);
            hash64_free_node(hash, node_to_remove);
            removed_any_value = TRUE;
        }

        if (removed_any_value) {
            VMM_ASSERT((node == NULL) || (hash64_node_get_value(node) > value_to));
            top_node_value = hash64_ptr_to_uint64(node);
            hash64_node_set_value(top_node, top_node_value);
            if (node == NULL) {
                BOOLEAN res;
                // all the entries were removed
                res = hash64_remove(hash_handle, key);
                VMM_ASSERT(res);
            }
            return TRUE;
        }
    }

    while (node != NULL) {
        HASH64_NODE* next_node = hash64_node_get_next(node);
        VMM_ASSERT(hash64_node_get_value(node) < value_from);
        if ((next_node != NULL) &&
            (hash64_node_get_value(next_node) > value_to)) {
            break;
        }

        if ((next_node != NULL) &&
            (hash64_node_get_value(next_node) >= value_from)) {
            hash64_node_set_next(node, hash64_node_get_next(next_node));
            hash64_free_node(hash, next_node);
            removed_any_value = TRUE;
        }
        else {
            node = next_node;
        }
    }
    return removed_any_value;
}

BOOLEAN hash64_multiple_values_is_empty(HASH64_HANDLE hash_handle) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;

    if (hash == NULL) {
        return FALSE;
    }

    return (hash64_get_element_count(hash) == 0);
}
#endif

#ifdef DEBUG
void hash64_print(HASH64_HANDLE hash_handle) {
    HASH64_TABLE* hash = (HASH64_TABLE*)hash_handle;
    HASH64_NODE** array;
    UINT32 i;

    VMM_LOG(mask_anonymous, level_trace,"Hash64:\n");
    VMM_LOG(mask_anonymous, level_trace,"========================\n");
    if (hash == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"%s: ERROR in parameter\n", __FUNCTION__);
        return;
    }
    VMM_LOG(mask_anonymous, level_trace,"Num of cells: %d\n", hash64_get_hash_size(hash));
    VMM_LOG(mask_anonymous, level_trace,"Num of elements: %d\n", hash64_get_element_count(hash));

    array = hash64_get_array(hash);
    for (i = 0; i < hash64_get_hash_size(hash); i++) {
        if (array[i] != NULL) {
            HASH64_NODE* node = array[i];
            VMM_LOG(mask_anonymous, level_trace,"[%d]: ", i);

            while (node != NULL) {
                if (hash64_is_multiple_values_hash(hash)) {
                    UINT32 counter = 0;
                    HASH64_NODE* node_value = hash64_uint64_to_ptr(hash64_node_get_value(node));
                    while (node_value != NULL) {
                        counter++;
                        node_value = hash64_node_get_next(node_value);
                    }
                    VMM_LOG(mask_anonymous, level_trace,"(%P : %d); ", hash64_node_get_key(node), counter);
                }
                else {
                    VMM_LOG(mask_anonymous, level_trace,"(%P : %P); ", hash64_node_get_key(node), hash64_node_get_value(node));
                }
                node = hash64_node_get_next(node);
            }

            VMM_LOG(mask_anonymous, level_trace,"\n");
        }
    }
}
#endif

