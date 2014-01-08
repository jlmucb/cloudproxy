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

#ifndef HASH64_INTERFACE_H
#define HASH64_INTERFACE_H

#include <vmm_defs.h>

typedef UINT32 (*HASH64_FUNC)(UINT64 key, UINT32 size);
typedef void*  (*HASH64_INTERNAL_MEM_ALLOCATION_FUNC)(UINT32 size);
typedef void   (*HASH64_INTERNAL_MEM_DEALLOCATION_FUNC)(void* data);
typedef void*  (*HASH64_NODE_ALLOCATION_FUNC)(void* context);
typedef void   (*HASH64_NODE_DEALLOCATION_FUNC)(void* context, void* data);

typedef void* HASH64_HANDLE;
typedef void* HASH64_MULTIPLE_VALUES_HASH_ITERATOR;
#define HASH64_INVALID_HANDLE ((HASH64_HANDLE)NULL)
#define HASH64_NULL_ITERATOR  ((HASH64_MULTIPLE_VALUES_HASH_ITERATOR)NULL)


/* Function: hash64_get_node_size
*  Description: This function returns the size of hash node.
*
*  Output: Size
*/
UINT32 hash64_get_node_size(void);

HASH64_HANDLE hash64_create_default_hash(UINT32 hash_size);

/* Function: hash64_create_hash
*  Description: This function is used in order to create 1-1 hash
*  Input: hash_func - hash function which returns index in array which is lower
*                     than "hash_size" parameter.
*         mem_alloc_func - function which will be used for allocation of inner
*                          data structures. If it is NULL then allocation will
*                          be performed directly from heap.
*         mem_dealloc_func - function which will be used for deallocation of
*                            inner data structures. If it is NULL then deallocation
*                            will be performed directly to heap.
*         node_alloc_func - function which will be used for allocation of hash nodes.
*                           Node that function doesn't receive the size as parameter.
*                           In order to know the required size, use "hash64_get_node_size"
*                           function.
*         node_dealloc_func - function which will be used for deallocation of each node,
*                             when necessary.
*         node_allocation_deallocation_context - context which will be passed to
*                                                "node_alloc_func" and "node_dealloc_func"
*                                                functions as parameter.
*         hash_size - number of cells in hash array.
*  Return value: Hash handle which should be used as parameter for other functions.
*                In case of failure, HASH64_INVALID_HANDLE will be returned
*/
HASH64_HANDLE hash64_create_hash(HASH64_FUNC hash_func,
                                 HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func,
                                 HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func,
                                 HASH64_NODE_ALLOCATION_FUNC node_alloc_func,
                                 HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func,
                                 void* node_allocation_deallocation_context,
                                 UINT32 hash_size);


/* Function: hash64_create_hash
*  Description: This function is used in order to destroy 1-1 hash
*  Input: hash_handle - handle returned by "hash64_create_hash" function
*/
void hash64_destroy_hash(HASH64_HANDLE hash_handle);


/* Function: hash64_lookup
*  Description: This function is used in order to find the value in 1-1 hash for given key.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*         key -
*  Output:
*         value -
*  Return value: TRUE in case the value is found
*/
BOOLEAN hash64_lookup(HASH64_HANDLE hash_handle,
                     UINT64 key,
                     UINT64* value);


/* Function: hash64_insert
*  Description: This function is used in order to insert the value into 1-1 hash.
*               If some value for given key exists, FALSE will be returned.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*         key -
*         value -
*  Return value: TRUE in case the operation is successful
*/
BOOLEAN hash64_insert(HASH64_HANDLE hash_handle,
                     UINT64 key,
                     UINT64 value);

/* Function: hash64_update
*  Description: This function is used in order to update the value in 1-1 hash.
*               If the value doesn't exist it will be inserted.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*         key -
*         value -
*  Return value: TRUE in case the operation is successful
*/
BOOLEAN hash64_update(HASH64_HANDLE hash_handle,
                     UINT64 key,
                     UINT64 value);


/* Function: hash64_remove
*  Description: This function is used in order to remove the value from 1-1 hash.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*         key -
*  Return value: TRUE in case the operation is successful
*/
BOOLEAN hash64_remove(HASH64_HANDLE hash_handle,
                     UINT64 key);


/* Function: hash64_is_empty
*  Description: This function is used in order check whether 1-1 hash is empty.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*  Return value: TRUE in case the hash is empty.
*/
BOOLEAN hash64_is_empty(HASH64_HANDLE hash_handle);

/* Function: hash64_change_size_and_rehash
*  Description: This function is used in order to change the size of the hash and rehash it.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*         hash_size   - new size
*  Return value: TRUE in case the operation is successfull.
*/
BOOLEAN hash64_change_size_and_rehash(HASH64_HANDLE hash_handle,
                                      UINT32 hash_size);


/* Function: hash64_change_size_and_rehash
*  Description: This function is used in order to change the size of the hash and rehash it.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*  Return value: Number of elements in hash.
*/
UINT32 hash64_get_num_of_elements(HASH64_HANDLE hash_handle);

/* Function: hash64_get_current_size
*  Description: This function returns the size (in number of cells) of hash array.
*  Input:
*         hash_handle - handle returned by "hash64_create_hash" function
*  Return value: Size of hash.
*/
UINT32 hash64_get_current_size(HASH64_HANDLE hash_handle);


/* Function: hash64_create_multiple_values_hash
*  Description: This function is used in order to create 1-n (one to many) hash
*  Input: hash_func - hash function which returns index in array which is lower
*                     than "hash_size" parameter.
*         mem_alloc_func - function which will be used for allocation of inner
*                          data structures. If it is NULL then allocation will
*                          be performed directly from heap.
*         mem_dealloc_func - function which will be used for deallocation of
*                            inner data structures. If it is NULL then deallocation
*                            will be performed directly to heap.
*         node_alloc_func - function which will be used for allocation of hash nodes.
*                           Node that function doesn't receive the size as parameter.
*                           In order to know the required size, use "hash64_get_node_size"
*                           function.
*         node_dealloc_func - function which will be used for deallocation of each node,
*                             when necessary.
*         node_allocation_deallocation_context - context which will be passed to
*                                                "node_alloc_func" and "node_dealloc_func"
*                                                functions as parameter.
*         hash_size - number of cells in hash array.
*  Return value: Hash handle which should be used as parameter for other functions.
*                In case of failure, HASH64_INVALID_HANDLE will be returned.
*/
HASH64_HANDLE hash64_create_multiple_values_hash(HASH64_FUNC hash_func,
                                                 HASH64_INTERNAL_MEM_ALLOCATION_FUNC mem_alloc_func,
                                                 HASH64_INTERNAL_MEM_DEALLOCATION_FUNC mem_dealloc_func,
                                                 HASH64_NODE_ALLOCATION_FUNC node_alloc_func,
                                                 HASH64_NODE_DEALLOCATION_FUNC node_dealloc_func,
                                                 void* node_allocation_deallocation_context,
                                                 UINT32 hash_size);


/* Function: hash64_destroy_multiple_values_hash
*  Description: This function is used in order to destroy 1-n hash
*  Input: hash_handle - handle returned by "hash64_create_multiple_values_hash" function
*/
void hash64_destroy_multiple_values_hash(HASH64_HANDLE hash_handle);


/* Function: hash64_lookup_in_multiple_values_hash
*  Description: This function is used in order to find the value in 1-n hash for given key.
*  Input:
*         hash_handle - handle returned by "hash64_create_multiple_values_hash" function
*         key -
*  Output:
*         iter - iterator for the existing values
*  Return value: TRUE in case when at least one value exists.
*/
BOOLEAN hash64_lookup_in_multiple_values_hash(HASH64_HANDLE hash_handle,
                                             UINT64 key,
                                             HASH64_MULTIPLE_VALUES_HASH_ITERATOR* iter);


/* Function: hash64_multiple_values_hash_iterator_get_next
*  Description: This function is used to advance iterator to the next value
*  Input:
*         iter - iterator (output of "hash64_lookup_in_multiple_values_hash" function).
*  Return value: iterator which points to next value. If there is no next value,
*                HASH64_NULL_ITERATOR will be returned.
*/
HASH64_MULTIPLE_VALUES_HASH_ITERATOR
hash64_multiple_values_hash_iterator_get_next(HASH64_MULTIPLE_VALUES_HASH_ITERATOR iter);


/* Function: hash64_multiple_values_hash_iterator_get_value
*  Description: This function is used to retrieve value from iterator
*  Input:
*         iter - iterator (output of "hash64_lookup_in_multiple_values_hash" function).
*  Return value: iterator which points to next value. If there is no next value,
*                HASH64_NULL_ITERATOR will be returned.
*/
UINT64 hash64_multiple_values_hash_iterator_get_value(HASH64_MULTIPLE_VALUES_HASH_ITERATOR iter);


/* Function: hash64_insert_into_multiple_values_hash
*  Description: This function is used in order to insert the value into 1-n hash.
*  Input:
*         hash_handle - handle returned by "hash64_create_multiple_values_hash" function
*         key -
*         value -
*  Return value: TRUE in case the operation is successful
*/
BOOLEAN hash64_insert_into_multiple_values_hash(HASH64_HANDLE hash_handle,
                                               UINT64 key,
                                               UINT64 value);

/* Function: hash64_remove_from_multiple_values_hash
*  Description: This function is used in order to remove the value from 1-n hash.
*  Input:
*         hash_handle - handle returned by "hash64_lookup_in_multiple_values_hash" function
*         key -
*         value - value to remove
*  Return value: TRUE in case the operation is successful.
*/
BOOLEAN hash64_remove_from_multiple_values_hash(HASH64_HANDLE hash_handle,
                                               UINT64 key,
                                               UINT64 value);

/* Function: hash64_is_value_in_multiple_values_hash
*  Description: This function is used in order to check whether some value is
*               recorded for given key in 1-n hash.
*  Input:
*         hash_handle - handle returned by "hash64_create_multiple_values_hash" function
*         key -
*         value -
*  Return value: TRUE in case the value exists.
*/
BOOLEAN hash64_is_value_in_multiple_values_hash(HASH64_HANDLE hash_handle,
                                               UINT64 key,
                                               UINT64 value);


/* Function: hash64_remove_range_from_multiple_values_hash
*  Description: This function is used in order to remove range of values from 1-n hash.
*  Input:
*         hash_handle - handle returned by "hash64_create_multiple_values_hash" function
*         key -
*         value_from - remove all recorded values starting from this one and including it.
*         value_to - remove all recorded values ending this one and including it.
*  Return value: TRUE in case the operation is successful.
*/
BOOLEAN hash64_remove_range_from_multiple_values_hash(HASH64_HANDLE hash_handle,
                                                     UINT64 key,
                                                     UINT64 value_from,
                                                     UINT64 value_to);


/* Function: hash64_multiple_values_is_empty
*  Description: This function is used in order check whether 1-n hash is empty.
*  Input:
*         hash_handle - handle returned by "hash64_create_multiple_values_hash" function
*  Return value: TRUE in case the hash is empty.
*/
BOOLEAN hash64_multiple_values_is_empty(HASH64_HANDLE hash_handle);

#ifdef DEBUG
void hash64_print(HASH64_HANDLE hash_handle);
#endif
#endif
