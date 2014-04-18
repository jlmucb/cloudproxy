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

#ifndef _CACHE64_H_
#define _CACHE64_H_

typedef struct CACHE64_STRUCT * CACHE64_OBJECT;
typedef void (*CACHE64_FIELD_PROCESS_FUNCTION)(UINT32 entry_no, void *arg);

#define CACHE_ALL_ENTRIES   ((UINT32) -1)
#define CACHE_DIRTY_FLAG 1
#define CACHE_VALID_FLAG 2

CACHE64_OBJECT cache64_create(UINT32 num_of_entries);
void    cache64_write(CACHE64_OBJECT cache, UINT64 value, UINT32 entry_no);
BOOLEAN cache64_read(CACHE64_OBJECT cache, UINT64 *p_value, UINT32 entry_no); 
// return cache flags
UINT32  cache64_read_raw(CACHE64_OBJECT cache, UINT64 *p_value, UINT32 entry_no); 
// clean valid bits
void    cache64_invalidate(CACHE64_OBJECT cache, UINT32 entry_no);
void    cache64_flush_dirty(CACHE64_OBJECT cache, 
            UINT32 entry_no, CACHE64_FIELD_PROCESS_FUNCTION function, 
            void *arg); // clean dirty bits
void cache64_flush_to_memory(CACHE64_OBJECT cache, void *p_dest, UINT32 max_bytes);
// return TRUE if any field is dirty valid
BOOLEAN cache64_is_dirty(CACHE64_OBJECT cache); 
void    cache64_destroy(CACHE64_OBJECT cache);

#endif // _CACHE64_H_


