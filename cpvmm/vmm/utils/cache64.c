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

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "common_libc.h"
#include "memory_allocator.h"
#include "cache64.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(CACHE64_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(CACHE64_C, __condition)

struct CACHE64_STRUCT {
    UINT32  num_of_entries;
    UINT16  bitmap_size; // in bytes
    UINT16  flags;
    UINT64 *table;
    UINT8  *dirty_bits;
    UINT8  *valid_bits;
};

//
// Helper macros
//
#define CACHE_FIELD_IS_VALID(__cache, __entry_no)   BITARRAY_GET((__cache)->valid_bits, __entry_no )
#define CACHE_FIELD_SET_VALID(__cache, __entry_no)  BITARRAY_SET((__cache)->valid_bits, __entry_no )
#define CACHE_FIELD_CLR_VALID(__cache, __entry_no)  BITARRAY_CLR((__cache)->valid_bits, __entry_no )

#define CACHE_FIELD_IS_DIRTY(__cache, __entry_no)   BITARRAY_GET((__cache)->dirty_bits, __entry_no )
#define CACHE_FIELD_SET_DIRTY(__cache, __entry_no)  BITARRAY_SET((__cache)->dirty_bits, __entry_no )
#define CACHE_FIELD_CLR_DIRTY(__cache, __entry_no)  BITARRAY_CLR((__cache)->dirty_bits, __entry_no )

#define ENUMERATE_DIRTY_ENTRIES(__cache, __func, __arg)                        \
    BITARRAY_ENUMERATE( (__cache)->dirty_bits,                                 \
                        (__cache)->num_of_entries,                             \
                        __func, __arg)


CACHE64_OBJECT cache64_create(UINT32 num_of_entries)
{
    struct CACHE64_STRUCT *cache;
    UINT64 *table;
    UINT8  *dirty_bits;
    UINT8  *valid_bits;
    UINT16 bitmap_size = (UINT16) BITARRAY_SIZE_IN_BYTES(num_of_entries);


    cache = vmm_malloc(sizeof(struct CACHE64_STRUCT));
    table = vmm_malloc(sizeof(UINT64) * num_of_entries);
    dirty_bits = vmm_malloc(bitmap_size);
    valid_bits = vmm_malloc(bitmap_size);

    if (NULL != cache       &&
        NULL != table       &&
        NULL != dirty_bits  &&
        NULL != valid_bits)
    {
        // everything is OK. fill the fields
        cache->num_of_entries = num_of_entries;
        cache->bitmap_size    = bitmap_size;
        cache->flags          = 0;
        cache->table          = table;
        cache->dirty_bits     = dirty_bits;
        cache->valid_bits     = valid_bits;

        vmm_memset(table, 0, sizeof(*table) * num_of_entries);
        vmm_memset(dirty_bits, 0, bitmap_size);
        vmm_memset(valid_bits, 0, bitmap_size);
    }
    else
    {
        VMM_LOG(mask_anonymous, level_trace,"[cache64] %s: Allocation failed\n", __FUNCTION__);
        if (NULL != cache)
        {
            vmm_mfree(cache);
        }
        if (NULL != table)
        {
            vmm_mfree(table);
        }
        if (NULL != dirty_bits)
        {
            vmm_mfree(dirty_bits);
        }
        if (NULL != valid_bits)
        {
            vmm_mfree(valid_bits);
        }
        cache = NULL;
    }

    return cache;
}
extern BOOLEAN vmcs_sw_shadow_disable[];

void cache64_write(CACHE64_OBJECT cache, UINT64 value, UINT32 entry_no)
{
    if (vmcs_sw_shadow_disable[hw_cpu_id()])
		return;
	
	VMM_ASSERT(cache);
    VMM_ASSERT(entry_no < cache->num_of_entries);

    if (entry_no < cache->num_of_entries)
    {
        if ( ! (cache->table[entry_no] == value && CACHE_FIELD_IS_VALID(cache, entry_no)))
        {
            cache->table[entry_no] = value;
            CACHE_FIELD_SET_DIRTY(cache, entry_no);
            CACHE_FIELD_SET_VALID(cache, entry_no);
            BITMAP_SET(cache->flags, CACHE_DIRTY_FLAG);
        }
    }
}


BOOLEAN cache64_read(CACHE64_OBJECT cache, UINT64 *p_value, UINT32 entry_no)
{
    BOOLEAN is_valid = FALSE;

    if (vmcs_sw_shadow_disable[hw_cpu_id()])
		return FALSE;

    VMM_ASSERT(cache);
    VMM_ASSERT(entry_no < cache->num_of_entries);
    VMM_ASSERT(p_value);

    if (entry_no < cache->num_of_entries)
    {
        if (CACHE_FIELD_IS_VALID(cache, entry_no))
        {
            *p_value = cache->table[entry_no];
            is_valid = TRUE;
        }
    }
    return is_valid;
}

#ifdef INCLUDE_UNUSED_CODE
UINT32 cache64_read_raw(CACHE64_OBJECT cache, UINT64 *p_value, UINT32 entry_no)
{
    UINT32 cache_flags = 0;

    VMM_ASSERT(cache);
    VMM_ASSERT(entry_no < cache->num_of_entries);
    VMM_ASSERT(p_value);

    if (entry_no < cache->num_of_entries)
    {
        if (CACHE_FIELD_IS_VALID(cache, entry_no))
        {
            *p_value = cache->table[entry_no];
            cache_flags = CACHE_VALID_FLAG;
            if (CACHE_FIELD_IS_DIRTY(cache, entry_no))
            {
                cache_flags |= CACHE_DIRTY_FLAG;
            }
        }
    }
    return cache_flags;
}
#endif

// clean valid bits
void cache64_invalidate(CACHE64_OBJECT cache, UINT32 entry_no)
{
    VMM_ASSERT(cache);

    if (entry_no < cache->num_of_entries)
    {
        // invalidate specific entry
        CACHE_FIELD_CLR_VALID(cache, entry_no);
    }
    else
    {
        // invalidate all entries
        BITMAP_CLR(cache->flags, CACHE_VALID_FLAG);
        vmm_memset(cache->valid_bits, 0, cache->bitmap_size);
        vmm_memset(cache->dirty_bits, 0, cache->bitmap_size);
    }
}

// flush dirty fields using <function>
void cache64_flush_dirty(
    CACHE64_OBJECT cache,
    UINT32 entry_no,
    CACHE64_FIELD_PROCESS_FUNCTION function,// if function == NULL, then just clean dirty bits
    void *arg
)
{
    VMM_ASSERT(cache);

    if (entry_no < cache->num_of_entries)
    {
        // flush specific entry
        if (CACHE_FIELD_IS_DIRTY(cache, entry_no))
        {
            CACHE_FIELD_CLR_DIRTY(cache, entry_no);
            if (NULL != function)
            {
                function(entry_no, arg);
            }
        }
    }
    else
    {
        // flush all entries
        BITMAP_CLR(cache->flags, CACHE_DIRTY_FLAG);

        if (NULL != function)
        {
            ENUMERATE_DIRTY_ENTRIES(cache, function, arg);
        }
        else
        {
            vmm_memset(cache->dirty_bits, 0, cache->bitmap_size);
        }
    }
}

#ifdef INCLUDE_LAYERING
void cache64_flush_to_memory(CACHE64_OBJECT cache, void *p_dest, UINT32 max_bytes)
{
    UINT32 cache_size = sizeof(*cache->table) * cache->num_of_entries;

    VMM_ASSERT(cache);
    VMM_ASSERT(p_dest);

    if (cache_size > max_bytes)
    {
        VMM_LOG(mask_anonymous, level_trace,"[cache64] %s: Warning!!! Destination size less then required\n", __FUNCTION__);
        cache_size = max_bytes;
    }
    vmm_memcpy(p_dest, cache->table, cache_size);
}
#endif

BOOLEAN cache64_is_dirty(CACHE64_OBJECT cache)
{
    VMM_ASSERT(cache);

    return (0 != BITMAP_GET(cache->flags, CACHE_DIRTY_FLAG));
}
void cache64_destroy(CACHE64_OBJECT cache)
{
    VMM_ASSERT(cache);

    vmm_mfree(cache->table);
    vmm_mfree(cache->dirty_bits);
    vmm_mfree(cache->valid_bits);
    vmm_mfree(cache);
}

