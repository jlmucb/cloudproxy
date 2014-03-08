/*
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
 */

#ifndef _ARRAY_ITERATORS_H_
#define _ARRAY_ITERATORS_H_

#include "vmm_defs.h"
#include "vmm_dbg.h"

// Implementation of array iterators template

//
// Generic array iterator
//
// Usage:
//
//  Provider:
//
//      typedef GENERIC_ARRAY_ITERATOR MY_OBJ_ITERATOR;
//
//      static MY_OBJ g_my_obj_array[size];
//
//      // forward iterator
//
//      MY_OBJ* my_obj_iterator_first( <params>, MY_OBJ_ITERATOR* ctx )
//      {
//          < some logic >
//          return ARRAY_ITERATOR_FIRST( MY_OBJ, g_my_obj_array, size, ctx );
//      }
//
//      MY_OBJ* my_obj_iterator_next( MY_OBJ_ITERATOR* ctx )
//      {
//          return ARRAY_ITERATOR_NEXT( MY_OBJ, ctx );
//      }
//
//      // backward iterator
//
//      MY_OBJ* my_obj_reverse_iterator_first( <params>, MY_OBJ_ITERATOR* ctx )
//      {
//          < some logic >
//          return ARRAY_REVERSE_ITERATOR_FIRST( MY_OBJ, g_my_obj_array, size, ctx );
//      }
//
//      MY_OBJ* my_obj_reverse_iterator_next( MY_OBJ_ITERATOR* ctx )
//      {
//          return ARRAY_REVERSE_ITERATOR_NEXT( MY_OBJ, ctx );
//      }
//
//  Consumer:
//
//      MY_OBJ_ITERATOR ctx;
//      MY_OBJ*         obj;
//
//      for (obj=my_obj_iterator_first(<params>, &ctx); obj; obj=my_obj_iterator_nextt(&ctx))
//      {
//          .....
//      }

typedef struct _GENERIC_ARRAY_ITERATOR {
    size_t      array_start;    // pointer to the array start
    UINT32      start_idx;      // count from
    UINT32      end_idx;        // count to
    UINT32      addend;         // count step - MUST be
                                //    end_idx=start_idx + elem_count*addend
    UINT32      cur_idx;        // current state
} GENERIC_ARRAY_ITERATOR;

INLINE
size_t generic_array_iterator_next( GENERIC_ARRAY_ITERATOR* ctx, UINT32 elem_size )
{
    UINT32 ret_idx;
    VMM_ASSERT( ctx != NULL );

    if (ctx->cur_idx != ctx->end_idx) {
        ret_idx = ctx->cur_idx;
        ctx->cur_idx += ctx->addend;
        return (ctx->array_start + ret_idx*elem_size);
    }
    return 0;
}

INLINE
size_t generic_array_iterator_first( UINT32 start_idx,
                                     UINT32 elem_count,
                                     UINT32 addend,
                                     size_t array_start,
                                     UINT32 elem_size,
                                     GENERIC_ARRAY_ITERATOR* ctx )
{
    VMM_ASSERT( ctx != NULL );

    ctx->array_start = array_start;
    ctx->start_idx   = start_idx;
    ctx->end_idx     = start_idx + elem_count*addend;
    ctx->addend      = addend;
    ctx->cur_idx     = start_idx;

    return generic_array_iterator_next( ctx, elem_size );
}


// Typeless generic macros

#define GENERIC_ARRAY_ITERATOR_FIRST( elem_type,                                \
                                      array_ptr,                                \
                                      start_elem_idx,                           \
                                      number_of_entries,                        \
                                      count_step,                               \
                                      ctx_ptr )                                 \
       (elem_type*)generic_array_iterator_first(  start_elem_idx,               \
                                                    number_of_entries,          \
                                                    count_step,                 \
                                                    (size_t)(array_ptr),        \
                                                    (UINT32)sizeof(elem_type),  \
                                                    ctx_ptr )



#define GENERIC_ARRAY_ITERATOR_NEXT(  elem_type,                                \
                                      ctx_ptr )                                 \
       (elem_type*)generic_array_iterator_next( ctx_ptr, (UINT32)sizeof(elem_type))



// Typeless array iterator 0->end_of_array
#define ARRAY_ITERATOR_FIRST( elem_type, array_ptr, number_of_entries, ctx_ptr )\
    GENERIC_ARRAY_ITERATOR_FIRST( elem_type, array_ptr, 0, number_of_entries, 1, ctx_ptr )

#define ARRAY_ITERATOR_NEXT( elem_type, ctx_ptr )                               \
    GENERIC_ARRAY_ITERATOR_NEXT( elem_type, ctx_ptr )


// Typeless array iterator end_of_array->0

#define ARRAY_REVERSE_ITERATOR_FIRST( elem_type, array_ptr, number_of_entries, ctx_ptr )\
    GENERIC_ARRAY_ITERATOR_FIRST( elem_type, array_ptr, number_of_entries-1, number_of_entries, -1, ctx_ptr )

#define ARRAY_REVERSE_ITERATOR_NEXT( elem_type, ctx_ptr )                       \
    GENERIC_ARRAY_ITERATOR_NEXT( elem_type, ctx_ptr )


#endif // _ARRAY_ITERATORS_H_
