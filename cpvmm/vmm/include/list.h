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

#ifndef _LIST_H
#define _LIST_H

#include "vmm_defs.h"
#include "common_libc.h"

#define LIST_ENTRY(list, entry_type, list_entry_name) \
    ((entry_type *) ((char *) list - OFFSET_OF(entry_type, list_entry_name)))


typedef struct _LIST_ELEMENT
{
    struct _LIST_ELEMENT *next;
    struct _LIST_ELEMENT *prev;
} LIST_ELEMENT;

INLINE void list_init(LIST_ELEMENT *entry)
{
    entry->next = entry->prev = entry;
}

INLINE void _list_add(LIST_ELEMENT *prev, LIST_ELEMENT *next, LIST_ELEMENT *new_entry)
{
    prev->next = new_entry;
    new_entry->prev = prev;
    next->prev = new_entry;
    new_entry->next = next;
}

INLINE void list_add(LIST_ELEMENT *list, LIST_ELEMENT *new_entry)
{
    _list_add(list, list->next, new_entry);
}
#ifdef INCLUDE_UNUSED_CODE
INLINE void list_add_after(LIST_ELEMENT *list, LIST_ELEMENT *new_entry)
{
    list_add(list, new_entry);
}

INLINE void list_add_before(LIST_ELEMENT *list, LIST_ELEMENT *new_entry)
{
    _list_add(list->prev, list, new_entry);
}
INLINE void list_merge(LIST_ELEMENT *list1, LIST_ELEMENT *list2)
{
    list1->next->prev = list2->prev;
    list2->prev->next = list1->next;
    list1->next = list2->next;
    list2->next->prev = list1;
}
#endif

INLINE void list_remove(LIST_ELEMENT *list)
{
    list->prev->next = list->next;
    list->next->prev = list->prev;
    list->prev = list->next = NULL;
}

INLINE BOOLEAN list_is_empty(LIST_ELEMENT *list)
{
    return (BOOLEAN) (list->next == list);
}


#define LIST_FOR_EACH(list, iter) \
    for(iter = (list)->next; iter != (list); iter = iter->next)

INLINE UINT16 list_size(LIST_ELEMENT *list)
{
    UINT16 size = 0;
    LIST_ELEMENT *curr_element = list;

    while(curr_element->next != list)
    {
        size++;
        curr_element = curr_element->next;
    }

    return size;
}

#define LIST_NEXT(list, entry_type, list_entry_name) (LIST_ENTRY((list)->next, entry_type, list_entry_name))

typedef struct _ARRAY_LIST *ARRAY_LIST_HANDLE;

typedef struct _ARRAY_LIST_ELEMENT *ARRAY_LIST_ELEMENT_HANDLE;

typedef struct _ARRAY_LIST_ITERATOR
{
    ARRAY_LIST_HANDLE alist;
    ARRAY_LIST_ELEMENT_HANDLE element;
} ARRAY_LIST_ITERATOR;

// FUNCTION:        array_list_memory_size
// DESCRIPTION:     Calculate memory size required for list.
// RETURN VALUE:    Memory size required for list
UINT32 array_list_memory_size(char *buffer, UINT32 element_size, UINT32 num_of_elements, UINT32 alignment);

// FUNCTION:        array_list_init
// DESCRIPTION:     Initialize the list.
// RETURN VALUE:    Array list handle to use for list manipulation
ARRAY_LIST_HANDLE array_list_init(char *buffer, UINT32 buffer_size, UINT32 element_size, UINT32 num_of_elements, UINT32 alignment);

// FUNCTION:        array_list_size
// DESCRIPTION:     Number of elements in the list.
// RETURN VALUE:    Number of elements in the list.
UINT32 array_list_size(ARRAY_LIST_HANDLE alist);

// FUNCTION:        array_list_add
// DESCRIPTION:     Add element to the list.
// RETURN VALUE:    TRUE if element was successfully added, FALSE for error.
BOOLEAN array_list_add(ARRAY_LIST_HANDLE alist, void* data);

// FUNCTION:        array_list_remove
// DESCRIPTION:     Remove element from the list.
// RETURN VALUE:    TRUE if element was successfully removed, FALSE for error.
BOOLEAN array_list_remove(ARRAY_LIST_HANDLE alist, void *data);

// FUNCTION:        array_list_first
// DESCRIPTION:     Get first element.
// RETURN VALUE:    The first element.
char *array_list_first(ARRAY_LIST_HANDLE alist, ARRAY_LIST_ITERATOR *iter);

// FUNCTION:        array_list_next
// DESCRIPTION:     Get next element for iteration.
// RETURN VALUE:    The next element.
char *array_list_next(ARRAY_LIST_ITERATOR *iter);

#endif
