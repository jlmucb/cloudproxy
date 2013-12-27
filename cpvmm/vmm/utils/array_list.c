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

#include "list.h"

// %VT% typedef struct _ARRAY_LIST_ELEMENT ARRAY_LIST_ELEMENT;

#define ARRAY_LIST_HEADER_SIZE(alignment)   \
       (UINT32) (ALIGN_FORWARD(sizeof(ARRAY_LIST) - sizeof(((ARRAY_LIST *) 0)->array), (ADDRESS) alignment))

#define ARRAY_LIST_ELEMENT_HEADER_SIZE          ((UINT32) sizeof(ARRAY_LIST_ELEMENT) - (UINT32) sizeof(((ARRAY_LIST_ELEMENT *) 0)->data))

#define ARRAY_LIST_ELEMENT_SIZE(element_size, alignment)   (UINT32) (ALIGN_FORWARD(ARRAY_LIST_ELEMENT_HEADER_SIZE + element_size, (ADDRESS) alignment))

#define ARRAY_LIST_ELEMENT_BY_INDEX(alist, i) \
    (ARRAY_LIST_ELEMENT *)(alist->array + ARRAY_LIST_ELEMENT_SIZE(alist->element_size, alist->alignment) * i)

#define ARRAY_LIST_DATA_TO_ELEMENT(data)     (ARRAY_LIST_ELEMENT *)((char *) data - (char *)((ARRAY_LIST_ELEMENT *) 0)->data)

#define ARRAY_LIST_PADDING_SIZE(address, alignment)    (UINT32) (((char *) ALIGN_FORWARD(address, (ADDRESS) alignment)) - address)

typedef struct _ARRAY_LIST_ELEMENT
{
    LIST_ELEMENT list;        // free/used list
    char data[ARCH_ADDRESS_WIDTH];
} ARRAY_LIST_ELEMENT;

typedef struct _ARRAY_LIST
{
    UINT32 element_size;
    UINT32 max_num_of_elements;
    UINT32 alignment;
    UINT32 memory_size;
    UINT32 header_padding_size;
    UINT32 id;
    LIST_ELEMENT free_list;
    LIST_ELEMENT used_list;
    UINT32 num_of_used_elements;
    char array[4];
} ARRAY_LIST;

UINT32 array_list_memory_size(char *buffer, UINT32 element_size, UINT32 num_of_elements, UINT32 alignment)
{
    return (UINT32) (ARRAY_LIST_PADDING_SIZE(buffer, alignment) + ARRAY_LIST_HEADER_SIZE(alignment) + ARRAY_LIST_ELEMENT_SIZE(element_size, alignment) * num_of_elements);
}

UINT32 array_list_size(ARRAY_LIST *alist)
{
    return alist->num_of_used_elements;
}

ARRAY_LIST_HANDLE array_list_init(char *buffer, UINT32 buffer_size, UINT32 element_size, UINT32 num_of_elements, UINT32 alignment)
{
    static UINT16 list_id = 1;
    UINT32 required_buffer_size = array_list_memory_size(buffer, element_size, num_of_elements, alignment);
    ARRAY_LIST *alist;
    UINT32 i;
    ARRAY_LIST_ELEMENT *entry = NULL;
    LIST_ELEMENT *free_list = NULL;

    if(required_buffer_size > buffer_size)
    {
        return NULL;
    }

    alist = (ARRAY_LIST *) (buffer + ARRAY_LIST_PADDING_SIZE(buffer, alignment));
    alist->id = list_id++;
    alist->element_size = element_size;
    alist->max_num_of_elements = num_of_elements;
    alist->alignment = alignment;
    alist->memory_size = buffer_size;
    alist->header_padding_size = ARRAY_LIST_PADDING_SIZE(buffer, alignment);
    alist->num_of_used_elements = 0;

    list_init(&alist->free_list);
    list_init(&alist->used_list);

    free_list = &alist->free_list;

    for(i = 0; i < num_of_elements; i++)
    {
        entry = ARRAY_LIST_ELEMENT_BY_INDEX(alist, i);
        list_add(free_list, &entry->list);
        free_list = free_list->next;
    }

    return alist;
}

BOOLEAN array_list_add(ARRAY_LIST_HANDLE alist, void* data)
{
    LIST_ELEMENT *free_element = NULL;
    ARRAY_LIST_ELEMENT *free_list_entry = NULL;

    if(list_is_empty(&alist->free_list) || alist == NULL || data == NULL)
    {
        return FALSE;
    }

    free_element = alist->free_list.next;
    list_remove(free_element);
    list_add(alist->used_list.prev, free_element);
    alist->num_of_used_elements++;

    free_list_entry = LIST_ENTRY(free_element, ARRAY_LIST_ELEMENT, list);

    vmm_memcpy(free_list_entry->data, data, alist->element_size);

    return TRUE;
}

BOOLEAN array_list_remove(ARRAY_LIST_HANDLE alist, void *data)
{
    ARRAY_LIST_ELEMENT *element;

    if(list_is_empty(&alist->used_list) || alist == NULL || data == NULL)
    {
        return FALSE;
    }

    element = ARRAY_LIST_DATA_TO_ELEMENT(data);
    list_remove(&element->list);
    list_add(alist->free_list.prev, &element->list);
    alist->num_of_used_elements--;

    return TRUE;
}
char *array_list_first(ARRAY_LIST_HANDLE alist, ARRAY_LIST_ITERATOR *iter)
{
    ARRAY_LIST_ELEMENT *element;
    char* data;

    if(list_is_empty(&alist->used_list))
    {
        return NULL;
    }

    element = LIST_ENTRY(alist->used_list.next, ARRAY_LIST_ELEMENT, list);
    data = element->data;

    if(iter != NULL)
    {
        iter->alist = alist;
        iter->element = element;
    }

    return data;
}
#ifdef INCLUDE_UNUSED_CODE
char *array_list_next(ARRAY_LIST_ITERATOR *iter)
{
    if(iter == NULL || iter->element->list.next == &iter->alist->used_list)
    {
        return NULL;
    }

    iter->element = LIST_ENTRY(iter->element->list.next, ARRAY_LIST_ELEMENT, list);

    return iter->element->data;
}
#endif
